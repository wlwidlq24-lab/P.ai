"""Versioned ChromaDB repository with staging -> validate -> activate -> rollback, plus authorization filters.

All methods are synchronous (Chroma's client is synchronous); async callers must use asyncio.to_thread.
Each index version is a separate collection; `registry.json` records which version is active.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import chromadb
from filelock import FileLock

from .errors import AuthorizationFilterMissingError, IndexValidationError, NoActiveIndexError
from .schemas import AccessControlMode, ChunkMetadata, RolePolicy, UserContext
from .timeutil import to_epoch, utc_now

REQUIRED_KEYS = {"document_id", "document_version", "chunk_id", "tenant_id", "allowed_roles_csv", "content_hash",
                 "normalization_version", "embedding_model", "embedding_dimension", "ingestion_run_id",
                 "effective_from_ts", "effective_to_ts", "pii_grade_rank", "source_trust_level"}
_PAGE = 500


@dataclass
class RetrievedChunk:
    chunk_id: str
    text: str
    metadata: ChunkMetadata
    distance: float


@dataclass
class ValidationReport:
    version: str
    ok: bool
    n_chunks: int
    n_documents: int
    errors: list[str] = field(default_factory=list)


def build_where(user: UserContext, role_policy: RolePolicy, mode: AccessControlMode, as_of: datetime,
                subject_id: str | None) -> dict[str, Any]:
    """Pre-retrieval authorization filter. Tenant + effective-date filters are applied in every mode."""
    ts = to_epoch(as_of)
    clauses: list[dict[str, Any]] = [
        {"tenant_id": {"$eq": user.tenant_id}},
        {"effective_from_ts": {"$lte": ts}},
        {"effective_to_ts": {"$gt": ts}},
    ]
    if mode == AccessControlMode.ENFORCED:
        clauses.append({f"role__{user.role}": {"$eq": True}})
        clauses.append({"pii_grade_rank": {"$lte": role_policy.max_pii_grade.rank}})
    if subject_id:
        # Subject scoping: subject-specific records of this subject, or general documents (subject_id == "").
        clauses.append({"subject_id": {"$in": [subject_id, ""]}})
    where = {"$and": clauses}
    assert_authz_filter(where, user, mode)
    return where


def assert_authz_filter(where: dict[str, Any] | None, user: UserContext, mode: AccessControlMode) -> None:
    """Fail closed: refuse retrieval unless mandatory constraints are present for the given mode."""
    if not where or "$and" not in where or not isinstance(where["$and"], list):
        raise AuthorizationFilterMissingError("retrieval attempted without an authorization filter")
    keys = {k for c in where["$and"] for k in c}
    if c := [x for x in where["$and"] if "tenant_id" in x]:
        if c[0]["tenant_id"].get("$eq") != user.tenant_id:
            raise AuthorizationFilterMissingError("tenant filter does not match the authenticated user")
    else:
        raise AuthorizationFilterMissingError("tenant filter missing")
    if mode == AccessControlMode.ENFORCED and (f"role__{user.role}" not in keys or "pii_grade_rank" not in keys):
        raise AuthorizationFilterMissingError("role/pii-grade filter missing under ENFORCED access control")


def is_authorized(md: ChunkMetadata, user: UserContext, role_policy: RolePolicy, as_of: datetime) -> bool:
    """Python mirror of the ENFORCED filter, used to label retrieval-authorization failures."""
    ts = to_epoch(as_of)
    f = to_epoch(md.effective_from) if md.effective_from else 0
    t = to_epoch(md.effective_to) if md.effective_to else 253402300799
    return (md.tenant_id == user.tenant_id and user.role in md.allowed_roles
            and md.pii_grade.rank <= role_policy.max_pii_grade.rank and f <= ts < t)


class ChromaRepository:
    def __init__(self, path: Path, prefix: str = "ragsec"):
        path.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.prefix = prefix
        self._client = chromadb.PersistentClient(path=str(path))
        self._registry_path = path / "registry.json"
        self._file_lock = FileLock(str(path / "registry.lock"), thread_local=False)
        self._mutex = threading.RLock()

    # ------------------------------------------------------------------ registry
    def _read_registry(self) -> dict[str, Any]:
        if not self._registry_path.exists():
            return {"active": None, "previous": None, "versions": {}}
        return json.loads(self._registry_path.read_text(encoding="utf-8"))

    def _write_registry(self, reg: dict[str, Any]) -> None:
        tmp = self._registry_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self._registry_path)

    def registry(self) -> dict[str, Any]:
        with self._mutex, self._file_lock:
            return self._read_registry()

    def active_version(self) -> str | None:
        return self.registry()["active"]

    def require_active(self) -> str:
        v = self.active_version()
        if v is None:
            raise NoActiveIndexError("no active index version; upload documents or ingest a dataset first")
        return v

    def _name(self, version: str) -> str:
        return f"{self.prefix}-{version}"

    def _col(self, version: str):
        return self._client.get_or_create_collection(self._name(version), embedding_function=None,
                                                     configuration={"hnsw": {"space": "cosine"}})

    # ------------------------------------------------------------------ staging
    def create_staging(self, base: str | None, note: str = "") -> str:
        with self._mutex, self._file_lock:
            reg = self._read_registry()
            version = f"v{utc_now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}"
            dst = self._col(version)
            if base:
                src = self._col(base)
                offset = 0
                while True:
                    got = src.get(include=["embeddings", "documents", "metadatas"], limit=_PAGE, offset=offset)
                    if not got["ids"]:
                        break
                    dst.add(ids=got["ids"], embeddings=got["embeddings"], documents=got["documents"],
                            metadatas=got["metadatas"])
                    offset += len(got["ids"])
            reg["versions"][version] = {"status": "staging", "base": base, "created_at": utc_now().isoformat(),
                                        "note": note}
            self._write_registry(reg)
            return version

    def add_chunks(self, version: str, ids: list[str], embeddings: list[list[float]], documents: list[str],
                   metadatas: list[dict[str, Any]]) -> None:
        self._assert_status(version, {"staging"})
        col = self._col(version)
        for i in range(0, len(ids), _PAGE):
            col.add(ids=ids[i:i + _PAGE], embeddings=embeddings[i:i + _PAGE], documents=documents[i:i + _PAGE],
                    metadatas=metadatas[i:i + _PAGE])

    def delete_document(self, version: str, document_id: str) -> int:
        self._assert_status(version, {"staging"})
        col = self._col(version)
        got = col.get(where={"document_id": {"$eq": document_id}}, include=[])
        if got["ids"]:
            col.delete(ids=got["ids"])
        return len(got["ids"])

    def document_versions(self, version: str, document_id: str) -> list[dict[str, Any]]:
        got = self._col(version).get(where={"document_id": {"$eq": document_id}}, include=["metadatas"])
        seen: dict[tuple, dict] = {}
        for md in got["metadatas"] or []:
            seen[(md["document_version"], md["document_content_hash"])] = md
        return list(seen.values())

    def _assert_status(self, version: str, allowed: set[str]) -> None:
        st = self.registry()["versions"].get(version, {}).get("status")
        if st not in allowed:
            raise IndexValidationError(f"index version {version} has status {st!r}; expected {sorted(allowed)}")

    # ------------------------------------------------------------------ validation / activation
    def validate(self, version: str, expected_embedding_model: str) -> ValidationReport:
        col = self._col(version)
        errors: list[str] = []
        doc_versions: dict[str, set[int]] = {}
        supersedes: set[str] = set()
        dims: set[int] = set()
        norms: set[str] = set()
        n = 0
        offset = 0
        while True:
            got = col.get(include=["metadatas"], limit=_PAGE, offset=offset)
            if not got["ids"]:
                break
            for cid, md in zip(got["ids"], got["metadatas"]):
                n += 1
                missing = REQUIRED_KEYS - set(md)
                if missing:
                    errors.append(f"{cid}: missing metadata {sorted(missing)}")
                    continue
                if md["embedding_model"] != expected_embedding_model:
                    errors.append(f"{cid}: embedding_model {md['embedding_model']} != {expected_embedding_model}")
                doc_versions.setdefault(md["document_id"], set()).add(int(md["document_version"]))
                if md.get("supersedes_document_id"):
                    supersedes.add(md["supersedes_document_id"])
                dims.add(int(md["embedding_dimension"]))
                norms.add(md["normalization_version"])
                if not md["allowed_roles_csv"]:
                    errors.append(f"{cid}: empty allowed_roles")
            offset += len(got["ids"])
        for d, vs in doc_versions.items():
            if len(vs) > 1:
                errors.append(f"document {d} has multiple versions mixed in one index: {sorted(vs)}")
        for s in supersedes & set(doc_versions):
            errors.append(f"superseded document {s} still present")
        if len(dims) > 1:
            errors.append(f"mixed embedding dimensions {sorted(dims)}")
        if len(norms) > 1:
            errors.append(f"mixed normalization versions {sorted(norms)}")
        if n == 0:
            errors.append("index is empty")
        report = ValidationReport(version=version, ok=not errors, n_chunks=n, n_documents=len(doc_versions),
                                  errors=errors[:50])
        with self._mutex, self._file_lock:
            reg = self._read_registry()
            entry = reg["versions"].get(version)
            if entry is not None and entry["status"] == "staging":
                entry["status"] = "validated" if report.ok else "staging"
                entry["validation"] = {"ok": report.ok, "n_chunks": n, "n_documents": len(doc_versions),
                                       "errors": report.errors, "at": utc_now().isoformat()}
                self._write_registry(reg)
        return report

    def activate(self, version: str) -> None:
        with self._mutex, self._file_lock:
            reg = self._read_registry()
            entry = reg["versions"].get(version)
            if not entry or entry["status"] not in ("validated", "retired"):
                raise IndexValidationError(f"version {version} is not validated")
            prev = reg["active"]
            if prev and prev != version:
                reg["versions"][prev]["status"] = "retired"
                reg["previous"] = prev
            entry["status"] = "active"
            entry["activated_at"] = utc_now().isoformat()
            reg["active"] = version
            self._write_registry(reg)

    def rollback(self) -> str:
        reg = self.registry()
        prev = reg.get("previous")
        if not prev:
            raise IndexValidationError("no previous version to roll back to")
        self.activate(prev)
        return prev

    def discard(self, version: str) -> None:
        with self._mutex, self._file_lock:
            reg = self._read_registry()
            if reg["active"] == version:
                raise IndexValidationError("cannot discard the active version")
            reg["versions"].pop(version, None)
            self._write_registry(reg)
        try:
            self._client.delete_collection(self._name(version))
        except Exception:  # collection may not exist; registry is authoritative
            pass

    # ------------------------------------------------------------------ retrieval
    def query(self, version: str, embedding: list[float], where: dict[str, Any], n: int,
              user: UserContext, mode: AccessControlMode) -> list[RetrievedChunk]:
        assert_authz_filter(where, user, mode)  # defence in depth: never query without a filter
        col = self._col(version)
        res = col.query(query_embeddings=[embedding], n_results=n, where=where,
                        include=["documents", "metadatas", "distances"])
        out: list[RetrievedChunk] = []
        for cid, doc, md, dist in zip(res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0]):
            out.append(RetrievedChunk(chunk_id=cid, text=doc, metadata=ChunkMetadata.from_chroma(md), distance=float(dist)))
        return out

    def count(self, version: str) -> int:
        return self._col(version).count()
