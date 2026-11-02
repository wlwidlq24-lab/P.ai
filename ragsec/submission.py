"""Submission handling: validate document files + metadata sidecars + an optional submission index.

A "submission" is how non-dataset documents (e.g. a legal corpus) are brought in: each document is a file
(.txt/.pdf) with a sibling `<document_id>.meta.json` sidecar (a DocumentMetadataIn record), optionally listed
in a `submission_index.csv`. This module performs deterministic, actionable validation and a dry-run that never
touches the active index. Ingestion itself is delegated to the existing versioned Ingestor (idempotent: a
re-submission of identical id+version+content is skipped).

source_url in metadata is provenance only and is NEVER fetched here (no URL-ingestion / SSRF surface).
Successful ingestion does NOT imply legal approval or human review — review_status is declarative metadata.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from .parsing import parse_document
from .policy import PolicyBundle
from .schemas import DocumentKind, DocumentMetadataIn, PiiGrade, SourceType, TrustLevel

INDEX_REQUIRED_COLUMNS = ("document_id", "document_version", "document_kind", "source_type",
                          "source_trust_level", "pii_grade", "tenant_id", "allowed_roles", "file_path")
_ENUM_COLUMNS = {"document_kind": DocumentKind, "source_type": SourceType,
                 "source_trust_level": TrustLevel, "pii_grade": PiiGrade}
ALLOWED_DOC_EXTS = (".txt", ".pdf")


@dataclass
class SubmissionItem:
    document_id: str
    meta_path: Path
    doc_path: Path | None
    meta: DocumentMetadataIn | None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and self.meta is not None and self.doc_path is not None


@dataclass
class SubmissionReport:
    sub_dir: Path
    items: list[SubmissionItem]
    index_errors: list[str] = field(default_factory=list)

    @property
    def ok_items(self) -> list[SubmissionItem]:
        return [i for i in self.items if i.ok]

    @property
    def error_items(self) -> list[SubmissionItem]:
        return [i for i in self.items if not i.ok]

    @property
    def ok(self) -> bool:
        return not self.index_errors and all(i.ok for i in self.items) and bool(self.items)

    def to_dict(self) -> dict:
        return {"sub_dir": str(self.sub_dir), "n_items": len(self.items),
                "n_ok": len(self.ok_items), "n_error": len(self.error_items),
                "index_errors": self.index_errors,
                "items": [{"document_id": i.document_id, "ok": i.ok,
                           "doc_path": str(i.doc_path) if i.doc_path else None, "errors": i.errors}
                          for i in self.items]}


def validate_submission_index(csv_path: Path) -> list[str]:
    """Deterministic structural validation of a submission index CSV. Returns actionable error strings
    (empty => structurally valid). Does NOT check that files exist — that is done by load_submission."""
    errors: list[str] = []
    try:
        text = csv_path.read_text(encoding="utf-8-sig")
    except OSError as e:
        return [f"cannot read index {csv_path.name}: {e}"]
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None:
        return [f"{csv_path.name}: empty or headerless CSV"]
    missing_cols = [c for c in INDEX_REQUIRED_COLUMNS if c not in reader.fieldnames]
    if missing_cols:
        errors.append(f"{csv_path.name}: missing required columns {missing_cols}")
        return errors
    seen: set[tuple[str, str]] = set()
    for n, row in enumerate(reader, start=2):  # row 1 is the header
        did = (row.get("document_id") or "").strip()
        if not did:
            errors.append(f"row {n}: document_id is empty")
        ver = (row.get("document_version") or "").strip()
        if not ver.isdigit() or int(ver) < 1:
            errors.append(f"row {n} ({did}): document_version must be an integer >= 1, got {ver!r}")
        for col, enum in _ENUM_COLUMNS.items():
            val = (row.get(col) or "").strip()
            if val and val not in {e.value for e in enum}:
                errors.append(f"row {n} ({did}): {col}={val!r} not one of {[e.value for e in enum]}")
        if not (row.get("allowed_roles") or "").strip():
            errors.append(f"row {n} ({did}): allowed_roles is empty (use '|'-separated roles)")
        if not (row.get("tenant_id") or "").strip():
            errors.append(f"row {n} ({did}): tenant_id is empty")
        if not (row.get("file_path") or "").strip():
            errors.append(f"row {n} ({did}): file_path is empty")
        if did and ver.isdigit():
            key = (did, ver)
            if key in seen:
                errors.append(f"row {n}: duplicate (document_id, document_version)=({did}, {ver})")
            seen.add(key)
    return errors


def _find_doc_file(meta_path: Path, document_id: str) -> tuple[Path | None, str | None]:
    """Resolve the document file for a sidecar: prefer <document_id>.<ext>, else the sibling sharing the
    sidecar stem (minus '.meta'). Returns (path, error)."""
    d = meta_path.parent
    for ext in ALLOWED_DOC_EXTS:
        cand = d / f"{document_id}{ext}"
        if cand.exists():
            return cand, None
    stem = meta_path.name[:-len(".meta.json")] if meta_path.name.endswith(".meta.json") else meta_path.stem
    cands = [p for ext in ALLOWED_DOC_EXTS for p in [d / f"{stem}{ext}"] if p.exists()]
    if len(cands) == 1:
        return cands[0], None
    if not cands:
        return None, f"no document file ({'/'.join(ALLOWED_DOC_EXTS)}) found next to {meta_path.name}"
    return None, f"ambiguous document files for {meta_path.name}: {[c.name for c in cands]}"


def load_submission(sub_dir: Path, settings, *, policies: PolicyBundle | None = None,
                    index_name: str = "submission_index.csv") -> SubmissionReport:
    """Discover sidecars, validate metadata + files (+ optional index + policy cross-checks). No ingestion."""
    sub_dir = sub_dir.resolve()
    items: list[SubmissionItem] = []
    index_errors: list[str] = []
    index_path = sub_dir / index_name
    index_ids: set[str] | None = None
    if index_path.exists():
        index_errors = validate_submission_index(index_path)
        try:
            rows = list(csv.DictReader(index_path.read_text(encoding="utf-8-sig").splitlines()))
            index_ids = {(r.get("document_id") or "").strip() for r in rows if (r.get("document_id") or "").strip()}
        except Exception as e:  # already partly covered by validate_submission_index
            index_errors.append(f"{index_name}: cannot parse rows: {e}")

    sidecars = sorted(sub_dir.rglob("*.meta.json"))
    for mp in sidecars:
        try:
            raw = json.loads(mp.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            items.append(SubmissionItem(document_id=mp.stem, meta_path=mp, doc_path=None, meta=None,
                                        errors=[f"invalid JSON: {e}"]))
            continue
        errs: list[str] = []
        meta: DocumentMetadataIn | None = None
        try:
            meta = DocumentMetadataIn.model_validate(raw)
        except ValidationError as e:
            errs.append("metadata invalid: " + "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}"
                                                         for x in e.errors(include_url=False)[:8]))
        did = meta.document_id if meta else str(raw.get("document_id") or mp.stem)
        doc_path, derr = _find_doc_file(mp, did)
        if derr:
            errs.append(derr)
        if doc_path is not None:
            try:  # parse to catch size/type/encoding problems before ingestion
                data = doc_path.read_bytes()
                parse_document(data, doc_path.name, max_bytes=settings.max_upload_bytes,
                               max_pages=settings.max_pdf_pages, max_chars=settings.max_extracted_chars,
                               min_chars_per_page=settings.min_chars_per_page_for_text_pdf)
            except Exception as e:
                errs.append(f"document unreadable: {type(e).__name__}: {e}")
        if meta is not None and policies is not None:
            if meta.tenant_id not in policies.access.tenants:
                errs.append(f"tenant {meta.tenant_id!r} not in access policy")
            unknown = [r for r in meta.allowed_roles if r not in policies.access.roles]
            if unknown:
                errs.append(f"allowed_roles not in access policy: {unknown}")
        items.append(SubmissionItem(document_id=did, meta_path=mp, doc_path=doc_path, meta=meta, errors=errs))

    if index_ids is not None:
        found = {i.document_id for i in items}
        for missing in sorted(index_ids - found):
            index_errors.append(f"index lists {missing!r} but no {missing}.meta.json sidecar was found")
        for extra in sorted(found - index_ids):
            index_errors.append(f"sidecar {extra!r} is not listed in {index_name}")
    if not sidecars:
        index_errors.append(f"no *.meta.json sidecars found under {sub_dir}")
    return SubmissionReport(sub_dir=sub_dir, items=items, index_errors=index_errors)
