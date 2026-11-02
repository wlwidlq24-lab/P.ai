"""Pilot freeze/verify: content-integrity locking for a reviewed DEV pilot.

`compute_freeze` resolves the selected cases and records content hashes of everything that defines the
experiment (manifest, dataset content, each selected case's JSON, the attack source documents, the active
policies, the prompt template, and the reproducibility-relevant settings). It REFUSES to freeze while any
selected attack case is unreviewed/ineligible.

`verify_freeze` recomputes those hashes and reports drift. Execution must verify immediately before running and
REJECT on any mismatch — approved content is never silently re-hashed. The approved freeze file is preserved;
execution records are written separately (per-run log dir), so freeze and results never overwrite each other.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import Settings
from .errors import DatasetError
from .experiments import load_dataset, manifest_hash, resolve_dataset_dir, select_cases
from .policy import load_active
from .rag import PROMPT_TEMPLATE_VERSION
from .schemas import CaseType, ExperimentManifest
from .textproc import sha256_bytes, sha256_text
from .timeutil import utc_now

FREEZE_SCHEMA_VERSION = "pilot-freeze/1.0"


def _settings_fingerprint(s: Settings) -> dict[str, Any]:
    return {"seed": s.seed, "temperature": s.temperature, "retrieval_top_k": s.retrieval_top_k,
            "max_distance": s.max_distance, "chunk_size": s.chunk_size, "chunk_overlap": s.chunk_overlap,
            "embedding_model": s.embedding_model, "guard_model": s.guard_model,
            "normalization_version": None}  # normalization_version is per-chunk; dataset hash already covers content


def compute_freeze(settings: Settings, m: ExperimentManifest, *, require_reviewed: bool = True) -> dict[str, Any]:
    root = resolve_dataset_dir(settings, m.dataset_dir)
    ds = load_dataset(root, verify_hash=True)  # also asserts dataset files match the dataset manifest hash
    cases = select_cases(ds, m)
    if not cases:
        raise DatasetError("freeze: manifest selects no cases")
    if require_reviewed:
        bad = [c.case_id for c in cases if c.case_type == CaseType.ATTACK
               and not (c.evaluation_eligible and c.review is not None and c.review.status == "reviewed")]
        if bad:
            raise DatasetError("freeze refused: unreviewed/ineligible attack cases selected",
                               detail={"unreviewed_attack_cases": bad[:20], "n": len(bad)})
    doc_paths = {meta.document_id: path for meta, path in ds.documents}
    case_hashes: dict[str, str] = {}
    doc_hashes: dict[str, str] = {}
    for c in cases:
        case_hashes[c.case_id] = sha256_text(c.model_dump_json())
        for doc_id in c.ground_truth.attack_document_ids:
            p = doc_paths.get(doc_id)
            if p is None:
                raise DatasetError(f"freeze: attack_document_id {doc_id} not found for case {c.case_id}")
            doc_hashes[doc_id] = sha256_bytes(Path(p).read_bytes())
    policies = load_active(settings.policy_dir)
    return {
        "schema_version": FREEZE_SCHEMA_VERSION,
        "frozen_at": utc_now().isoformat(),
        "experiment_id": m.experiment_id,
        "manifest_hash": manifest_hash(m),
        "manifest": json.loads(m.model_dump_json()),
        "dataset_dir": m.dataset_dir,
        "dataset_version": ds.manifest.dataset_version,
        "dataset_content_hash": ds.manifest.content_hash,
        "selected_case_ids": sorted(c.case_id for c in cases),
        "selected_attack_case_ids": sorted(c.case_id for c in cases if c.case_type == CaseType.ATTACK),
        "control_case_ids": sorted({c.control_case_id for c in cases if c.control_case_id}),
        "case_hashes": case_hashes,
        "attack_document_hashes": doc_hashes,
        "policy_versions": policies.versions,
        "policy_file_hashes": policies.file_hashes,
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "settings_fingerprint": _settings_fingerprint(settings),
    }


def verify_freeze(settings: Settings, frozen: dict[str, Any]) -> list[str]:
    """Return a list of drift descriptions (empty => content matches the approved freeze)."""
    drift: list[str] = []
    try:
        m = ExperimentManifest.model_validate(frozen["manifest"])
    except Exception as e:  # a tampered manifest is itself drift
        return [f"manifest unparseable: {e}"]
    if manifest_hash(m) != frozen["manifest_hash"]:
        drift.append("manifest_hash mismatch")
    try:
        current = compute_freeze(settings, m, require_reviewed=False)
    except DatasetError as e:
        return [f"cannot recompute freeze: {e.message} {e.detail}"]
    if current["dataset_content_hash"] != frozen["dataset_content_hash"]:
        drift.append(f"dataset_content_hash changed ({frozen['dataset_content_hash'][:12]} -> "
                     f"{current['dataset_content_hash'][:12]})")
    for key in ("case_hashes", "attack_document_hashes", "policy_file_hashes"):
        old, new = frozen.get(key, {}), current.get(key, {})
        for k in sorted(set(old) | set(new)):
            if old.get(k) != new.get(k):
                drift.append(f"{key}: {k} changed/added/removed")
    if current["prompt_template_version"] != frozen["prompt_template_version"]:
        drift.append("prompt_template_version changed")
    if current["settings_fingerprint"] != frozen["settings_fingerprint"]:
        drift.append("settings_fingerprint changed")
    if sorted(current["selected_case_ids"]) != sorted(frozen["selected_case_ids"]):
        drift.append("selected case set changed")
    return drift
