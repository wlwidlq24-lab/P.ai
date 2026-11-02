"""Pilot freeze/verify content-integrity tests (no model needed)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ragsec.config import Settings
from ragsec.dataset_gen import generate
from ragsec.errors import DatasetError
from ragsec.experiments import dataset_content_hash
from ragsec.pilot import compute_freeze, verify_freeze
from ragsec.schemas import Case, CaseReview, CaseType, ExperimentManifest, GuardMode


def _settings(tmp_path) -> Settings:
    return Settings(data_dir=tmp_path / "var", policy_dir="policies", dataset_root=tmp_path, api_key="x" * 8)


def _gen(tmp_path) -> Path:
    root = tmp_path / "ds"
    generate(root, seed=1, n_subjects=2, dataset_version="pilot-test")
    return root


def _manifest(case_ids) -> ExperimentManifest:
    return ExperimentManifest(experiment_id="dev-pilot-v1", dataset_dir="ds", splits=["dev"],
                              case_types=[CaseType.ATTACK, CaseType.BENIGN_PII], case_ids=case_ids,
                              guard_modes=[GuardMode.OFF, GuardMode.HYBRID], require_reviewed_attacks=True)


def _review_one_dev_attack(root: Path) -> tuple[str, str]:
    """Mark the first DEV attack case reviewed+active; return (attack_case_id, control_case_id). Re-hash dataset."""
    lines = [l for l in (root / "cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    cases = [Case.model_validate_json(l) for l in lines]
    target = next(c for c in cases if c.case_type == CaseType.ATTACK and c.split == "dev")
    target.attack_active = True
    target.evaluation_eligible = True
    target.exclusion_reason = None
    target.review = CaseReview(status="reviewed", reviewer="role3@example.local",
                               reviewed_at=datetime(2026, 10, 29, tzinfo=timezone.utc),
                               payload_provenance="unit-test template", notes="synthetic")
    out = [(target.model_dump_json() if c.case_id == target.case_id else l) for c, l in zip(cases, lines)]
    (root / "cases.jsonl").write_text("\n".join(out) + "\n", encoding="utf-8")
    _rehash(root)
    return target.case_id, target.control_case_id


def _rehash(root: Path) -> None:
    man = json.loads((root / "dataset_manifest.json").read_text(encoding="utf-8"))
    man["content_hash"] = dataset_content_hash(root)
    (root / "dataset_manifest.json").write_text(json.dumps(man), encoding="utf-8")


def test_freeze_refuses_unreviewed_attacks(tmp_path):
    _gen(tmp_path)
    s = _settings(tmp_path)
    # select some DEV attack cases (all placeholder/unreviewed) -> compute_freeze must refuse
    with pytest.raises(DatasetError) as e:
        compute_freeze(s, _manifest(None))
    assert "unreviewed" in e.value.message.lower()


def test_freeze_then_verify_ok_then_detects_drift(tmp_path):
    root = _gen(tmp_path)
    s = _settings(tmp_path)
    atk, ctrl = _review_one_dev_attack(root)
    m = _manifest([atk, ctrl])

    frozen = compute_freeze(s, m)
    assert atk in frozen["selected_attack_case_ids"]
    assert frozen["attack_document_hashes"]  # the reviewed attack's source doc is hashed
    assert verify_freeze(s, frozen) == []    # no drift immediately after freezing

    # --- drift 1: tamper the attack source document, then re-hash the dataset (approved-then-edited)
    doc_id = next(iter(frozen["attack_document_hashes"]))
    doc_path = root / "documents" / f"{doc_id}.txt"
    doc_path.write_text(doc_path.read_text(encoding="utf-8") + "\nTAMPERED", encoding="utf-8")
    _rehash(root)
    drift = verify_freeze(s, frozen)
    assert any("attack_document_hashes" in d for d in drift)
    assert any("dataset_content_hash" in d for d in drift)


def test_rehash_after_edit_still_fails_against_unchanged_frozen_baseline(tmp_path):
    """Item-5 clarification: re-computing the dataset hash after editing a document does NOT 'launder' the edit.
    verify_freeze compares against the UNCHANGED approved baseline, so the edit is still detected as drift.
    (The only way to defeat detection is to tamper with the approved frozen baseline file itself.)"""
    root = _gen(tmp_path)
    s = _settings(tmp_path)
    atk, ctrl = _review_one_dev_attack(root)
    frozen = compute_freeze(s, _manifest([atk, ctrl]))   # approved baseline (kept unchanged below)
    doc_id = next(iter(frozen["attack_document_hashes"]))
    doc_path = root / "documents" / f"{doc_id}.txt"
    doc_path.write_text(doc_path.read_text(encoding="utf-8") + "\nSILENTLY EDITED", encoding="utf-8")
    _rehash(root)  # attacker also recomputes the dataset's own hash so load_dataset(verify_hash=True) passes
    drift = verify_freeze(s, frozen)   # still compared to the ORIGINAL frozen baseline
    assert drift, "re-hashing after an edit must NOT pass verification against the unchanged frozen baseline"
    assert any("attack_document_hashes" in d for d in drift)


def test_verify_detects_case_metadata_change(tmp_path):
    root = _gen(tmp_path)
    s = _settings(tmp_path)
    atk, ctrl = _review_one_dev_attack(root)
    frozen = compute_freeze(s, _manifest([atk, ctrl]))
    # change a case's query (its JSON hash) and re-hash the dataset
    lines = [l for l in (root / "cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    cases = [Case.model_validate_json(l) for l in lines]
    for c in cases:
        if c.case_id == atk:
            c.query = c.query + " (edited)"
    (root / "cases.jsonl").write_text("\n".join(c.model_dump_json() for c in cases) + "\n", encoding="utf-8")
    _rehash(root)
    drift = verify_freeze(s, frozen)
    assert any("case_hashes" in d for d in drift)
