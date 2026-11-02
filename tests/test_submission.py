"""Submission index validation + dry-run submission loading (ragsec/submission.py)."""
from __future__ import annotations

import json
from pathlib import Path

from ragsec.config import Settings
from ragsec.schemas import DocumentMetadataIn
from ragsec.submission import load_submission, validate_submission_index

REPO = Path(__file__).resolve().parent.parent
GOOD_META = {
    "document_id": "sub_doc_a", "document_version": 1, "source_name": "합성 내부정책",
    "source_type": "internal_wiki", "source_trust_level": "high", "document_kind": "internal_policy",
    "law_or_policy_id": "policy-a", "pii_grade": "none", "tenant_id": "bank_a",
    "allowed_roles": ["compliance"], "review_status": "submitted",
}
GOOD_INDEX = ("document_id,document_version,document_kind,source_type,source_trust_level,pii_grade,"
              "tenant_id,allowed_roles,file_path\n"
              "sub_doc_a,1,internal_policy,internal_wiki,high,none,bank_a,compliance,sub_doc_a.txt\n")


def _write_submission(d: Path, with_index: bool = True) -> None:
    (d / "sub_doc_a.txt").write_text("제1조(목적) 합성 문서.\n제2조(정의) 용어.\n", encoding="utf-8")
    (d / "sub_doc_a.meta.json").write_text(json.dumps(GOOD_META, ensure_ascii=False), encoding="utf-8")
    if with_index:
        (d / "submission_index.csv").write_text(GOOD_INDEX, encoding="utf-8")


def test_committed_template_is_directly_valid():
    raw = json.loads((REPO / "docs/handoff/templates/document_metadata.template.json").read_text(encoding="utf-8"))
    obj = DocumentMetadataIn.model_validate(raw)  # must validate with NO stripping of comment keys
    assert obj.schema_version == "doc-meta/1.1"


def test_committed_index_template_structurally_valid():
    errs = validate_submission_index(REPO / "docs/handoff/templates/submission_index.template.csv")
    assert errs == []


def test_valid_index_passes(tmp_path: Path):
    p = tmp_path / "idx.csv"
    p.write_text(GOOD_INDEX, encoding="utf-8")
    assert validate_submission_index(p) == []


def test_index_reports_actionable_errors(tmp_path: Path):
    p = tmp_path / "idx.csv"
    p.write_text("document_id,document_version,file_path\nbad id,0,\n", encoding="utf-8")
    errs = validate_submission_index(p)
    assert any("missing required columns" in e for e in errs)


def test_index_bad_values_rows(tmp_path: Path):
    p = tmp_path / "idx.csv"
    bad = GOOD_INDEX.replace("1,internal_policy", "0,not_a_kind").replace("compliance,sub_doc_a.txt", ",sub_doc_a.txt")
    p.write_text(bad, encoding="utf-8")
    errs = validate_submission_index(p)
    assert any("document_version must be an integer" in e for e in errs)
    assert any("document_kind=" in e for e in errs)
    assert any("allowed_roles is empty" in e for e in errs)


def test_load_submission_dry_run_ok(tmp_path: Path):
    _write_submission(tmp_path)
    report = load_submission(tmp_path, Settings(), policies=None)
    assert report.ok, report.to_dict()
    assert len(report.ok_items) == 1
    assert report.ok_items[0].meta.document_id == "sub_doc_a"


def test_load_submission_detects_missing_document_file(tmp_path: Path):
    (tmp_path / "sub_doc_a.meta.json").write_text(json.dumps(GOOD_META, ensure_ascii=False), encoding="utf-8")
    report = load_submission(tmp_path, Settings(), policies=None)
    assert not report.ok
    assert any("no document file" in e for it in report.error_items for e in it.errors)


def test_load_submission_index_sidecar_mismatch(tmp_path: Path):
    _write_submission(tmp_path, with_index=True)
    # index references an id that has no sidecar
    (tmp_path / "submission_index.csv").write_text(
        GOOD_INDEX + "ghost_doc,1,internal_policy,internal_wiki,high,none,bank_a,compliance,ghost.txt\n",
        encoding="utf-8")
    report = load_submission(tmp_path, Settings(), policies=None)
    assert any("ghost_doc" in e for e in report.index_errors)
