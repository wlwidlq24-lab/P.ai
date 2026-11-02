"""Structural/consistency validation of the DEV candidate set. No efficacy execution, no model.

Metadata is validated against each document's ACTUAL content (PII is detected, not inferred from the file name
or the attack/benign label), per the requirement that attack docs need not contain PII and controls need not be
PII-free (the cross-document attack email has NO canary; the data-matched benign controls DO carry canaries).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ragsec.guards.pii import detect_pii
from ragsec.parsing import parse_document
from ragsec.schemas import Case, CaseType, DocumentMetadataIn, PiiType
from ragsec.sink import MockSink

STAGE = Path("data/staging/dev_candidates")
UNIQUE_ID_TYPES = {PiiType.RRN, PiiType.CARD_NUMBER, PiiType.ACCOUNT_NUMBER}
pytestmark = pytest.mark.skipif(not (STAGE / "candidate_cases.jsonl").exists(),
                                reason="run scripts/make_dev_candidates.py first")


def _cases() -> list[Case]:
    return [Case.model_validate_json(l) for l in (STAGE / "candidate_cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def _docrows() -> list[dict]:
    return [json.loads(l) for l in (STAGE / "documents.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def test_inventory_counts():
    c = _cases()
    attacks = [x for x in c if x.case_type == CaseType.ATTACK]
    assert len(attacks) == 4                                   # 3 self-contained + 1 cross-document
    assert sum(1 for x in c if x.case_type == CaseType.BENIGN_PII) == 4   # data-matched controls
    assert sum(1 for x in c if x.case_type == CaseType.BENIGN) == 3       # no-PII controls
    assert any("cross_document" in x.case_id for x in attacks)


def test_candidates_explicitly_unreviewed_and_blocked():
    from ragsec.metrics import is_eligible
    for c in _cases():
        if c.case_type == CaseType.ATTACK:
            assert c.attack_active is False and c.evaluation_eligible is False
            assert c.review is not None and c.review.status == "unreviewed"
            assert c.review.reviewer is None and c.review.reviewed_at is None   # no fabricated approval
            assert is_eligible({"ground_truth": {"is_attack": True}, "evaluation_eligible": c.evaluation_eligible}) is False


def test_each_attack_has_a_matched_control_same_actor_subject():
    cases = {c.case_id: c for c in _cases()}
    for c in cases.values():
        if c.case_type == CaseType.ATTACK:
            ctrl = cases.get(c.control_case_id)
            assert ctrl is not None and ctrl.case_type in (CaseType.BENIGN, CaseType.BENIGN_PII)
            assert ctrl.ground_truth.is_attack is False and ctrl.evaluation_eligible is True
            assert ctrl.user_id == c.user_id and ctrl.subject_id == c.subject_id


def test_cross_document_attack_email_contains_no_protected_canary():
    c = next(x for x in _cases() if "cross_document" in x.case_id and x.case_type == CaseType.ATTACK)
    email = (STAGE / "documents" / f"{c.ground_truth.attack_document_ids[0]}.txt").read_text(encoding="utf-8")
    norm = email.replace("-", "")
    for canary in c.ground_truth.protected_canaries:
        assert canary not in email and canary.replace("-", "") not in norm, "cross-doc email must carry no canary"
    assert c.ground_truth.protected_canaries                      # but the ground-truth canaries exist (in the CRM doc)


def test_metadata_matches_actual_document_content():
    # validate pii_grade against DETECTED content, regardless of attack/benign label
    for row in _docrows():
        meta = DocumentMetadataIn.model_validate({k: v for k, v in row.items() if k != "file"})
        text = (STAGE / "documents" / row["file"]).read_text(encoding="utf-8")
        has_unique_id = any(m.pii_type in UNIQUE_ID_TYPES for m in detect_pii(text))
        if meta.pii_grade.value == "none":
            assert not has_unique_id, f"{row['document_id']}: graded none but unique-id PII detected"
        else:
            assert has_unique_id, f"{row['document_id']}: graded {meta.pii_grade.value} but no unique-id PII detected"


def test_destinations_only_local_mock_sinks(tmp_path):
    sink = MockSink(tmp_path)
    for c in _cases():
        dest = c.ground_truth.attacker_destination
        if dest is not None:
            assert sink.is_local(dest) and not dest.startswith(("http://", "https://"))
    for p in (STAGE / "documents").glob("*.txt"):
        assert not re.search(r"https?://", p.read_text(encoding="utf-8"))


def test_docs_parse_and_authz_is_synthetic_experimental():
    for row in _docrows():
        data = (STAGE / "documents" / row["file"]).read_bytes()
        parsed = parse_document(data, row["file"], max_bytes=10_000_000, max_pages=200, max_chars=500_000,
                                min_chars_per_page=20)
        assert parsed.text.strip()
    for c in _cases():
        if c.case_type == CaseType.ATTACK:
            assert c.authorization is not None and c.authorization.actor_role == "compliance"
            crit = (c.ground_truth.observable_success_criteria or "").lower()
            assert ("receiv" in crit or "executed" in crit or "delivered" in crit)
            assert "not" in crit  # criteria explicitly state what is NOT success (text/echo/attempt)
