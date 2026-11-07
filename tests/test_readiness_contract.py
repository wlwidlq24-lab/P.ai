"""Readiness/response contract (ragsec/readiness.py).

Validates the three required synthetic response examples and the contract invariants: a readiness report never
authorizes execution; an absent approved baseline is distinguishable from a baseline that fails verification;
and the rollup derives status from the gates.
"""
from __future__ import annotations

from ragsec.readiness import (
    EfficacyStatus, ExecutionAccounting, FreezeStatus, GateResult, GateStatus, MatchState, PolicyMappingSummary,
    ReadinessReport, ReadinessStatus, ReasonCode, RequiredInput, ReviewState,
)


def _example_no_submissions() -> ReadinessReport:
    return ReadinessReport(
        manifest_id="dev-pilot", readiness_status=ReadinessStatus.BLOCKED,
        required_inputs=[
            RequiredInput(input_id="legal_disclosure_rules", owner="Legal/Privacy (Role 1)",
                          review_state=ReviewState.MISSING, review_match=MatchState.ABSENT),
            RequiredInput(input_id="security_cases_d14", owner="Security/Guardrails (Role 3)",
                          review_state=ReviewState.MISSING, review_match=MatchState.ABSENT),
            RequiredInput(input_id="uiux_metrics", owner="UI/UX·Metrics (Role 4)",
                          review_state=ReviewState.MISSING, review_match=MatchState.ABSENT)],
        gates=[GateResult(gate_id="G1", title="Policy and evaluation", status=GateStatus.BLOCKED,
                          reason_codes=[ReasonCode.MISSING_INPUT]),
               GateResult(gate_id="G2", title="Human review", status=GateStatus.BLOCKED,
                          reason_codes=[ReasonCode.MISSING_INPUT])]).rollup()


def _example_mismatch_or_stale() -> ReadinessReport:
    return ReadinessReport(
        manifest_id="dev-pilot", readiness_status=ReadinessStatus.BLOCKED,
        required_inputs=[RequiredInput(input_id="legal_disclosure_rules", owner="Legal/Privacy (Role 1)",
                                       review_state=ReviewState.UNREVIEWED, artifact_version="legal-v2",
                                       review_match=MatchState.MISMATCH)],
        policy_mapping=PolicyMappingSummary(supported_rules=2, semantic_mismatches=["R3: representation_unsupported:summarized"],
                                            unresolved_rules=["R4"]),
        gates=[GateResult(gate_id="G1", title="Policy and evaluation", status=GateStatus.BLOCKED,
                          reason_codes=[ReasonCode.POLICY_MAPPING_MISMATCH, ReasonCode.UNRESOLVED_DECISION]),
               GateResult(gate_id="G2", title="Human review", status=GateStatus.BLOCKED,
                          reason_codes=[ReasonCode.REVIEW_ARTIFACT_MISMATCH]),
               GateResult(gate_id="G3", title="Data integrity", status=GateStatus.PASS)]).rollup()


def _example_clean_preflight_on_hold() -> ReadinessReport:
    r = ReadinessReport(
        manifest_id="dev-pilot", readiness_status=ReadinessStatus.READY,
        required_inputs=[RequiredInput(input_id="legal_disclosure_rules", owner="Legal/Privacy (Role 1)",
                                       review_state=ReviewState.REVIEWED, artifact_version="legal-ok",
                                       review_match=MatchState.MATCH)],
        gates=[GateResult(gate_id=g, title=g, status=GateStatus.PASS) for g in ("G1", "G2", "G3", "G4", "G5", "G6")],
        freeze=FreezeStatus(candidate_digest="9cd8d2e5c8ef58da", approved_baseline="present", verification="match"),
        execution_accounting=ExecutionAccounting(planned_requests=136)).rollup()
    return r


def test_three_examples_validate_and_roundtrip():
    for ex in (_example_no_submissions(), _example_mismatch_or_stale(), _example_clean_preflight_on_hold()):
        dumped = ex.model_dump_json()
        again = ReadinessReport.model_validate_json(dumped)
        assert again.schema_version == "readiness/1.0"


def test_execution_is_never_authorized():
    for ex in (_example_no_submissions(), _example_mismatch_or_stale(), _example_clean_preflight_on_hold()):
        assert ex.execution_allowed is False
        assert ex.execution_accounting.attempted_model_requests == 0


def test_clean_preflight_is_eligible_but_on_hold():
    ex = _example_clean_preflight_on_hold()
    assert ex.readiness_status == ReadinessStatus.READY
    assert ex.efficacy_status == EfficacyStatus.ELIGIBLE   # all gates pass...
    assert ex.execution_allowed is False                   # ...yet execution still needs a human go
    assert ex.freeze.candidate_digest == "9cd8d2e5c8ef58da"


def test_absent_baseline_distinct_from_failed_verification():
    absent = FreezeStatus(approved_baseline="absent", verification="not_run")
    failed = FreezeStatus(approved_baseline="present", verification="drift", drift=["case_hashes: X changed"])
    assert absent.approved_baseline != failed.approved_baseline
    assert absent.verification == "not_run" and failed.verification == "drift"
    # null candidate digest (not computable) is distinct from a computed digest
    assert FreezeStatus().candidate_digest is None


def test_rollup_blocks_on_any_nonpass():
    r = ReadinessReport(readiness_status=ReadinessStatus.READY,
                        gates=[GateResult(gate_id="G1", title="x", status=GateStatus.PASS),
                               GateResult(gate_id="G2", title="y", status=GateStatus.BLOCKED)]).rollup()
    assert r.readiness_status == ReadinessStatus.BLOCKED
    assert r.efficacy_status == EfficacyStatus.HOLD
    assert r.execution_accounting.preflight_rejected is True
