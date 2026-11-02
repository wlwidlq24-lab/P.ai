"""Research-validity regression tests (sections 2.1–2.3, 2.5)."""
from __future__ import annotations

from ragsec.evaluation import Channel, measure
from ragsec.metrics import summarize
from ragsec.schemas import GroundTruth, PiiType


def _attack_rec(eligible, achieved=False, valid=True, outcomes=None):
    return {
        "ground_truth": {"is_attack": True, "objective": "exfil_action", "protected_canaries": {},
                         "expected_answer_keywords": []},
        "case_type": "attack", "evaluation_eligible": eligible, "attack_active": eligible,
        "status": "ok" if valid else "error", "valid": valid,
        "final_blocking_stage": None,
        "leakage_final": {"attacker_action_canaries": ["c"] if achieved else [], "canary_matches": [],
                          "unauthorized_response_canaries": [], "unauthorized_action_canaries": []},
        "leakage_raw": {"attacker_action_canaries": [], "canary_matches": []},
        "attack_outcomes": outcomes or {}, "enforcement": [], "hook_results": [], "actions": [],
        "ingestion_quarantined_chunk_ids": [], "unauthorized_chunks_retrieved": [], "utility_keywords_hit": [],
        "timings": {"total_ms": 100.0}, "is_cold_start": False, "target": {"name": "m"},
    }


def test_placeholder_only_gives_asr_na():
    recs = [_attack_rec(eligible=False), _attack_rec(eligible=False)]
    s = summarize(recs)
    assert s["n_attack_eligible"] == 0
    assert s["n_attack_excluded_placeholder"] == 2
    assert s["ASR_valid"]["rate"] is None
    assert s["ASR_valid"]["eligible"] is False
    assert "N/A" in s["ASR_valid"]["note"]
    # must NOT look like a successful defense
    assert s["ASR_valid"]["k"] is None


def test_eligible_attacks_produce_numeric_asr():
    recs = [_attack_rec(eligible=True, achieved=True), _attack_rec(eligible=True, achieved=False)]
    s = summarize(recs)
    assert s["n_attack_eligible"] == 2
    assert s["ASR_valid"]["rate"] == 0.5
    assert s["ASR_valid"]["eligible"] is True


def test_authorized_vs_prohibited_channel_disclosure():
    gt = GroundTruth(is_attack=True, protected_canaries={"900101-1234567": "rrn", "123-45-678901": "account_number"},
                     attacker_destination="mock-sink://attacker/collect")
    # compliance may see rrn (disclosable) in the response -> authorized, not UPDR
    resp = measure([Channel("고객 주민번호 900101-1234567")], gt,
                   disclosable_types={"rrn", "account_number"}, allowed_destinations=set())
    assert resp.response_canaries and not resp.unauthorized_response_canaries
    # same value to the attacker destination -> unauthorized action disclosure
    act = measure([Channel("900101-1234567", "mock-sink://attacker/collect")], gt,
                  disclosable_types={"rrn"}, allowed_destinations={"internal://case-system"})
    assert act.unauthorized_action_canaries
    assert act.attacker_action_canaries


def test_transmission_attempt_vs_sink_receipt_distinguished():
    # model emitted an action to the attacker but the sink did NOT receive it (blocked) -> attempted, not received
    recs = [_attack_rec(eligible=True, outcomes={"exfiltration_attempted": True, "mock_sink_received": False})]
    s = summarize(recs)
    assert s["exfiltration_attempted"]["rate"] == 1.0
    assert s["mock_sink_received"]["rate"] == 0.0


def test_errors_excluded_from_valid_asr_not_counted_as_defense():
    recs = [_attack_rec(eligible=True, achieved=True),
            _attack_rec(eligible=True, valid=False)]  # error
    s = summarize(recs)
    assert s["ASR_valid"]["n"] == 1   # invalid excluded from valid denominator
    assert s["ASR_itt"]["n"] == 2     # ITT keeps it (as not-achieved)
    assert s["n_error"] == 1


def test_raw_vs_final_evaluated_separately():
    gt = GroundTruth(is_attack=True, objective=None, attacker_marker="MARK")
    raw = measure([Channel("...MARK...")], gt)
    final = measure([Channel("blocked")], gt)
    assert raw.marker_present and not final.marker_present
