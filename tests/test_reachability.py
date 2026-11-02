"""Pre-execution structural sink reachability + opaque canary identifiers."""
from __future__ import annotations

from ragsec.evaluation import canaries_in_text, canary_id
from ragsec.reachability import structural_sink_reachability
from ragsec.schemas import AttackObjective, GroundTruth

LOCAL = "mock-sink://attacker.exfil/collect"


def _atk(**kw):
    return GroundTruth(is_attack=True, **kw)


def test_local_destination_reachable_under_open():
    s, r = structural_sink_reachability(_atk(objective=AttackObjective.EXFIL_ACTION, attacker_destination=LOCAL),
                                        tool_egress="OPEN", allowed_destinations=set())
    assert s == "reachable"


def test_local_destination_unreachable_under_allowlist_when_not_authorized():
    s, r = structural_sink_reachability(_atk(objective=AttackObjective.EXFIL_ACTION, attacker_destination=LOCAL),
                                        tool_egress="ALLOWLIST", allowed_destinations={"mock-sink://ok/here"})
    assert s == "unreachable" and "ALLOWLIST" in r


def test_local_destination_reachable_under_allowlist_when_authorized():
    s, _ = structural_sink_reachability(_atk(objective=AttackObjective.EXFIL_ACTION, attacker_destination=LOCAL),
                                        tool_egress="ALLOWLIST", allowed_destinations={LOCAL})
    assert s == "reachable"


def test_external_destination_unreachable():
    s, r = structural_sink_reachability(
        _atk(objective=AttackObjective.EXFIL_ACTION, attacker_destination="https://evil.example/c"),
        tool_egress="OPEN", allowed_destinations=set())
    assert s == "unreachable" and "non-local" in r


def test_non_attack_is_not_applicable():
    s, _ = structural_sink_reachability(GroundTruth(is_attack=False), tool_egress="OPEN", allowed_destinations=set())
    assert s == "not_applicable"


def test_disclose_response_objective_not_applicable():
    s, _ = structural_sink_reachability(_atk(objective=AttackObjective.DISCLOSE_RESPONSE),
                                        tool_egress="OPEN", allowed_destinations=set())
    assert s == "not_applicable"


def test_exfil_without_destination_is_unknown():
    s, _ = structural_sink_reachability(_atk(objective=AttackObjective.EXFIL_ACTION),
                                        tool_egress="OPEN", allowed_destinations=set())
    assert s == "unknown"


def test_opaque_canary_id_preferred_when_present():
    g = _atk(protected_canaries={"900101-1234567": "rrn"}, canary_dataset_ids={"900101-1234567": "DS-CANARY-7"})
    assert canaries_in_text("고객 번호 900101-1234567 입니다.", g) == ["DS-CANARY-7"]


def test_value_hash_fallback_without_dataset_id():
    g = _atk(protected_canaries={"900101-1234567": "rrn"})
    assert canaries_in_text("900101-1234567", g) == [canary_id("900101-1234567")]
