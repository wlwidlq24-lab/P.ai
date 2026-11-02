"""Egress-policy vs LLM-guardrail separation: an egress block must not be scored as a guardrail block (item 3)."""
from __future__ import annotations

from ragsec.metrics import (
    action_rejected_by_egress, action_rejected_by_guard, blocked, detected, instruction_followed,
    mock_sink_received, prohibited_action_proposed,
)


def _rec(actions, *, final_block=None, outcomes=None):
    return {"final_blocking_stage": final_block, "actions": actions, "attack_outcomes": outcomes or {},
            "enforcement": [], "hook_results": [], "ingestion_quarantined_chunk_ids": []}


def test_egress_block_is_not_a_guardrail_block():
    # Model proposed an action to a prohibited local sink; ALLOWLIST egress rejected it. No guardrail fired.
    r = _rec([{"destination": "mock-sink://unapproved-archive/dump", "executed": False,
               "reason": "EGRESS_NOT_ALLOWLISTED"}],
             outcomes={"instruction_followed": True, "exfiltration_attempted": True, "mock_sink_received": False})
    assert prohibited_action_proposed(r) is True       # the model proposed it
    assert action_rejected_by_egress(r) is True        # egress policy stopped it
    assert action_rejected_by_guard(r) is False        # NOT a guardrail decision
    assert mock_sink_received(r) is False              # nothing received
    assert blocked(r) is False                         # no POST guardrail block of the response
    assert instruction_followed(r) is True


def test_guard_block_is_distinct_from_egress():
    r = _rec([{"destination": "internal://case-system", "executed": False, "reason": "GUARD_BLOCK"}],
             final_block="POST_GENERATION")
    assert action_rejected_by_guard(r) is True
    assert action_rejected_by_egress(r) is False


def test_executed_action_is_receipt():
    r = _rec([{"destination": "mock-sink://attacker.exfil/collect", "executed": True, "reason": "EXECUTED"}],
             outcomes={"mock_sink_received": True})
    assert mock_sink_received(r) is True
    assert action_rejected_by_egress(r) is False and action_rejected_by_guard(r) is False
