"""Unit tests for trusted runtime disclosure enforcement (ragsec/disclosure.py).

Trusted inputs only (role policy + operational request context). No ground truth, no case oracle. Deterministic.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ragsec.disclosure import SUPPORTED_PREDICATES, evaluate_disclosure
from ragsec.schemas import DisclosureRule, PiiGrade, PiiType, RolePolicy

AS_OF = datetime(2026, 11, 3, tzinfo=timezone.utc)


def rp(rules=None, disclosable=None):
    return RolePolicy(description="t", max_pii_grade=PiiGrade.UNIQUE_ID,
                      disclosable_pii_types=disclosable if disclosable is not None else [PiiType.ACCOUNT_NUMBER, PiiType.RRN],
                      allowed_action_destinations=["internal://case-system"], allowed_purposes=["handover"],
                      disclosure_rules=rules or [])


def _ev(types, policy, *, recipient=None, purpose=None, channel="response", evidence=None):
    return evaluate_disclosure(set(types), role_policy=policy, recipient=recipient, purpose=purpose,
                               channel=channel, as_of=AS_OF, evidence=evidence or {})


def test_fallback_allows_role_disclosable_and_denies_others():
    d = _ev({"account_number", "email"}, rp(disclosable=[PiiType.ACCOUNT_NUMBER]))
    assert d.decision == "DENY"
    assert d.allowed_types == ["account_number"] and d.denied_types == ["email"]


def test_recipient_rule_allow_vs_deny():
    rule = DisclosureRule(recipient="internal_successor", channel="response", allowed_pii_types=[PiiType.ACCOUNT_NUMBER])
    policy = rp(rules=[rule])
    assert _ev({"account_number"}, policy, recipient="internal_successor").decision == "ALLOW"
    assert _ev({"account_number"}, policy, recipient="external_partner").decision == "DENY"


def test_rules_take_precedence_over_flat_disclosable():
    # rrn is role-disclosable, but with rules present only the rule-granted recipient is allowed.
    rule = DisclosureRule(recipient="auditor", channel="response", allowed_pii_types=[PiiType.RRN])
    assert _ev({"rrn"}, rp(rules=[rule]), recipient="internal_successor").decision == "DENY"


def test_expired_authority_denies():
    rule = DisclosureRule(recipient="internal_successor", channel="response",
                          allowed_pii_types=[PiiType.ACCOUNT_NUMBER], effective_to="2026-06-01T00:00:00+00:00")
    d = _ev({"account_number"}, rp(rules=[rule]), recipient="internal_successor")
    assert d.decision == "DENY" and "expired_authority" in " ".join(d.trace)


def test_conditional_met_unmet_unsupported():
    rule = DisclosureRule(recipient="internal_successor", channel="response",
                          allowed_pii_types=[PiiType.ACCOUNT_NUMBER], conditional_predicates=["recipient_verified"])
    policy = rp(rules=[rule])
    assert _ev({"account_number"}, policy, recipient="internal_successor",
               evidence={"recipient_verified": True}).decision == "ALLOW"
    assert _ev({"account_number"}, policy, recipient="internal_successor",
               evidence={"recipient_verified": False}).decision == "HOLD"   # unmet -> held
    assert _ev({"account_number"}, policy, recipient="internal_successor", evidence={}).decision == "HOLD"  # missing -> held
    unsup = DisclosureRule(recipient="internal_successor", channel="response",
                           allowed_pii_types=[PiiType.ACCOUNT_NUMBER], conditional_predicates=["made_up"])
    # an unsupported predicate is never inferred as satisfied
    assert _ev({"account_number"}, rp(rules=[unsup]), recipient="internal_successor",
               evidence={"made_up": True}).decision == "HOLD"
    assert "made_up" not in SUPPORTED_PREDICATES


def test_policy_change_before_action_flips_decision():
    r1 = DisclosureRule(recipient="internal_successor", channel="response", allowed_pii_types=[PiiType.RRN])
    r2 = DisclosureRule(recipient="auditor", channel="response", allowed_pii_types=[PiiType.RRN])
    before = _ev({"rrn"}, rp(rules=[r1]), recipient="internal_successor")
    after = _ev({"rrn"}, rp(rules=[r2]), recipient="internal_successor")  # trusted policy changed
    assert before.decision == "ALLOW" and after.decision == "DENY"


def test_no_pii_detected_is_allow():
    assert _ev(set(), rp()).decision == "ALLOW"
