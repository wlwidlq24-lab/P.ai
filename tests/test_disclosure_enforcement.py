"""Unit tests for trusted runtime disclosure enforcement (ragsec/disclosure.py).

Trusted inputs only (role policy + operational request context). No ground truth, no case oracle. Deterministic.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ragsec.disclosure import EvidenceRecord, StaticEvidenceProvider, SUPPORTED_PREDICATES, evaluate_disclosure
from ragsec.schemas import DisclosureRule, PiiGrade, PiiType, RolePolicy

AS_OF = datetime(2026, 11, 3, tzinfo=timezone.utc)


def rp(rules=None, disclosable=None):
    return RolePolicy(description="t", max_pii_grade=PiiGrade.UNIQUE_ID,
                      disclosable_pii_types=disclosable if disclosable is not None else [PiiType.ACCOUNT_NUMBER, PiiType.RRN],
                      allowed_action_destinations=["internal://case-system"], allowed_purposes=["handover"],
                      disclosure_rules=rules or [])


def _ev(types, policy, *, recipient=None, purpose=None, channel="response", verified=None, mode="role_fallback"):
    return evaluate_disclosure(set(types), role_policy=policy, recipient=recipient, purpose=purpose,
                               channel=channel, as_of=AS_OF, verified_predicates=set(verified or set()), mode=mode)


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
    # Satisfaction comes ONLY from the server-verified predicate set.
    assert _ev({"account_number"}, policy, recipient="internal_successor",
               verified={"recipient_verified"}).decision == "ALLOW"
    assert _ev({"account_number"}, policy, recipient="internal_successor", verified=set()).decision == "HOLD"  # unmet
    unsup = DisclosureRule(recipient="internal_successor", channel="response",
                           allowed_pii_types=[PiiType.ACCOUNT_NUMBER], conditional_predicates=["made_up"])
    # an unsupported predicate is never inferred as satisfied, even if "verified"
    assert _ev({"account_number"}, rp(rules=[unsup]), recipient="internal_successor",
               verified={"made_up"}).decision == "HOLD"
    assert "made_up" not in SUPPORTED_PREDICATES


def test_strict_mode_holds_on_missing_or_unmatched_coverage():
    # No rules at all -> strict HOLD (readiness), not a flat-role ALLOW.
    d0 = _ev({"account_number"}, rp(rules=[]), recipient="x", mode="strict_rules")
    assert d0.decision == "HOLD" and "no_rules_configured" in d0.reasons and d0.rule_matched is False
    # Rules exist but none match this recipient -> strict HOLD with a distinct reason.
    rule = DisclosureRule(recipient="internal_successor", channel="response", allowed_pii_types=[PiiType.ACCOUNT_NUMBER])
    d1 = _ev({"account_number"}, rp(rules=[rule]), recipient="external_partner", mode="strict_rules")
    assert d1.decision == "HOLD" and "no_matching_rule" in d1.reasons
    # Matching rule in strict mode -> ALLOW, and resolution reports a matched rule.
    d2 = _ev({"account_number"}, rp(rules=[rule]), recipient="internal_successor", mode="strict_rules")
    assert d2.decision == "ALLOW" and d2.rule_matched is True and d2.mode == "strict_rules"


def test_fallback_mode_reports_resolution():
    d = _ev({"account_number"}, rp(rules=[], disclosable=[PiiType.ACCOUNT_NUMBER]), recipient="x", mode="role_fallback")
    assert d.decision == "ALLOW" and "role_fallback_allow" in d.reasons and d.rule_matched is False


def test_policy_change_before_action_flips_decision():
    r1 = DisclosureRule(recipient="internal_successor", channel="response", allowed_pii_types=[PiiType.RRN])
    r2 = DisclosureRule(recipient="auditor", channel="response", allowed_pii_types=[PiiType.RRN])
    before = _ev({"rrn"}, rp(rules=[r1]), recipient="internal_successor")
    after = _ev({"rrn"}, rp(rules=[r2]), recipient="internal_successor")  # trusted policy changed
    assert before.decision == "ALLOW" and after.decision == "DENY"


def test_no_pii_detected_is_allow():
    assert _ev(set(), rp()).decision == "ALLOW"


# --------------------------------------------------------------------------- context-bound evidence (server-side)
def _ctx(**over):
    base = dict(principal_id="p1", tenant_id="bank_a", recipient="internal_successor", purpose="handover",
                channel="response", scope="cust_1", as_of=AS_OF, requested_predicates={"recipient_verified"})
    base.update(over)
    return base


def _rec(**kw):
    return StaticEvidenceProvider([EvidenceRecord(predicate="recipient_verified", evidence_id="E1", version="1", **kw)])


def test_evidence_valid_context_verifies():
    p = _rec(recipient="internal_successor", channel="response")
    assert p.verified(**_ctx()) == {"recipient_verified"}


def test_evidence_reuse_across_context_fails():
    p = _rec(principal_id="p1", tenant_id="bank_a", recipient="internal_successor", purpose="handover",
             channel="response", scope="cust_1")
    for axis, val in [("principal_id", "p2"), ("tenant_id", "bank_b"), ("recipient", "external_partner"),
                      ("purpose", "marketing"), ("channel", "partner_feed"), ("scope", "cust_2")]:
        assert p.verified(**_ctx(**{axis: val})) == set(), f"bound evidence leaked across {axis}"


def test_evidence_expired_revoked_missing_mismatched_cannot_permit():
    from datetime import datetime, timezone
    expired = _rec(recipient="internal_successor", valid_to=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert expired.verified(**_ctx()) == set()                                   # expired
    assert _rec(recipient="internal_successor", revoked=True).verified(**_ctx()) == set()  # revoked
    assert StaticEvidenceProvider([]).verified(**_ctx()) == set()                # missing
    # a record for a DIFFERENT predicate cannot satisfy the requested one
    other = StaticEvidenceProvider([EvidenceRecord(predicate="approval_on_file", recipient="internal_successor")])
    assert other.verified(**_ctx()) == set()


def test_evidence_unsupported_predicate_never_verified():
    p = StaticEvidenceProvider([EvidenceRecord(predicate="made_up", recipient="internal_successor")])
    assert p.verified(**_ctx(requested_predicates={"made_up"})) == set()


def test_settings_reject_invalid_profile_and_mode():
    import pytest
    from ragsec.config import Settings
    with pytest.raises(Exception):
        Settings(min_enforcement_profile="bogus", api_key="abcdefgh")
    with pytest.raises(Exception):
        Settings(disclosure_policy_mode="bogus", api_key="abcdefgh")
    # valid combination constructs fine
    s = Settings(min_enforcement_profile="enforced", disclosure_policy_mode="strict_rules", api_key="abcdefgh")
    assert s.min_enforcement_profile == "enforced" and s.disclosure_policy_mode == "strict_rules"
