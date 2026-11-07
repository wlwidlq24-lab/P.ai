"""Legal rule mapping + round-trip comparison (ragsec/rulemap.py).

Verifies: a supported rule preserves runtime behaviour; an unsupported representation/predicate produces an
actionable mismatch (never silently coerced to ALLOW/DENY); CONDITIONAL and UNRESOLVED stay distinct; the
schema round trip is identity; and the default command writes only to a separate output dir.
"""
from __future__ import annotations

from ragsec.rulemap import RuleRow, RuleSubmission, map_submission, write_outputs


def _sub(rows, mode="strict_rules"):
    return RuleSubmission(submission_id="t", policy_mode=mode, rows=rows)


def _scen(result, rule_id):
    return {s.name: s for s in result.scenarios[rule_id]}


def test_supported_allow_rule_preserves_behavior():
    row = RuleRow(rule_id="R1", role="compliance", recipient="internal_successor", purpose="handover",
                  channel="response", allowed_pii_types=["account_number"], decision="ALLOW",
                  validity_from="2026-01-01T00:00:00+00:00", validity_to="2027-01-01T00:00:00+00:00")
    res = map_submission(_sub([row], mode="role_fallback"))
    mr = res.rules[0]
    assert mr.expression == "grant" and mr.emitted is not None and not mr.mismatches
    s = _scen(res, "R1")
    assert s["valid_window"].observed == "ALLOW" and s["valid_window"].ok
    assert s["expired_window"].observed == "DENY"            # authority lapsed
    assert s["mismatched_context"].observed == "DENY"        # uncovered recipient, role_fallback
    assert res.behavior_ok


def test_conditional_met_vs_missing_evidence():
    row = RuleRow(rule_id="R1", role="compliance", recipient="internal_successor", channel="response",
                  allowed_pii_types=["account_number"], conditions=["recipient_verified"], decision="CONDITIONAL")
    res = map_submission(_sub([row]))
    s = _scen(res, "R1")
    assert s["valid_window"].observed == "ALLOW"             # condition verified in the valid scenario
    assert s["missing_evidence"].observed == "HOLD"          # no server evidence -> held, never allowed
    assert res.rules[0].expression == "grant"


def test_unsupported_representation_is_not_coerced():
    # ALLOW intended but only in a masked/summarized form: the runtime cannot express "disclose but masked".
    row = RuleRow(rule_id="R3", role="credit_officer", recipient="internal_successor", channel="response",
                  allowed_pii_types=["credit_info"], decision="ALLOW", permitted_form="summarized")
    res = map_submission(_sub([row]))
    mr = res.rules[0]
    assert mr.emitted is None                                 # NOT emitted as an unmasked ALLOW
    assert mr.expression == "unsupported_representation"
    assert any("representation_unsupported" in x for x in mr.mismatches)
    assert res.policy_mapping_summary().supported_rules == 0


def test_unsupported_predicate_flagged_and_holds():
    row = RuleRow(rule_id="R1", role="compliance", recipient="internal_successor", channel="response",
                  allowed_pii_types=["account_number"], conditions=["made_up_predicate"], decision="CONDITIONAL")
    res = map_submission(_sub([row]))
    mr = res.rules[0]
    assert any("unsupported_predicate" in x for x in mr.mismatches)
    # a granting rule exists but the predicate can never be satisfied -> HOLD, never ALLOW
    assert _scen(res, "R1")["valid_window"].observed == "HOLD"


def test_unresolved_is_distinct_from_deny():
    deny = RuleRow(rule_id="D", role="compliance", recipient="external_partner", channel="response",
                   allowed_pii_types=["rrn"], decision="DENY")
    unres = RuleRow(rule_id="U", role="compliance", recipient="overseas_partner", channel="response",
                    allowed_pii_types=["account_number"], decision="UNRESOLVED")
    res = map_submission(_sub([deny, unres]))
    exprs = {r.rule_id: r.expression for r in res.rules}
    assert exprs["D"] == "deny_by_omission" and exprs["U"] == "held_unresolved"
    assert res.policy_mapping_summary().unresolved_rules == ["U"]
    # UNRESOLVED under strict mode HOLDS (held pending), never silently denied away as a flat DENY
    assert _scen(res, "U")["valid_window"].expected == "HOLD"


def test_overlapping_rules_precedence():
    a = RuleRow(rule_id="A", role="compliance", recipient="internal_successor", channel="response",
                allowed_pii_types=["account_number"], decision="ALLOW")
    b = RuleRow(rule_id="B", role="compliance", recipient="auditor", channel="response",
                allowed_pii_types=["rrn"], decision="ALLOW")
    res = map_submission(_sub([a, b], mode="role_fallback"))
    # A's account to internal_successor allowed; B's recipient does not grant account -> A still governs account
    assert _scen(res, "A")["valid_window"].observed == "ALLOW"
    assert _scen(res, "A")["mismatched_context"].observed == "DENY"


def test_schema_round_trip_is_identity():
    row = RuleRow(rule_id="R1", role="compliance", recipient="internal_successor", purpose="handover",
                  channel="response", allowed_pii_types=["account_number", "rrn"],
                  conditions=["recipient_verified"], decision="CONDITIONAL",
                  validity_from="2026-01-01T00:00:00+09:00")
    res = map_submission(_sub([row]))
    assert res.rules[0].roundtrip == []                       # YAML->same loader->same model: no drift


def test_write_outputs_isolated(tmp_path):
    row = RuleRow(rule_id="R1", role="compliance", recipient="internal_successor", channel="response",
                  allowed_pii_types=["account_number"], decision="ALLOW")
    res = map_submission(_sub([row]))
    out = write_outputs(res, tmp_path / "rm")
    assert out["candidate_yaml"].exists() and out["report_md"].exists() and out["result_json"].exists()
    assert "UNAPPROVED" in out["candidate_yaml"].read_text(encoding="utf-8")
    # nothing is written outside the requested output dir
    assert out["candidate_yaml"].parent == (tmp_path / "rm")
