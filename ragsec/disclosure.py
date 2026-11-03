"""Trusted runtime disclosure enforcement.

This module decides whether detected PII TYPES in generated output may be disclosed, using ONLY trusted inputs:
  * the authenticated role's versioned disclosure policy (RolePolicy.disclosure_rules / disclosable_pii_types), and
  * the request's operational context (recipient, purpose, channel, as_of, disclosure_evidence).

It MUST NOT read evaluation ground truth (GroundTruth canaries) or the per-case evaluation oracle
(DisclosureOracle). Those are scoring constructs; letting them drive a runtime decision would conflate the
system under test with its answer key. Decisions are deterministic and produce a trace of TYPES only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .schemas import RolePolicy
from .timeutil import to_epoch

# Registry of SUPPORTED conditional predicates. An unsupported predicate id is treated as HELD (never inferred as
# allowed): the system does not guess legal permission for a condition it cannot evaluate.
SUPPORTED_PREDICATES: tuple[str, ...] = ("recipient_verified", "approval_on_file", "within_retention_period")


@dataclass
class DisclosureDecision:
    decision: str                               # "ALLOW" | "HOLD" | "DENY"
    allowed_types: list[str] = field(default_factory=list)
    held_types: list[str] = field(default_factory=list)
    denied_types: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)


def _predicate_status(pid: str, evidence: dict[str, bool]) -> str:
    if pid not in SUPPORTED_PREDICATES:
        return "unsupported"
    return "ok" if evidence.get(pid) is True else "unmet"


def _window_ok(rule, as_of: datetime) -> bool:
    ts = to_epoch(as_of)
    if rule.effective_from and to_epoch(rule.effective_from) > ts:
        return False
    if rule.effective_to and to_epoch(rule.effective_to) <= ts:
        return False
    return True


def _rule_matches(rule, recipient: str | None, purpose: str | None, channel: str | None) -> bool:
    return ((rule.recipient is None or rule.recipient == recipient)
            and (rule.purpose is None or rule.purpose == purpose)
            and (rule.channel is None or rule.channel == channel))


def evaluate_disclosure(detected_types: set[str], *, role_policy: RolePolicy, recipient: str | None,
                        purpose: str | None, channel: str | None, as_of: datetime,
                        evidence: dict[str, bool] | None) -> DisclosureDecision:
    """Per detected PII type, decide ALLOW / HOLD / DENY. Overall decision = DENY if any denied, else HOLD if any
    held, else ALLOW. Trusted inputs only; deterministic; trace carries types, never values."""
    evidence = evidence or {}
    allowed: list[str] = []
    held: list[str] = []
    denied: list[str] = []
    trace: list[str] = []
    rules = list(role_policy.disclosure_rules or [])
    base_disclosable = {p.value for p in role_policy.disclosable_pii_types}

    for t in sorted(detected_types):
        if not rules:
            # No recipient/purpose/channel rules configured: fall back to the role's flat disclosable types.
            if t in base_disclosable:
                allowed.append(t); trace.append(f"{t}: ALLOW (role-disclosable; no recipient rules)")
            else:
                denied.append(t); trace.append(f"{t}: DENY (not role-disclosable)")
            continue
        applicable = [r for r in rules if _rule_matches(r, recipient, purpose, channel)]
        granting_in_window = [r for r in applicable
                              if _window_ok(r, as_of) and t in {p.value for p in r.allowed_pii_types}]
        if not granting_in_window:
            expired = any(not _window_ok(r, as_of) and t in {p.value for p in r.allowed_pii_types}
                          for r in applicable)
            reason = "expired_authority" if expired else "no_matching_rule"
            denied.append(t); trace.append(f"{t}: DENY ({reason})")
            continue
        # A type is ALLOWed if some granting, in-window rule has ALL its predicates satisfied; otherwise, if a
        # granting rule exists but a predicate is unmet/unsupported, the type is HELD (never inferred allowed).
        verdict = "DENY"
        detail = "granting rule predicate(s) failed"
        for r in granting_in_window:
            statuses = {pid: _predicate_status(pid, evidence) for pid in r.conditional_predicates}
            if all(s == "ok" for s in statuses.values()):
                verdict = "ALLOW"
                detail = f"recipient={r.recipient},purpose={r.purpose},channel={r.channel}"
                break
            unresolved = {pid: s for pid, s in statuses.items() if s != "ok"}
            if unresolved and verdict != "ALLOW":
                verdict = "HOLD"
                detail = f"unresolved predicates {unresolved}"
        if verdict == "ALLOW":
            allowed.append(t); trace.append(f"{t}: ALLOW ({detail})")
        elif verdict == "HOLD":
            held.append(t); trace.append(f"{t}: HOLD ({detail})")
        else:
            denied.append(t); trace.append(f"{t}: DENY ({detail})")

    decision = "DENY" if denied else ("HOLD" if held else "ALLOW")
    return DisclosureDecision(decision=decision, allowed_types=sorted(set(allowed)),
                              held_types=sorted(set(held)), denied_types=sorted(set(denied)), trace=trace)
