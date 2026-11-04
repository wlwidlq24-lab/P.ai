"""Trusted runtime disclosure enforcement.

Decides whether detected PII TYPES in generated output may be disclosed, using ONLY trusted inputs:
  * the authenticated role's versioned disclosure policy (RolePolicy.disclosure_rules / disclosable_pii_types),
  * the request's operational context (recipient, purpose, channel, as_of), and
  * SERVER-VERIFIED predicate facts produced by a trusted EvidenceProvider.

It MUST NOT read evaluation ground truth (GroundTruth canaries) or the per-case evaluation oracle
(DisclosureOracle); and it MUST NOT accept a client-supplied boolean as proof of a condition. A conditional
predicate is satisfied only when a trusted server-side provider verifies it. Decisions are deterministic and
carry a trace of TYPES only (never values).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from .schemas import RolePolicy
from .timeutil import to_epoch

# Registry of SUPPORTED conditional predicates. An unsupported predicate id is treated as HELD (never inferred as
# allowed): the system does not guess legal permission for a condition it cannot evaluate.
SUPPORTED_PREDICATES: tuple[str, ...] = ("recipient_verified", "approval_on_file", "within_retention_period")


# --------------------------------------------------------------------------- evidence providers (server-side)
@dataclass(frozen=True)
class EvidenceRecord:
    """A protected server-side fact that verifies ONE conditional predicate, BOUND TO A SPECIFIC CONTEXT. It is
    deliberately NOT a reusable global boolean: it verifies its predicate only for a request whose context matches
    every NON-None field here, within [valid_from, valid_to), and only while not revoked. Reuse across a different
    principal/tenant/recipient/purpose/channel/scope therefore fails. A None field is a wildcard for that one axis
    (use specific values to prevent reuse). `evidence_id`/`version` make the fact traceable/revocable."""
    predicate: str
    principal_id: str | None = None
    tenant_id: str | None = None
    recipient: str | None = None
    purpose: str | None = None
    channel: str | None = None
    scope: str | None = None            # data/policy scope (e.g., a subject id or policy id)
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    evidence_id: str | None = None
    version: str | None = None
    revoked: bool = False

    def matches(self, *, principal_id, tenant_id, recipient, purpose, channel, scope, as_of) -> bool:
        if self.revoked or self.predicate not in SUPPORTED_PREDICATES:
            return False
        ts = to_epoch(as_of)
        if self.valid_from and to_epoch(self.valid_from) > ts:
            return False
        if self.valid_to and to_epoch(self.valid_to) <= ts:
            return False
        ctx = {"principal_id": principal_id, "tenant_id": tenant_id, "recipient": recipient,
               "purpose": purpose, "channel": channel, "scope": scope}
        for fld, val in ctx.items():
            rec = getattr(self, fld)
            if rec is not None and rec != val:   # a bound field must match the request's context exactly
                return False
        return True


class EvidenceProvider(Protocol):
    """Produces the set of conditional-predicate IDs that are SERVER-VERIFIED for a request's FULL context.
    Implementations draw from protected server-side records / validated evidence references — NEVER the request
    body. The context identifies principal/tenant/recipient/purpose/channel/scope and the evaluation time."""
    def verified(self, *, principal_id: str | None, tenant_id: str | None, recipient: str | None,
                 purpose: str | None, channel: str | None, scope: str | None, as_of: datetime,
                 requested_predicates: set[str]) -> set[str]: ...


class NullEvidenceProvider:
    """Operational default: no server-side facts are configured, so NO predicate is verified. Conditional
    disclosures are therefore HELD (fail-closed). Not driven by any client assertion."""
    def verified(self, *, principal_id=None, tenant_id=None, recipient=None, purpose=None, channel=None,
                 scope=None, as_of=None, requested_predicates=None):
        return set()


@dataclass
class StaticEvidenceProvider:
    """A deterministic, server-constructed provider of VERIFIED evidence RECORDS (for tests and trusted local
    config). NOT the request's disclosure_evidence; a client cannot populate it. Each record is context-bound
    (see EvidenceRecord), so a fact verified for one recipient/tenant/scope does not leak to another."""
    records: list[EvidenceRecord] = field(default_factory=list)

    def verified(self, *, principal_id=None, tenant_id=None, recipient=None, purpose=None, channel=None,
                 scope=None, as_of, requested_predicates=None):
        want = set(requested_predicates) if requested_predicates is not None else None
        out: set[str] = set()
        for rec in self.records:
            if want is not None and rec.predicate not in want:
                continue
            if rec.matches(principal_id=principal_id, tenant_id=tenant_id, recipient=recipient,
                           purpose=purpose, channel=channel, scope=scope, as_of=as_of):
                out.add(rec.predicate)
        return out & set(SUPPORTED_PREDICATES)


# --------------------------------------------------------------------------- decision
@dataclass
class DisclosureDecision:
    decision: str                               # "ALLOW" | "HOLD" | "DENY"
    allowed_types: list[str] = field(default_factory=list)
    held_types: list[str] = field(default_factory=list)
    denied_types: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    # Policy-resolution transparency: the mode used and whether a recipient/purpose/channel rule actually matched.
    mode: str = "role_fallback"
    rule_matched: bool = False
    reasons: list[str] = field(default_factory=list)  # distinct resolution reasons encountered (sorted, unique)


def _window_ok(rule, as_of: datetime) -> bool:
    ts = to_epoch(as_of)
    if rule.effective_from and to_epoch(rule.effective_from) > ts:
        return False
    if rule.effective_to and to_epoch(rule.effective_to) <= ts:
        return False
    return True


def _rule_matches(rule, recipient, purpose, channel) -> bool:
    return ((rule.recipient is None or rule.recipient == recipient)
            and (rule.purpose is None or rule.purpose == purpose)
            and (rule.channel is None or rule.channel == channel))


def evaluate_disclosure(detected_types: set[str], *, role_policy: RolePolicy, recipient: str | None,
                        purpose: str | None, channel: str | None, as_of: datetime,
                        verified_predicates: set[str] | None = None,
                        mode: str = "role_fallback") -> DisclosureDecision:
    """Per detected PII type, decide ALLOW / HOLD / DENY. Overall = DENY if any denied, else HOLD if any held,
    else ALLOW. `verified_predicates` is the set of SERVER-VERIFIED predicate ids (from a trusted EvidenceProvider,
    NEVER the client). `mode`: 'role_fallback' flattens to role disclosable when no rules apply; 'strict_rules'
    HOLDS on missing/unmatched coverage. Deterministic; trace/reasons carry types & reason codes only."""
    verified = set(verified_predicates or set())
    allowed: list[str] = []
    held: list[str] = []
    denied: list[str] = []
    trace: list[str] = []
    reasons: set[str] = set()
    rule_matched = False
    rules = list(role_policy.disclosure_rules or [])
    base_disclosable = {p.value for p in role_policy.disclosable_pii_types}
    applicable = [r for r in rules if _rule_matches(r, recipient, purpose, channel)]
    if applicable:
        rule_matched = True

    for t in sorted(detected_types):
        granting_in_window = [r for r in applicable
                              if _window_ok(r, as_of) and t in {p.value for p in r.allowed_pii_types}]
        if not rules:
            # No recipient/purpose/channel rules configured for this role at all.
            if mode == "strict_rules":
                held.append(t); reasons.add("no_rules_configured")
                trace.append(f"{t}: HOLD (strict: no disclosure_rules configured for role)")
            elif t in base_disclosable:
                allowed.append(t); reasons.add("role_fallback_allow")
                trace.append(f"{t}: ALLOW (role-disclosable; no recipient rules)")
            else:
                denied.append(t); reasons.add("not_role_disclosable")
                trace.append(f"{t}: DENY (not role-disclosable)")
            continue
        if not granting_in_window:
            # The role HAS rules (it opted into recipient-aware policy), so an uncovered recipient/context/type is
            # NOT silently flattened to flat role permissions: role_fallback DENIES (rules take precedence) and
            # strict HOLDS (readiness). An expired-but-otherwise-granting rule is a DENY (authority lapsed).
            expired = any(not _window_ok(r, as_of) and t in {p.value for p in r.allowed_pii_types}
                          for r in applicable)
            if expired:
                denied.append(t); reasons.add("expired_authority")
                trace.append(f"{t}: DENY (expired_authority)")
            elif mode == "strict_rules":
                held.append(t); reasons.add("no_matching_rule")
                trace.append(f"{t}: HOLD (strict: no matching trusted rule for this recipient/context/type)")
            else:
                denied.append(t); reasons.add("no_matching_rule")
                trace.append(f"{t}: DENY (rules present but none grant this recipient/context/type)")
            continue
        # A type is ALLOWed if some granting, in-window rule has ALL predicates server-verified; else, if a
        # granting rule exists but a predicate is unmet/unsupported, the type is HELD (never inferred allowed).
        verdict = "DENY"
        detail = "granting rule predicate(s) failed"
        for r in granting_in_window:
            statuses = {}
            for pid in r.conditional_predicates:
                if pid not in SUPPORTED_PREDICATES:
                    statuses[pid] = "unsupported"
                else:
                    statuses[pid] = "ok" if pid in verified else "unmet"
            if all(s == "ok" for s in statuses.values()):
                verdict = "ALLOW"
                detail = f"recipient={r.recipient},purpose={r.purpose},channel={r.channel}"
                break
            unresolved = {pid: s for pid, s in statuses.items() if s != "ok"}
            if unresolved and verdict != "ALLOW":
                verdict = "HOLD"
                detail = f"unresolved predicates {unresolved}"
        if verdict == "ALLOW":
            allowed.append(t); reasons.add("rule_allow")
            trace.append(f"{t}: ALLOW ({detail})")
        elif verdict == "HOLD":
            held.append(t); reasons.add("condition_unmet")
            trace.append(f"{t}: HOLD ({detail})")
        else:
            denied.append(t); reasons.add("condition_denied")
            trace.append(f"{t}: DENY ({detail})")

    decision = "DENY" if denied else ("HOLD" if held else "ALLOW")
    return DisclosureDecision(decision=decision, allowed_types=sorted(set(allowed)), held_types=sorted(set(held)),
                             denied_types=sorted(set(denied)), trace=trace, mode=mode, rule_matched=rule_matched,
                             reasons=sorted(reasons))
