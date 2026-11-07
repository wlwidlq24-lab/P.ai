"""Typed readiness/response contract shared by the CLI preflight output and a future researcher-facing endpoint.

This is a SCHEMA DRAFT (no HTTP route is added here). It reports submission + freeze readiness WITHOUT any
authority to start a run: a dry-run readiness report ALWAYS sets `execution_allowed=False`. Efficacy execution
stays on HOLD until all required inputs carry valid HUMAN review for their exact versions and an approved freeze
verifies — none of which this tool can grant.

Null semantics worth noting:
  * `FreezeStatus.approved_baseline == ABSENT` (no human-approved baseline supplied) is DISTINCT from
    `verification == DRIFT` (a baseline exists but current artifacts do not match it).
  * `candidate_digest is None` means a candidate freeze could not be computed (an upstream gate blocked it),
    distinct from a computed digest with execution still on HOLD.

Routine status output must NOT carry secrets, raw payloads, protected data, or local absolute paths — only
opaque ids, enum codes, short messages and hash PREFIXES. Callers building HTTP responses from this reuse the
existing researcher/admin authorization boundary (see api.py); this module adds no new surface by itself.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .timeutil import utc_now

READINESS_SCHEMA_VERSION = "readiness/1.0"


class GateStatus(StrEnum):
    PASS = "pass"          # the gate's checks hold for the supplied artifacts
    BLOCKED = "blocked"    # a required input is missing/invalid; readiness cannot proceed here
    NOT_RUN = "not_run"    # not evaluated (e.g. no approved baseline to verify against yet)
    FAIL = "fail"          # an active defect (e.g. detected drift)


class ReadinessStatus(StrEnum):
    READY = "ready"        # every gate passes for the supplied artifacts (still not an execution authorization)
    BLOCKED = "blocked"    # at least one gate is blocked/failed
    ERROR = "error"        # the tool could not produce a complete report


class EfficacyStatus(StrEnum):
    HOLD = "hold"              # efficacy execution is not authorized (the default, and the only honest value
                              # until humans approve the exact versions and the approved freeze verifies)
    ELIGIBLE = "eligible"     # all AUTOMATED gates pass AND an approved baseline verifies; still needs an
                              # explicit human go — never implies execution_allowed


class ReviewState(StrEnum):
    REVIEWED = "reviewed"
    UNREVIEWED = "unreviewed"
    MISSING = "missing"       # the input was not supplied at all


class MatchState(StrEnum):
    MATCH = "match"           # the reviewed artifact version matches the selected/used artifact
    MISMATCH = "mismatch"     # a review exists but for a different artifact version/bytes
    UNKNOWN = "unknown"       # cannot be determined (e.g. input missing)
    ABSENT = "absent"         # no review artifact to match


class ReasonCode(StrEnum):
    """Stable reason codes. The first six are the required set; the rest are explicit, documented equivalents
    used by specific gates. Treat the string values as the stable contract."""
    MISSING_INPUT = "MISSING_INPUT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REVIEW_ARTIFACT_MISMATCH = "REVIEW_ARTIFACT_MISMATCH"
    POLICY_MAPPING_MISMATCH = "POLICY_MAPPING_MISMATCH"
    UNRESOLVED_BUDGET = "UNRESOLVED_BUDGET"
    FREEZE_DRIFT = "FREEZE_DRIFT"
    # --- documented equivalents (narrower causes rolled up under the six above where asked) ---
    DATASET_INTEGRITY = "DATASET_INTEGRITY"          # G3: schema/hash/lineage problem
    PLACEHOLDER_PAYLOAD = "PLACEHOLDER_PAYLOAD"      # G2: attack still holds [IPI_PAYLOAD_PLACEHOLDER]
    UNRESOLVED_DECISION = "UNRESOLVED_DECISION"      # G1: a rule row is UNRESOLVED (held, not ALLOW/DENY)
    COVERAGE_GAP = "COVERAGE_GAP"                    # G5: freeze does not cover an artifact class
    BASELINE_ABSENT = "BASELINE_ABSENT"              # G6: no approved baseline supplied


class RequiredInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_id: str                          # e.g. "legal_disclosure_rules", "security_cases_d14", "uiux_metrics"
    owner: str                             # team/role responsible
    review_state: ReviewState
    artifact_version: str | None = None    # opaque version/hash-prefix of what was supplied (never a path)
    review_match: MatchState = MatchState.UNKNOWN
    note: str = ""


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    gate_id: str                           # "G1".."G6"
    title: str
    status: GateStatus
    reason_codes: list[ReasonCode] = Field(default_factory=list)
    message: str = ""                      # short, actionable; no payloads/paths/secrets


class PolicyMappingSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    supported_rules: int = 0               # rows expressible exactly in the runtime schema
    semantic_mismatches: list[str] = Field(default_factory=list)  # rule_id: short reason
    unresolved_rules: list[str] = Field(default_factory=list)     # rule_ids held as UNRESOLVED


class FreezeStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_digest: str | None = None    # hash prefix of a computable candidate freeze, or None if not computable
    approved_baseline: Literal["absent", "present"] = "absent"
    verification: Literal["not_run", "match", "drift", "unverifiable"] = "not_run"
    drift: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)  # artifact classes the freeze does NOT pin


class ExecutionAccounting(BaseModel):
    model_config = ConfigDict(extra="forbid")
    planned_requests: int | None = None     # units the manifest WOULD plan (never executed here)
    attempted_model_requests: int = 0        # always 0 for a readiness/dry-run report
    preflight_rejected: bool = False         # True when readiness is not READY (a rejection, not a run)


class ReadinessReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["readiness/1.0"] = READINESS_SCHEMA_VERSION
    checked_at: datetime = Field(default_factory=utc_now)
    manifest_id: str | None = None
    readiness_status: ReadinessStatus
    efficacy_status: EfficacyStatus = EfficacyStatus.HOLD
    execution_allowed: bool = False          # a readiness report NEVER authorizes execution
    required_inputs: list[RequiredInput] = Field(default_factory=list)
    gates: list[GateResult] = Field(default_factory=list)
    policy_mapping: PolicyMappingSummary | None = None
    freeze: FreezeStatus = Field(default_factory=FreezeStatus)
    execution_accounting: ExecutionAccounting = Field(default_factory=ExecutionAccounting)
    notes: list[str] = Field(default_factory=list)

    def rollup(self) -> "ReadinessReport":
        """Derive the overall status fields from the gates. Keeps the invariant: execution is never authorized
        from here, and efficacy is ELIGIBLE only when every gate PASSes (and only then does a human decide)."""
        statuses = {g.status for g in self.gates}
        if GateStatus.FAIL in statuses or GateStatus.BLOCKED in statuses:
            self.readiness_status = ReadinessStatus.BLOCKED
        elif statuses and statuses <= {GateStatus.PASS}:
            self.readiness_status = ReadinessStatus.READY
        elif GateStatus.NOT_RUN in statuses and not (statuses - {GateStatus.PASS, GateStatus.NOT_RUN}):
            # everything that ran passed, but a verification step (e.g. G6) has no baseline yet
            self.readiness_status = ReadinessStatus.BLOCKED
        all_pass = bool(self.gates) and all(g.status == GateStatus.PASS for g in self.gates)
        self.efficacy_status = EfficacyStatus.ELIGIBLE if all_pass else EfficacyStatus.HOLD
        self.execution_allowed = False       # invariant
        self.execution_accounting.attempted_model_requests = 0
        self.execution_accounting.preflight_rejected = self.readiness_status != ReadinessStatus.READY
        return self
