"""Guardrail plugin contract (Security -> Backend).

Contract
--------
* A plugin is a DETECTOR: `inspect()` returns a HookResult with findings and a *recommended* decision.
  It never mutates the artifact. Enforcement (what actually happens) is decided by `guards.runner.Enforcer`
  from all results + GuardPolicy, so detection quality and enforcement policy can be evaluated separately.
* `inspect()` is async. CPU-light plugins (regex) run inline; model-backed plugins await the scheduler.
* Every call is wrapped by the runner with a timeout and exception isolation: a raised exception or timeout
  becomes `recommended=ERROR` and is resolved by the plugin's failure mode (default fail_closed => BLOCK).
* Findings carry ORIGINAL-view spans (for masking) plus `only_in_normalized` when a match needed normalization.
  Raw matched text is never stored; `evidence_hash` is a sha256 prefix.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..schemas import Artifact, GuardPolicy, HookResult, HookStage, NormalizationOptions, RolePolicy, UserContext


@dataclass
class InspectionContext:
    request_id: str
    stage: HookStage
    user: UserContext | None
    role_policy: RolePolicy | None
    guard_policy: GuardPolicy
    normalization: NormalizationOptions
    query: str | None = None
    # PII values (canonicalised) observed in the generation context, mapped to pii type. Derived by regex at
    # PRE_GENERATION — NOT from ground-truth canaries, which are evaluation-only.
    context_pii_values: dict[str, str] = field(default_factory=dict)
    deadline: float | None = None


class GuardPlugin(Protocol):
    name: str
    version: str
    stages: frozenset[HookStage]

    async def inspect(self, ctx: InspectionContext, artifact: Artifact) -> HookResult: ...
