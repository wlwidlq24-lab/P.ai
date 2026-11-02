"""Stage execution (timeouts, exception isolation) and enforcement (detection -> decision)."""
from __future__ import annotations

import asyncio
import logging
import time

from ..errors import RagSecError
from ..schemas import (
    Artifact, Decision, EnforcementRecord, Finding, GuardPolicy, HookResult, HookStage, Transformation,
)
from .base import GuardPlugin, InspectionContext

log = logging.getLogger(__name__)
REDACTION_TOKEN = "[REDACTED:{cat}]"


async def run_plugin(plugin: GuardPlugin, ctx: InspectionContext, artifact: Artifact, timeout_s: float) -> HookResult:
    t0 = time.perf_counter()
    try:
        return await asyncio.wait_for(plugin.inspect(ctx, artifact), timeout=timeout_s)
    except TimeoutError:
        err = f"PLUGIN_TIMEOUT after {timeout_s}s"
    except RagSecError as e:
        err = f"{e.code}: {e.message}"
    except Exception as e:  # isolation: a plugin bug must not crash the request
        log.exception("plugin %s failed", plugin.name)
        err = f"UNHANDLED: {type(e).__name__}"
    return HookResult(plugin=plugin.name, plugin_version=plugin.version, stage=ctx.stage,
                      artifact_id=artifact.artifact_id, recommended=Decision.ERROR, error=err,
                      duration_ms=(time.perf_counter() - t0) * 1000)


async def run_stage(plugins: list[GuardPlugin], ctx: InspectionContext, artifacts: list[Artifact],
                    timeout_s: float) -> dict[str, list[HookResult]]:
    """Runs plugins sequentially per artifact in PLUGIN_ORDER (model plugins are GPU-serialized anyway)."""
    out: dict[str, list[HookResult]] = {}
    for art in artifacts:
        results = []
        for p in plugins:
            if ctx.stage in p.stages:
                results.append(await run_plugin(p, ctx, art, timeout_s))
        out[art.artifact_id] = results
    return out


def mask_spans(text: str, findings: list[Finding]) -> tuple[str, list[Transformation]]:
    spans = sorted({(f.location.start, f.location.end, f.category) for f in findings
                    if f.location is not None and f.location.view == "original"}, key=lambda x: x[0])
    merged: list[tuple[int, int, str]] = []
    for s, e, c in spans:
        if merged and s < merged[-1][1]:
            ps, pe, pc = merged[-1]
            merged[-1] = (ps, max(pe, e), pc)
        else:
            merged.append((s, e, c))
    out, last, counts = [], 0, {}
    for s, e, c in merged:
        out.append(text[last:s])
        out.append(REDACTION_TOKEN.format(cat=c.split(".")[-1]))
        last = e
        counts[c] = counts.get(c, 0) + 1
    out.append(text[last:])
    return "".join(out), [Transformation(type=f"redact.{c}", artifact_id="", count=n) for c, n in counts.items()]


class Enforcer:
    """Resolves plugin recommendations into one decision per artifact.

    Rules (in order):
      1. ERROR -> BLOCK (fail_closed, default) or ignored (fail_open) per plugin failure mode.
      2. Combination rule: provenance.low_trust + IPI score >= low-trust threshold => QUARANTINE (chunks).
      3. Final decision = most severe remaining recommendation.
      4. REDACT applies span masking from all REDACT-recommending plugins' located findings.
    """

    def __init__(self, policy: GuardPolicy):
        self.policy = policy

    def failure_mode(self, plugin: str) -> str:
        return self.policy.plugin_failure_mode.get(plugin, self.policy.default_failure_mode)

    def decide(self, stage: HookStage, artifact: Artifact, results: list[HookResult]) -> tuple[EnforcementRecord, str]:
        reasons: list[str] = []
        decisions: list[Decision] = [Decision.ALLOW]
        redact_findings: list[Finding] = []
        for r in results:
            rec = r.recommended
            if rec == Decision.ERROR:
                if self.failure_mode(r.plugin) == "fail_closed":
                    decisions.append(Decision.BLOCK)
                    reasons.append(f"{r.plugin}:ERROR_FAIL_CLOSED")
                else:
                    reasons.append(f"{r.plugin}:ERROR_FAIL_OPEN")
                continue
            if rec != Decision.ALLOW:
                decisions.append(rec)
                reasons.extend(f"{r.plugin}:{f.reason_code}" for f in r.findings
                               if f.score > 0 and not f.category.startswith(("ipi.score",)))
            if rec == Decision.REDACT:
                redact_findings.extend(f for f in r.findings if f.location is not None and f.score > 0)
        # Combination rule (provenance x IPI)
        if artifact.kind.value == "chunk":
            low_trust = any(f.category == "provenance.low_trust" for r in results for f in r.findings)
            ipi_score = max((f.score for r in results for f in r.findings if f.category == "ipi.score"), default=0.0)
            if low_trust and ipi_score >= self.policy.ipi_quarantine_low_trust_threshold:
                decisions.append(Decision.QUARANTINE)
                reasons.append(f"combo:LOW_TRUST_IPI_{ipi_score}")
        final = max(decisions, key=lambda d: d.severity)
        text = artifact.original
        transformations: list[Transformation] = []
        if final == Decision.REDACT:
            text, transformations = mask_spans(artifact.original, redact_findings)
            for t in transformations:
                t.artifact_id = artifact.artifact_id
        elif final in (Decision.QUARANTINE, Decision.BLOCK):
            transformations = [Transformation(type=f"{final.value.lower()}.{artifact.kind.value}",
                                              artifact_id=artifact.artifact_id)]
        rec = EnforcementRecord(stage=stage, artifact_id=artifact.artifact_id, decision=final,
                                reasons=sorted(set(reasons)), plugins=[r.plugin for r in results],
                                transformations=transformations)
        return rec, text
