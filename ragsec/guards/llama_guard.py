"""Llama Guard 3 safety-classification plugin.

Llama Guard 3 is a HARMFUL-CONTENT classifier, NOT an indirect-prompt-injection detector; HYBRID combines it
with separate IPI rules. Its Korean performance is a hypothesis to be measured (RQ4), not assumed.

Taxonomy VERIFIED 2026-10-28 from the installed `llama-guard3:1b` template (digest 494147e0..., Q8_0): this
model enumerates S1-S13 ONLY — S1 Violent, S2 Non-Violent Crimes, S3 Sex Crimes, S4 Child Exploitation,
S5 Defamation, S6 Specialized Advice, S7 Privacy, S8 IP, S9 Indiscriminate Weapons, S10 Hate, S11 Self-Harm,
S12 Sexual Content, S13 Elections. There is NO S14 in this model (that is an 8B-taxonomy category).

Output contract (template): first line "safe" or "unsafe"; if unsafe, second line lists categories (e.g. "S7").
Indeterminate results (empty/unparseable output, timeout) are returned as recommended=ERROR with a distinct
`safety.indeterminate` finding, NOT as a valid safe/unsafe classification; the Enforcer resolves ERROR via the
guard-policy failure mode (fail_closed => BLOCK). Metrics count indeterminate as error, never as a defense.
"""
from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING

from ..errors import MalformedModelResponseError
from ..schemas import Artifact, ArtifactKind, Decision, Finding, HookResult, HookStage
from .base import InspectionContext

if TYPE_CHECKING:
    from ..llm.base import LLMClient
    from ..scheduler import ModelScheduler

PLUGIN_VERSION = "llama_guard/1.1"
_CAT = re.compile(r"S\d{1,2}")
# llama-guard3:1b taxonomy (verified from the model template 2026-10-28): S1-S13 only (no S14).
VALID_CATEGORIES = frozenset(f"S{i}" for i in range(1, 14))


def parse_guard_output(text: str) -> tuple[bool, list[str]]:
    """Return (unsafe, raw_codes). Codes are returned EXACTLY as reported (deduped/sorted), NOT filtered — the
    caller preserves them and decides how to treat codes outside this model's taxonomy. Empty or non-safe/unsafe
    heads raise MalformedModelResponseError (handled as indeterminate by the plugin)."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        raise MalformedModelResponseError("empty Llama Guard output")
    head = lines[0].lower()
    if head == "safe":
        return False, []
    if head == "unsafe":
        return True, sorted(set(_CAT.findall(" ".join(lines[1:]))))
    raise MalformedModelResponseError(f"unexpected Llama Guard output head: {lines[0][:40]!r}")


class LlamaGuardPlugin:
    name = "llama_guard"
    version = PLUGIN_VERSION
    stages = frozenset(HookStage)

    def __init__(self, client: "LLMClient", scheduler: "ModelScheduler", model: str, num_ctx: int,
                 keep_alive: str, timeout_s: float, seed: int):
        self.client = client
        self.scheduler = scheduler
        self.model = model
        self.num_ctx = num_ctx
        self.keep_alive = keep_alive
        self.timeout_s = timeout_s
        self.seed = seed
        self.last_load_ms: float | None = None

    def _messages(self, ctx: InspectionContext, artifact: Artifact) -> list[dict[str, str]]:
        text = artifact.normalized if ctx.normalization.detect_on_normalized else artifact.original
        if artifact.kind in (ArtifactKind.RESPONSE, ArtifactKind.ACTION):
            return [{"role": "user", "content": ctx.query or ""}, {"role": "assistant", "content": text}]
        return [{"role": "user", "content": text}]

    async def classify(self, messages: list[dict[str, str]], deadline: float | None) -> tuple[bool, list[str]]:
        async with self.scheduler.slot(self.model, deadline=deadline):
            res = await self.client.chat(self.model, messages,
                                         options={"temperature": 0.0, "seed": self.seed, "num_ctx": self.num_ctx,
                                                  "num_predict": 20},
                                         keep_alive=self.keep_alive, timeout_s=self.timeout_s, deadline=deadline)
        self.last_load_ms = res.load_ms
        return parse_guard_output(res.text)

    async def inspect(self, ctx: InspectionContext, artifact: Artifact) -> HookResult:
        t0 = time.perf_counter()
        if artifact.kind == ArtifactKind.CHUNK and not ctx.guard_policy.llama_guard_on_chunks:
            return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                              artifact_id=artifact.artifact_id, recommended=Decision.ALLOW,
                              findings=[Finding(category="safety.skipped", reason_code="CHUNKS_DISABLED", score=0)],
                              duration_ms=0.0)
        try:
            unsafe, cats = await self.classify(self._messages(ctx, artifact), ctx.deadline)
        except MalformedModelResponseError as e:
            # Indeterminate: unparseable/empty output. Recorded distinctly as ERROR (not a safe/unsafe verdict);
            # the Enforcer resolves ERROR via the guard-policy failure mode (fail_closed => BLOCK).
            return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                              artifact_id=artifact.artifact_id, recommended=Decision.ERROR,
                              findings=[Finding(category="safety.indeterminate", reason_code="PARSE_FAILURE", score=0)],
                              error=f"MALFORMED_MODEL_RESPONSE: {e.message}",
                              duration_ms=(time.perf_counter() - t0) * 1000)
        # Preserve ALL reported codes (known + unknown) in the record.
        findings = [Finding(category=f"safety.{c}", reason_code="LLAMA_GUARD_UNSAFE") for c in cats]
        unknown = [c for c in cats if c not in VALID_CATEGORIES]
        if unknown:
            # A code outside this model's S1-S13 taxonomy is an INCONSISTENT output -> indeterminate (ERROR),
            # never silently downgraded to "safe". Enforcer resolves ERROR via the fail-closed guard policy.
            findings.append(Finding(category="safety.indeterminate",
                                    reason_code="UNKNOWN_CATEGORY:" + ",".join(unknown), score=0))
            return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                              artifact_id=artifact.artifact_id, recommended=Decision.ERROR, findings=findings,
                              error="unsupported guard categories: " + ",".join(unknown),
                              duration_ms=(time.perf_counter() - t0) * 1000)
        if unsafe and not cats:
            findings.append(Finding(category="safety.unspecified", reason_code="LLAMA_GUARD_UNSAFE"))
        blocking = unsafe and (not cats or any(c in ctx.guard_policy.llama_guard_block_categories for c in cats))
        if not blocking:
            rec = Decision.ALLOW
        elif artifact.kind in (ArtifactKind.CHUNK, ArtifactKind.DOCUMENT):
            rec = Decision.QUARANTINE
        else:
            rec = Decision.BLOCK
        return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                          artifact_id=artifact.artifact_id, recommended=rec, findings=findings,
                          duration_ms=(time.perf_counter() - t0) * 1000)
