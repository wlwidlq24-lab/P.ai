"""Korean financial PII regex detector and the REGEX PII plugin.

Precision/recall of these patterns is an experimental quantity, not an assumption. Names and addresses are
not regex-detected (low precision); they rely on declared metadata. Checksums are NOT required so that
synthetic, checksum-invalid canaries are still detected (the detector models format-level detection).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from ..schemas import Artifact, Decision, EvidenceLocation, Finding, HookResult, HookStage, PiiType
from ..textproc import NormalizedText, normalize, short_hash
from .base import InspectionContext

PLUGIN_VERSION = "pii_regex/1.0"

# Order = priority when spans overlap (earlier wins).
_PATTERNS: list[tuple[PiiType, re.Pattern[str]]] = [
    (PiiType.RRN, re.compile(r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\s?[-–]?\s?[1-4]\d{6}(?!\d)")),
    (PiiType.FOREIGNER_RRN, re.compile(r"(?<!\d)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\s?[-–]?\s?[5-8]\d{6}(?!\d)")),
    (PiiType.DRIVER_LICENSE, re.compile(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)")),
    (PiiType.CARD_NUMBER, re.compile(r"(?<!\d)(?:\d{4}[-\s]){3}\d{4}(?!\d)")),
    (PiiType.PHONE, re.compile(r"(?<!\d)(?:01[016789]|02|0[3-6][1-5])[-\s.]?\d{3,4}[-\s.]?\d{4}(?!\d)")),
    (PiiType.ACCOUNT_NUMBER, re.compile(r"(?<!\d)\d{3,6}-\d{2,6}-\d{2,7}(?:-\d{1,3})?(?!\d)")),
    (PiiType.ACCOUNT_NUMBER, re.compile(r"(?:계좌(?:번호)?|account(?:\s*(?:no\.?|number))?)\s*[:：]?\s*(\d{10,14})(?!\d)", re.I)),
    (PiiType.PASSPORT, re.compile(r"(?<![A-Z0-9])[MSRODG](?:\d{8}|\d{3}[A-Z]\d{4})(?![A-Z0-9])")),
    (PiiType.EMAIL, re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    (PiiType.CREDIT_INFO, re.compile(r"(?:신용\s*(?:점수|등급)|credit\s*score)\s*[:：]?\s*\d{1,4}", re.I)),
]


@dataclass(frozen=True)
class PiiMatch:
    pii_type: PiiType
    start: int
    end: int
    value: str


def detect_pii(text: str) -> list[PiiMatch]:
    found: list[PiiMatch] = []
    taken: list[tuple[int, int]] = []
    for ptype, pat in _PATTERNS:
        for m in pat.finditer(text):
            s, e = (m.start(1), m.end(1)) if m.groups() else (m.start(), m.end())
            if any(s < te and ts < e for ts, te in taken):
                continue
            taken.append((s, e))
            found.append(PiiMatch(ptype, s, e, text[s:e]))
    return sorted(found, key=lambda x: x.start)


def canonical(value: str, pii_type: PiiType | str) -> str:
    t = PiiType(pii_type)
    if t == PiiType.EMAIL:
        return value.strip().lower()
    if t == PiiType.PASSPORT:
        return re.sub(r"\s", "", value).upper()
    return re.sub(r"\D", "", value)


def scan_views(artifact: Artifact, use_normalized: bool) -> list[tuple[PiiMatch, EvidenceLocation, bool]]:
    """Detect on the original view and (optionally) the normalized view, mapping spans to the original."""
    out: list[tuple[PiiMatch, EvidenceLocation, bool]] = []
    orig = detect_pii(artifact.original)
    for m in orig:
        out.append((m, EvidenceLocation(artifact_id=artifact.artifact_id, view="original", start=m.start, end=m.end), False))
    if use_normalized:
        nt: NormalizedText = normalize(artifact.original)
        for m in detect_pii(nt.text):
            s, e = nt.original_span(m.start, m.end)
            if any(s < o.end and o.start < e for o in orig):
                continue
            out.append((m, EvidenceLocation(artifact_id=artifact.artifact_id, view="original", start=s, end=e), True))
    return out


class PiiRegexPlugin:
    name = "pii_regex"
    version = PLUGIN_VERSION
    stages = frozenset(HookStage)

    async def inspect(self, ctx: InspectionContext, artifact: Artifact) -> HookResult:
        t0 = time.perf_counter()
        hits = scan_views(artifact, ctx.normalization.detect_on_normalized)
        disclosable = set(ctx.role_policy.disclosable_pii_types) if ctx.role_policy else set()
        findings: list[Finding] = []
        redact = False
        for m, loc, only_norm in hits:
            non_disclosable = m.pii_type not in disclosable
            # INGESTION: detection only. PRE/POST: recommend redaction of PII this role may not receive.
            act = ctx.stage != HookStage.INGESTION and non_disclosable and ctx.guard_policy.pii_redact_non_disclosable
            if artifact.kind.value == "query":
                act = False  # the user's own query is not redacted
            redact = redact or act
            findings.append(Finding(category=f"pii.{m.pii_type.value}",
                                    reason_code="PII_NON_DISCLOSABLE" if non_disclosable else "PII_DISCLOSABLE",
                                    location=loc, evidence_hash=short_hash(m.value), only_in_normalized=only_norm,
                                    score=1.0 if act else 0.0))
        return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                          artifact_id=artifact.artifact_id,
                          recommended=Decision.REDACT if redact else Decision.ALLOW, findings=findings,
                          duration_ms=(time.perf_counter() - t0) * 1000)


class ContextLeakPlugin:
    """POST_GENERATION: flags output that reproduces non-disclosable PII values present in the context.

    Matching is on canonical forms (digits only), so formatting changes (spaces, full-width digits after
    normalization, removed hyphens) are still caught. Values are derived from regex detection on context.
    """
    name = "context_leak"
    version = "context_leak/1.0"
    stages = frozenset({HookStage.POST_GENERATION})

    async def inspect(self, ctx: InspectionContext, artifact: Artifact) -> HookResult:
        t0 = time.perf_counter()
        disclosable = {p.value for p in (ctx.role_policy.disclosable_pii_types if ctx.role_policy else [])}
        protected = {v: t for v, t in ctx.context_pii_values.items() if t not in disclosable and len(v) >= 6}
        findings: list[Finding] = []
        nt = normalize(artifact.original)
        digits_only = re.sub(r"\D", "", nt.text)
        lowered = nt.text.lower()
        for val, ptype in protected.items():
            hit = (val in lowered) if ptype == PiiType.EMAIL.value else (val.isdigit() and val in digits_only)
            if hit:
                findings.append(Finding(category="leak.context_pii", reason_code=f"LEAK_{ptype.upper()}",
                                        evidence_hash=short_hash(val)))
        # Spans for masking come from regex hits on this artifact that canonicalise to a protected value.
        for m, loc, only_norm in scan_views(artifact, True):
            if canonical(m.value, m.pii_type) in protected:
                findings.append(Finding(category="leak.context_pii", reason_code="LEAK_SPAN", location=loc,
                                        evidence_hash=short_hash(m.value), only_in_normalized=only_norm))
        if not findings:
            rec = Decision.ALLOW
        else:
            rec = Decision.BLOCK if ctx.guard_policy.canary_post_action == "BLOCK" else Decision.REDACT
            # A leak without a maskable span (e.g. digits split by words) cannot be redacted safely -> block.
            if rec == Decision.REDACT and not any(f.location for f in findings):
                rec = Decision.BLOCK
        return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                          artifact_id=artifact.artifact_id, recommended=rec, findings=findings,
                          duration_ms=(time.perf_counter() - t0) * 1000)
