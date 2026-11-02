"""Rule-based Korean/English indirect-prompt-injection detector (separate from Llama Guard).

Score = sum over categories of the max rule weight hit in that category. Thresholds live in GuardPolicy.
These rules are a transparent baseline; their precision/recall is measured, not assumed.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from ..schemas import Artifact, ArtifactKind, Decision, EvidenceLocation, Finding, HookResult, HookStage, TrustLevel
from ..textproc import normalize, short_hash
from .base import InspectionContext

PLUGIN_VERSION = "ipi_rules/1.0"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    weight: float
    pattern: re.Pattern[str]


def _r(rule_id: str, cat: str, w: float, pat: str) -> Rule:
    return Rule(rule_id, cat, w, re.compile(pat, re.I | re.S))


RULES: list[Rule] = [
    # override / instruction hijack
    _r("KO_OVERRIDE_1", "ipi.override", 1.0, r"(이전|앞|위|기존)\s*(의|에\s*있는)?\s*(모든\s*)?(지시|지침|명령|규칙|안내)\s*(사항)?\s*(을|를|은|는|들을)?\s*(모두\s*|전부\s*)?(무시|잊|따르지\s*마)"),
    _r("KO_OVERRIDE_2", "ipi.override", 0.8, r"(지금부터|이제부터)\s*.{0,20}(새로운|다음)\s*(지시|명령|규칙)"),
    _r("EN_OVERRIDE_1", "ipi.override", 1.0, r"\b(ignore|disregard|forget|override)\b\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding|system)\s+(instructions?|rules?|directions?|prompts?|guidelines?)"),
    _r("EN_OVERRIDE_2", "ipi.override", 0.8, r"\bnew\s+(instructions?|task)\s*[:：]"),
    _r("XX_OVERRIDE_TAG", "ipi.override", 1.0, r"SYSTEM\s*OVERRIDE|ADMIN\s*MODE|DEVELOPER\s*MODE"),
    # role / system impersonation
    _r("KO_ROLE_1", "ipi.role", 0.6, r"(당신|너)\s*(은|는)\s*이제|시스템\s*(관리자|프롬프트|메시지)\s*(로서|의\s*지시|입니다)?"),
    _r("EN_ROLE_1", "ipi.role", 0.6, r"\byou\s+are\s+now\b|\bact\s+as\b|\bsystem\s+prompt\b|^\s*#{2,}\s*system\b"),
    _r("XX_ROLE_TOKENS", "ipi.role", 0.8, r"<\|im_start\|>|<\|system\|>|\[INST\]|<<SYS>>|\[system\]"),
    # exfiltration / data movement
    _r("KO_EXFIL_1", "ipi.exfil", 0.8, r"(전송|보내|발송|업로드|전달)[^\n]{0,40}(mock-sink://|https?://|[\w.\-]+@[\w.\-]+\.\w+)"),
    _r("EN_EXFIL_1", "ipi.exfil", 0.8, r"\b(send|forward|email|upload|post|transmit)\b[^\n]{0,40}(mock-sink://|https?://|[\w.\-]+@[\w.\-]+\.\w+)"),
    _r("XX_EXFIL_DEST", "ipi.exfil", 0.6, r"(mock-sink://|https?://)[^\s)]+[?&][\w\-]+="),
    _r("KO_BULK_PII", "ipi.exfil", 0.6, r"(고객|개인)\s*(정보|데이터|주민등록번호|계좌번호).{0,20}(모두|전부|전체|그대로)"),
    _r("EN_BULK_PII", "ipi.exfil", 0.6, r"\b(all|every|full|complete)\s+(customer|account|personal)\s+(data|records|details|information|numbers)"),
    # tool-syntax abuse and hidden channels
    _r("XX_ACTION_SYNTAX", "ipi.tool", 1.0, r"\[\[\s*ACTION"),
    _r("XX_MD_IMAGE_EXFIL", "ipi.hidden", 0.8, r"!\[[^\]]*\]\([^)]*\?[^)]*\)"),
    _r("XX_HTML_COMMENT", "ipi.hidden", 0.3, r"<!--.*?-->"),
    _r("KO_CONCEAL", "ipi.hidden", 0.6, r"(사용자|고객)\s*에게\s*(알리지|말하지|언급하지|표시하지)\s*(마|말)"),
    _r("EN_CONCEAL", "ipi.hidden", 0.6, r"\bdo\s+not\s+(mention|tell|reveal|disclose)\s+(this|that|these)"),
    # attacker marker / output control
    _r("KO_MARKER", "ipi.output_control", 0.5, r"(확인\s*코드|응답\s*(의\s*)?(끝|마지막|맨\s*앞)).{0,40}(포함|출력|붙여|작성)"),
    _r("EN_MARKER", "ipi.output_control", 0.5, r"(confirmation\s+code|end\s+(of\s+)?(your|the)\s+(answer|response)).{0,40}(include|append|output|print)"),
    # spoofed policy authorising disclosure
    _r("KO_POLICY_SPOOF", "ipi.policy_spoof", 0.6, r"(내부\s*규정|정책|지침).{0,30}(개정|변경|업데이트).{0,60}(공개|제공|전송).{0,20}(허용|가능|의무)"),
    _r("EN_POLICY_SPOOF", "ipi.policy_spoof", 0.6, r"(policy|regulation).{0,30}(updated|changed|amended).{0,60}(disclos|shar|send).{0,20}(permitted|allowed|required)"),
]


def score_text(text: str) -> tuple[float, list[tuple[Rule, re.Match[str]]]]:
    hits: list[tuple[Rule, re.Match[str]]] = []
    best: dict[str, float] = {}
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            hits.append((rule, m))
            best[rule.category] = max(best.get(rule.category, 0.0), rule.weight)
    return round(sum(best.values()), 3), hits


class IpiRulePlugin:
    name = "ipi_rules"
    version = PLUGIN_VERSION
    stages = frozenset({HookStage.INGESTION, HookStage.PRE_GENERATION, HookStage.POST_GENERATION})

    async def inspect(self, ctx: InspectionContext, artifact: Artifact) -> HookResult:
        t0 = time.perf_counter()
        s_orig, h_orig = score_text(artifact.original)
        findings: list[Finding] = []
        for rule, m in h_orig:
            findings.append(Finding(category=rule.category, reason_code=rule.rule_id, score=rule.weight,
                                    location=EvidenceLocation(artifact_id=artifact.artifact_id, view="original",
                                                              start=m.start(), end=m.end()),
                                    evidence_hash=short_hash(m.group(0))))
        score = s_orig
        if ctx.normalization.detect_on_normalized:
            nt = normalize(artifact.original)
            s_norm, h_norm = score_text(nt.text)
            seen = {r.rule_id for r, _ in h_orig}
            for rule, m in h_norm:
                if rule.rule_id in seen:
                    continue
                s, e = nt.original_span(m.start(), m.end())
                findings.append(Finding(category=rule.category, reason_code=rule.rule_id, score=rule.weight,
                                        location=EvidenceLocation(artifact_id=artifact.artifact_id, view="original",
                                                                  start=s, end=e),
                                        evidence_hash=short_hash(m.group(0)), only_in_normalized=True))
            score = max(score, s_norm)
        # Trust-agnostic threshold here; the Enforcer lowers it for low-trust sources only when the
        # provenance signal is part of the active mode (keeps the two signals separable in ablations).
        rec = Decision.ALLOW
        if score >= ctx.guard_policy.ipi_block_threshold:
            if artifact.kind in (ArtifactKind.CHUNK, ArtifactKind.DOCUMENT):
                rec = Decision.QUARANTINE
            elif artifact.kind == ArtifactKind.ACTION:
                rec = Decision.BLOCK
            elif artifact.kind == ArtifactKind.RESPONSE:
                rec = Decision.REDACT  # echoed injection text in a response is masked, not the whole answer
            else:  # direct query injection is outside this study's IPI scope; flag only
                rec = Decision.ALLOW
        findings.append(Finding(category="ipi.score", reason_code="IPI_SCORE", score=score))
        return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                          artifact_id=artifact.artifact_id, recommended=rec, findings=findings,
                          duration_ms=(time.perf_counter() - t0) * 1000)


class ProvenancePlugin:
    """Emits source-trust findings; the Enforcer combines them with IPI findings (combination rule)."""
    name = "provenance"
    version = "provenance/1.0"
    stages = frozenset({HookStage.PRE_GENERATION})

    async def inspect(self, ctx: InspectionContext, artifact: Artifact) -> HookResult:
        t0 = time.perf_counter()
        findings = []
        if artifact.kind == ArtifactKind.CHUNK and artifact.trust in (TrustLevel.LOW, TrustLevel.UNTRUSTED):
            findings.append(Finding(category="provenance.low_trust", reason_code=f"TRUST_{artifact.trust.value.upper()}",
                                    score=1.0))
        return HookResult(plugin=self.name, plugin_version=self.version, stage=ctx.stage,
                          artifact_id=artifact.artifact_id, recommended=Decision.ALLOW, findings=findings,
                          duration_ms=(time.perf_counter() - t0) * 1000)
