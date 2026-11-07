"""Legal disclosure-rule mapping + round-trip comparison.

Legal submits the MEANING of disclosure rules (role × recipient × purpose × channel, permitted info, window,
conditions, open questions) as a structured companion to docs/handoff/templates/disclosure_rule_submission.template.md.
Backend owns only the TRANSLATION into executable configuration (`RolePolicy.disclosure_rules`) and returns a
human-readable Korean comparison so Legal can confirm the meaning was preserved. Backend never invents a legal
conclusion, never auto-approves, and never activates a policy from here (candidate output is written to a
separate path and labelled unapproved).

Four things are kept strictly separate (never collapsed into the runtime rule):
  * runtime policy  — DisclosureRule: decides whether an UNMASKED disclosure may proceed at runtime,
  * evaluation oracle — DisclosureOracle: scores the observed result (never touched here),
  * task_required   — information needed for the task (necessity is NOT a legal basis),
  * legal_obligation — a separately supported statutory duty.
CONDITIONAL and UNRESOLVED stay distinct. If the runtime schema cannot express a decision/condition/representation
exactly, it is reported as UNSUPPORTED against the affected rule — never silently dropped, broadened, or coerced
into ALLOW/DENY.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .disclosure import SUPPORTED_PREDICATES, evaluate_disclosure
from .readiness import PolicyMappingSummary
from .schemas import DisclosureRule, PiiGrade, PiiType, RolePolicy

_PII_VALUES = {p.value for p in PiiType}
_FORMS = ("original", "masked", "summarized", "omitted")
_DECISIONS = ("ALLOW", "DENY", "CONDITIONAL", "UNRESOLVED")


# --------------------------------------------------------------------------- structured companion input
class RuleRow(BaseModel):
    """One submitted judgement = one (role × recipient × purpose × channel). Mirrors the Markdown template §1.
    Legal fills meaning/grounds/conditions/open-questions; Backend maps the runtime-expressible subset."""
    model_config = ConfigDict(extra="forbid")
    rule_id: str                                   # source rule id (stable, cited back in the report)
    version: str = "1"                             # source rule version
    description: str = ""
    role: str
    recipient: str | None = None
    purpose: str | None = None
    channel: str | None = None
    allowed_pii_types: list[str] = Field(default_factory=list)
    validity_from: datetime | None = None
    validity_to: datetime | None = None
    conditions: list[str] = Field(default_factory=list)
    decision: Literal["ALLOW", "DENY", "CONDITIONAL", "UNRESOLVED"]
    permitted_form: Literal["original", "masked", "summarized", "omitted"] = "original"
    legal_ground: str = ""                         # Legal's cited basis + factual premise (metadata only)
    task_required: bool = False                    # necessity (orthogonal; NOT a legal basis)
    legal_obligation: bool = False                 # statutory duty (orthogonal; distinct from task_required)
    unresolved_note: str = ""                      # open legal question (for UNRESOLVED)


class RuleSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    submission_id: str
    source: str = ""                               # provenance: who submitted / when / which template version
    policy_mode: Literal["role_fallback", "strict_rules"] = "strict_rules"
    rows: list[RuleRow] = Field(default_factory=list)


def load_submission(path: Path) -> RuleSubmission:
    raw = path.read_bytes()
    data = yaml.safe_load(raw) if path.suffix in (".yaml", ".yml") else json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name}: top level must be a mapping")
    return RuleSubmission.model_validate(data)


# --------------------------------------------------------------------------- mapping result
@dataclass
class MappedRule:
    rule_id: str
    version: str
    role: str
    expression: str                 # grant | deny_by_omission | held_unresolved | unsupported_representation
    emitted: DisclosureRule | None
    mismatches: list[str] = field(default_factory=list)   # real mapping problems (semantic)
    separated: list[str] = field(default_factory=list)    # fields intentionally NOT runtime-mapped (by design)
    roundtrip: list[str] = field(default_factory=list)    # schema round-trip diffs (ideally empty)


@dataclass
class Scenario:
    name: str
    expected: str
    observed: str
    detail: str

    @property
    def ok(self) -> bool:
        return self.expected == self.observed


@dataclass
class RuleMappingResult:
    submission_id: str
    policy_mode: str
    rules: list[MappedRule]
    scenarios: dict[str, list[Scenario]]

    # ---- summaries
    def policy_mapping_summary(self) -> PolicyMappingSummary:
        supported = sum(1 for r in self.rules if r.expression == "grant" and not r.mismatches)
        mism = [f"{r.rule_id}: {'; '.join(r.mismatches)}" for r in self.rules if r.mismatches]
        unresolved = [r.rule_id for r in self.rules if r.expression == "held_unresolved"]
        return PolicyMappingSummary(supported_rules=supported, semantic_mismatches=mism, unresolved_rules=unresolved)

    @property
    def behavior_ok(self) -> bool:
        return all(s.ok for lst in self.scenarios.values() for s in lst)

    def rules_by_role(self) -> dict[str, list[DisclosureRule]]:
        out: dict[str, list[DisclosureRule]] = {}
        for r in self.rules:
            if r.emitted is not None:
                out.setdefault(r.role, []).append(r.emitted)
        return out

    def candidate_yaml(self) -> str:
        """A candidate fragment for access_policy.yaml, keyed by role. LABELLED UNAPPROVED. Never activated."""
        body = {role: [rule.model_dump(mode="json", exclude_none=True) for rule in rules]
                for role, rules in self.rules_by_role().items()}
        header = ("# UNAPPROVED candidate — generated from a Legal rule submission. Do NOT activate.\n"
                  "# Backend mapping of MEANING -> RolePolicy.disclosure_rules; Legal must confirm the comparison\n"
                  "# report, and a human must approve before this is merged into an access policy.\n"
                  f"# submission_id: {self.submission_id}\n")
        return header + yaml.safe_dump({"disclosure_rules_by_role": body}, allow_unicode=True, sort_keys=True)

    def to_json(self) -> dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "policy_mode": self.policy_mode,
            "behavior_ok": self.behavior_ok,
            "policy_mapping": self.policy_mapping_summary().model_dump(),
            "rules": [
                {"rule_id": r.rule_id, "version": r.version, "role": r.role, "expression": r.expression,
                 "emitted": r.emitted.model_dump(mode="json", exclude_none=True) if r.emitted else None,
                 "mismatches": r.mismatches, "separated": r.separated, "roundtrip_diffs": r.roundtrip,
                 "scenarios": [{"name": s.name, "expected": s.expected, "observed": s.observed,
                                "ok": s.ok, "detail": s.detail} for s in self.scenarios.get(r.rule_id, [])]}
                for r in self.rules],
        }

    def to_report_md(self) -> str:
        """Human-readable Korean comparison for Legal (meaning preservation, not code review)."""
        lines = [f"# 공개 규칙 매핑 대조표 (제출 {self.submission_id})", "",
                 f"- 집행 모드: `{self.policy_mode}`  ·  행동 검증: "
                 f"{'모두 일치 ✅' if self.behavior_ok else '불일치 있음 ⚠️ (아래 표 확인)'}",
                 "- Backend는 **의미 보존**만 되돌려 드립니다. 미지원 항목은 숨기지 않고 '차이'에 명시합니다.", ""]
        for r in self.rules:
            lines.append(f"## 규칙 {r.rule_id} (v{r.version}) — {r.role}")
            intent = {"ALLOW": "허용", "DENY": "거부", "CONDITIONAL": "조건부", "UNRESOLVED": "미결(보류)"}
            exprs = {"grant": "런타임 허용 규칙으로 매핑", "deny_by_omission": "규칙 미발급(= 거부로 집행)",
                     "held_unresolved": "규칙 미발급(미결 → 보류)",
                     "unsupported_representation": "표현형 미지원 — 허용 규칙 발급 안 함"}
            lines.append(f"| 항목 | 내용 |")
            lines.append(f"|---|---|")
            lines.append(f"| 규칙 | {r.rule_id} v{r.version} · {r.role} |")
            lines.append(f"| 런타임 매핑 | {exprs.get(r.expression, r.expression)} |")
            if r.emitted is not None:
                e = r.emitted
                win = (f"{e.effective_from.date() if e.effective_from else '∞'}~"
                       f"{e.effective_to.date() if e.effective_to else '∞'}")
                lines.append(f"| 생성된 설정 | recipient={e.recipient} · purpose={e.purpose} · channel={e.channel} · "
                             f"유형={[p.value for p in e.allowed_pii_types]} · 창={win} · "
                             f"조건={e.conditional_predicates or '없음'} |")
            scen = self.scenarios.get(r.rule_id, [])
            obs = "; ".join(f"{s.name}:{s.observed}{'' if s.ok else ' (예상 '+s.expected+')'}" for s in scen)
            lines.append(f"| 집행 결과 | {obs or '(해당 없음)'} |")
            diffs = []
            if r.mismatches:
                diffs.append("미지원: " + "; ".join(r.mismatches))
            if r.separated:
                diffs.append("런타임 밖(설계상 분리): " + "; ".join(r.separated))
            if r.roundtrip:
                diffs.append("왕복 차이: " + "; ".join(r.roundtrip))
            lines.append(f"| 차이 | {' / '.join(diffs) if diffs else '없음'} |")
            status = ("Legal 확인 요청" if not r.mismatches and all(s.ok for s in scen)
                      else "수정 필요" if r.mismatches else "미결 — 법률 판단 필요")
            lines.append(f"| 검토 상태 | {status} · ☐ Legal 확인 |")
            lines.append("")
        return "\n".join(lines)


# --------------------------------------------------------------------------- mapping + verification
def _emit_rule(row: RuleRow) -> tuple[DisclosureRule | None, str, list[str], list[str]]:
    mismatches: list[str] = []
    separated: list[str] = []
    # representation separation: the runtime rule only governs UNMASKED disclosure of a TYPE. masked/summarized
    # are a different mechanism and must NOT be coerced into an unmasked ALLOW.
    valid_types = [t for t in row.allowed_pii_types if t in _PII_VALUES]
    for t in row.allowed_pii_types:
        if t not in _PII_VALUES:
            mismatches.append(f"unknown_pii_type:{t}")
    # record intentionally-separated, non-runtime fields (by design; not defects)
    if row.legal_ground:
        separated.append("legal_ground(근거: 오라클/문서화 전용)")
    if row.task_required:
        separated.append("task_required(필요성 — 법적 근거 아님)")
    if row.legal_obligation:
        separated.append("legal_obligation(법정 의무 — 별도 집행 아님)")

    if row.decision == "DENY" or row.permitted_form == "omitted":
        if row.permitted_form == "omitted" and row.decision in ("ALLOW", "CONDITIONAL"):
            separated.append("permitted_form=omitted(= 비공개로 집행)")
        return None, "deny_by_omission", mismatches, separated
    if row.decision == "UNRESOLVED":
        return None, "held_unresolved", mismatches, separated
    if row.permitted_form in ("masked", "summarized"):
        # ALLOW/CONDITIONAL intended, but the requested representation is not expressible: DO NOT emit a grant
        # (that would broaden to an unmasked ALLOW). Report as unsupported against this rule.
        mismatches.append(f"representation_unsupported:{row.permitted_form}")
        return None, "unsupported_representation", mismatches, separated
    if not valid_types:
        mismatches.append("no_runtime_expressible_pii_types")
        return None, "unsupported_representation", mismatches, separated
    for pid in row.conditions:
        if pid not in SUPPORTED_PREDICATES:
            mismatches.append(f"unsupported_predicate:{pid} (런타임 HOLD)")
    rule = DisclosureRule(recipient=row.recipient, purpose=row.purpose, channel=row.channel,
                          allowed_pii_types=[PiiType(t) for t in valid_types],
                          effective_from=row.validity_from, effective_to=row.validity_to,
                          conditional_predicates=list(row.conditions))
    return rule, "grant", mismatches, separated


def _roundtrip(rule: DisclosureRule) -> list[str]:
    """Parse the generated YAML with the SAME model the app uses; report semantic diffs (empty => identical)."""
    d1 = rule.model_dump(mode="json")
    y = yaml.safe_dump(d1, allow_unicode=True, sort_keys=True)
    back = DisclosureRule.model_validate(yaml.safe_load(y))
    d2 = back.model_dump(mode="json")
    diffs: list[str] = []
    for k in sorted(set(d1) | set(d2)):
        if d1.get(k) != d2.get(k):
            diffs.append(f"{k}: {d1.get(k)!r} -> {d2.get(k)!r}")
    return diffs


def _mid(lo: datetime | None, hi: datetime | None) -> datetime:
    a = lo or datetime(2000, 1, 1, tzinfo=timezone.utc)
    b = hi or datetime(2100, 1, 1, tzinfo=timezone.utc)
    return a + (b - a) / 2


def _role_policy(role: str, result_rules: list[MappedRule]) -> RolePolicy:
    rules = [r.emitted for r in result_rules if r.role == role and r.emitted is not None]
    disclosable = sorted({p for r in rules for p in r.allowed_pii_types}, key=lambda p: p.value)
    return RolePolicy(description=f"candidate:{role}", max_pii_grade=PiiGrade.UNIQUE_ID,
                      disclosable_pii_types=disclosable, allowed_action_destinations=["internal://case-system"],
                      allowed_purposes=[], disclosure_rules=rules)


def _scenarios_for(row: RuleRow, mapped: MappedRule, policy: RolePolicy, mode: str) -> list[Scenario]:
    """Behavioral check with EXPLICIT expected outcomes against synthetic contexts."""
    t = next((t for t in row.allowed_pii_types if t in _PII_VALUES), None)
    if t is None:
        return []
    supported_conditions = all(c in SUPPORTED_PREDICATES for c in row.conditions)
    verified = {c for c in row.conditions if c in SUPPORTED_PREDICATES}

    def run(as_of, recipient, verified_set):
        return evaluate_disclosure({t}, role_policy=policy, recipient=recipient, purpose=row.purpose,
                                   channel=row.channel, as_of=as_of, verified_predicates=verified_set,
                                   mode=mode).decision

    out: list[Scenario] = []
    # expected outcome of the row's OWN context under a valid window
    if mapped.expression == "grant":
        exp_valid = "ALLOW" if (row.decision == "ALLOW" or (row.decision == "CONDITIONAL" and supported_conditions)) else "HOLD"
    elif mapped.expression == "held_unresolved":
        exp_valid = "HOLD" if mode == "strict_rules" else "DENY"   # UNRESOLVED must never be ALLOW
    else:  # deny_by_omission / unsupported_representation -> no grant for this (recipient,type)
        exp_valid = "HOLD" if mode == "strict_rules" else "DENY"
    out.append(Scenario("valid_window", exp_valid, run(_mid(row.validity_from, row.validity_to), row.recipient, verified),
                        "유효 창·해당 수신자·조건 충족 가정"))

    # expired window (only meaningful when a grant with an end date exists)
    if mapped.expression == "grant" and row.validity_to is not None:
        out.append(Scenario("expired_window", "DENY", run(row.validity_to, row.recipient, verified),
                            "as_of = validity_to (만료 경계)"))
    # conditional with NO server evidence -> HOLD
    if mapped.expression == "grant" and verified:
        out.append(Scenario("missing_evidence", "HOLD",
                            run(_mid(row.validity_from, row.validity_to), row.recipient, set()),
                            "조건부인데 서버측 증거 없음"))
    # mismatched recipient -> not covered
    exp_mis = "HOLD" if mode == "strict_rules" else "DENY"
    out.append(Scenario("mismatched_context", exp_mis,
                        run(_mid(row.validity_from, row.validity_to), "__other_recipient__", verified),
                        "다른 수신자(미커버)"))
    return out


def map_submission(sub: RuleSubmission) -> RuleMappingResult:
    mapped: list[MappedRule] = []
    for row in sub.rows:
        emitted, expression, mism, sep = _emit_rule(row)
        mr = MappedRule(rule_id=row.rule_id, version=row.version, role=row.role, expression=expression,
                        emitted=emitted, mismatches=mism, separated=sep,
                        roundtrip=_roundtrip(emitted) if emitted is not None else [])
        mapped.append(mr)
    # behavioral comparison uses the COMBINED per-role policy (overlapping rules interact)
    policies = {role: _role_policy(role, mapped) for role in {m.role for m in mapped}}
    scenarios: dict[str, list[Scenario]] = {}
    for row, mr in zip(sub.rows, mapped):
        scenarios[row.rule_id] = _scenarios_for(row, mr, policies[row.role], sub.policy_mode)
    return RuleMappingResult(submission_id=sub.submission_id, policy_mode=sub.policy_mode,
                             rules=mapped, scenarios=scenarios)


def write_outputs(result: RuleMappingResult, out_dir: Path) -> dict[str, Path]:
    """Write the three deliverables to a SEPARATE directory, labelled unapproved. Never touches active policy."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cand = out_dir / f"{result.submission_id}.candidate.yaml"
    rep = out_dir / f"{result.submission_id}.report.ko.md"
    js = out_dir / f"{result.submission_id}.result.json"
    cand.write_text(result.candidate_yaml(), encoding="utf-8")
    rep.write_text(result.to_report_md(), encoding="utf-8")
    js.write_text(json.dumps(result.to_json(), ensure_ascii=False, indent=2), encoding="utf-8")
    return {"candidate_yaml": cand, "report_md": rep, "result_json": js}
