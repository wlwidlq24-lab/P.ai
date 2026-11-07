"""W-01 민원 조사 인수인계 — investigation workflow (research-supported).

Scope comes from the team research (see docs/handoff/06_investigation_workflow.md for the source-to-code table):
the duty is a privacy-complaint INVESTIGATION whose result is a structured handover summary a successor uses to
continue the investigation. The flow is:

    investigation request -> authorized evidence retrieval -> structured findings (with citations) -> handover

Three artifacts are kept SEPARATE (never collapsed):
  * WORKFLOW CONFIG   — `InvestigationCase`: the duties/steps/result fields implementable now. Synthetic demo
                        content staged with the case; it is NOT a permission and NOT an evaluation label.
  * RUNTIME POLICY    — the access policy's disclosure_rules + per-click OpenEvidence authorization (unchanged).
  * EVALUATION ORACLE — scoring after execution (never read here; never authorizes retrieval/disclosure).

The structured findings distinguish CONFIRMED facts (확인 사실), items still being CHECKED (확인 중/미결), and
proposed NEXT actions (다음 조치). Customer identifiers withheld by policy are listed, not shown. Evidence links
are minted from the REAL retrieved source memo via the existing CreateHandoff, so every evidence click is
authorized live at OpenEvidence exactly as before.
"""
from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .errors import InvestigationCaseNotFoundError

INVESTIGATION_SCHEMA_VERSION = "investigation/1.0"
CASE_SCHEMA_VERSION = "investigation-case/1.0"

# SYNTHETIC DEMO POLICY (documented assumption): the research could not confirm which department investigates
# privacy complaints at a financial institution, and places the investigator under compliance as an experiment
# setting (업무 조사표 'W-01 직무 구분: ... 조사 부서를 준법감시로 둔 것은 실험용 설정'). We therefore let only the
# `compliance` role initiate an investigation here. This is a workflow-authority demo setting, SEPARATE from the
# disclosure runtime policy, and a real deployment must confirm it with Legal.
INVESTIGATOR_ROLES: tuple[str, ...] = ("compliance",)


class FactStatus(StrEnum):
    CONFIRMED = "confirmed"   # 확인 사실 — established during the investigation
    CHECKING = "checking"     # 확인 중 / 미결 — still being verified (an open question)


class FindingItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str                                   # synthetic statement (no raw customer identifiers)
    status: FactStatus
    evidence_label: str | None = None           # ties to an evidence link's server label (e.g. "E1") where supported


class NextAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    due: str | None = None                      # 기한 — ISO date or free text; None if open


class InvestigationCase(BaseModel):
    """WORKFLOW CONFIG for one staged synthetic investigation. Not a permission, not an oracle label."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["investigation-case/1.0"] = CASE_SCHEMA_VERSION
    case_id: str
    institution: str                            # fictional institution name
    subject_ref: str                            # synthetic subject token (NEVER a real identifier)
    issue: str                                  # 민원 쟁점
    status: str                                 # 처리 상태
    findings: list[FindingItem] = Field(default_factory=list)
    next_actions: list[NextAction] = Field(default_factory=list)
    withheld_categories: list[str] = Field(default_factory=list)  # 요약에서 제외/마스킹되는 범주
    evidence_query: str                         # query used to retrieve the source memo for evidence links
    source_document_id: str                     # the staged memo document id (provenance)


class InvestigationFindings(BaseModel):
    """API RESULT delivered to the UI: structured findings + recipient-facing evidence links."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["investigation/1.0"] = INVESTIGATION_SCHEMA_VERSION
    case_id: str
    institution: str
    requester: str
    recipient: str | None = None
    issue: str
    status: str
    confirmed_facts: list[FindingItem] = Field(default_factory=list)   # 확인 사실
    checking: list[FindingItem] = Field(default_factory=list)          # 확인 중 / 미결
    next_actions: list[NextAction] = Field(default_factory=list)       # 다음 조치 · 기한
    withheld_categories: list[str] = Field(default_factory=list)       # 정책상 요약에서 제외된 범주
    handover_id: str | None = None
    evidence_links: list[dict[str, Any]] = Field(default_factory=list)  # {label, evidence_id, url} — no metadata
    notes: list[str] = Field(default_factory=list)


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str                                # the requester (investigator) identity
    case_id: str
    recipient: str | None = None                # successor to hand the findings to (optional)
    create_handover: bool = True
    purpose: str = "handover"                   # API value preserved; UI shows a Korean label
    channel: str = "response"
    evidence_policy: Literal["original_only", "approved_excerpt"] = "approved_excerpt"


# --------------------------------------------------------------------------- use-case helpers (pure)
def may_investigate(role: str) -> bool:
    """Workflow authority (synthetic demo setting), separate from disclosure runtime policy."""
    return role in INVESTIGATOR_ROLES


def load_case(data_dir: Path, case_id: str) -> InvestigationCase:
    """Load a staged synthetic case by id. Rejects path traversal; raises 404 when absent."""
    safe = case_id.strip()
    if not safe or "/" in safe or "\\" in safe or safe.startswith(".") or ".." in safe:
        raise InvestigationCaseNotFoundError(f"invalid case_id {case_id!r}")
    base = (data_dir / "investigation_cases").resolve()
    p = (base / f"{safe}.json").resolve()
    if base not in p.parents or not p.exists():
        raise InvestigationCaseNotFoundError(f"investigation case {case_id!r} not found")
    return InvestigationCase.model_validate_json(p.read_text(encoding="utf-8"))


def assemble_findings(case: InvestigationCase, *, requester: str, recipient: str | None,
                      handover_id: str | None, evidence_links: list[dict[str, Any]],
                      notes: list[str] | None = None) -> InvestigationFindings:
    """Project the staged case into the API result, splitting confirmed vs still-checking findings."""
    confirmed = [f for f in case.findings if f.status == FactStatus.CONFIRMED]
    checking = [f for f in case.findings if f.status == FactStatus.CHECKING]
    return InvestigationFindings(
        case_id=case.case_id, institution=case.institution, requester=requester, recipient=recipient,
        issue=case.issue, status=case.status, confirmed_facts=confirmed, checking=checking,
        next_actions=list(case.next_actions), withheld_categories=list(case.withheld_categories),
        handover_id=handover_id, evidence_links=evidence_links, notes=notes or [])


def write_case(data_dir: Path, case: InvestigationCase) -> Path:
    """Stage a synthetic case for the demo (used by the seed script and tests)."""
    base = data_dir / "investigation_cases"
    base.mkdir(parents=True, exist_ok=True)
    p = base / f"{case.case_id}.json"
    p.write_text(case.model_dump_json(indent=2), encoding="utf-8", newline="")
    return p
