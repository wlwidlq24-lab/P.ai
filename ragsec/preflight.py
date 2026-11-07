"""Read-only readiness preflight around the EXISTING freeze logic (no second freeze implementation).

It validates inputs and returns a ReadinessReport WITHOUT activating an index, writing an approved .frozen.json,
running model inference, or starting an experiment. It reuses the real dataset loader, case selection, review
checks and `compute_freeze` (called with require_reviewed=False only to compute a CANDIDATE digest — never to
approve). Gates G1–G6 are reported individually, so (for example) G3 can PASS while G1/G2 are BLOCKED.

`compute_freeze`/`verify_freeze` side-effect audit: both only READ files (dataset manifest+cases+documents, the
active policy dir) and compute hashes; neither writes, activates an index, nor runs inference. This harness adds
no writes of its own. The only outputs are the returned report and whatever the CLI chooses to print.

Efficacy execution stays on HOLD: a READY report is NOT an authorization. `execution_allowed` is always False.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import Settings
from .errors import DatasetError, RagSecError
from .experiments import (
    Dataset, conditions, load_dataset, manifest_hash, plan, resolve_dataset_dir, select_cases,
)
from .pilot import compute_freeze, verify_freeze
from .readiness import (
    EfficacyStatus, ExecutionAccounting, FreezeStatus, GateResult, GateStatus, MatchState, PolicyMappingSummary,
    ReadinessReport, ReadinessStatus, ReasonCode, RequiredInput, ReviewState,
)
from .schemas import CaseType, ExperimentManifest
from .textproc import sha256_text

PLACEHOLDER = "[IPI_PAYLOAD_PLACEHOLDER]"

# Artifact classes a pilot freeze should ideally pin, checked against what compute_freeze actually covers.
_COVERAGE_EXPECTED = ("reviewed_submission_files", "attack_payload_bytes", "control_document_bytes",
                      "runtime_policy", "evaluation_oracle", "prompt_text", "model_digest", "index_version")


def _gate(gid: str, title: str, status: GateStatus, codes=None, msg="") -> GateResult:
    return GateResult(gate_id=gid, title=title, status=status, reason_codes=list(codes or []), message=msg)


def _coverage_gaps(m: ExperimentManifest, frozen: dict[str, Any], ds: Dataset) -> list[str]:
    """What the current freeze does NOT pin (reported as gaps, not silently assumed covered)."""
    gaps: list[str] = []
    # reviewed Legal submission files are a CANDIDATE artifact, not the active policy -> not in the freeze
    gaps.append("reviewed_submission_files: 프리즈는 활성 정책 해시만 고정(제출 원본 파일 비포함)")
    # control documents: only attack_document_ids are hashed; a control case's own documents are not, unless listed
    selected_ids = set(frozen.get("selected_case_ids", []))
    hashed_docs = set(frozen.get("attack_document_hashes", {}))
    ctrl_doc_ids: set[str] = set()
    for c in ds.cases:
        if c.case_id in selected_ids:
            ctrl_doc_ids |= set(c.ground_truth.attack_document_ids)
    if not (ctrl_doc_ids <= hashed_docs):
        gaps.append("control_document_bytes: 선택 케이스 문서 중 일부 미해시 가능")
    # prompt: only a version string is pinned, not the full template text
    gaps.append("prompt_text: 템플릿 버전만 고정(전문 바이트 비고정)")
    # model identity/digest is NOT in the freeze (settings_fingerprint carries NAMES, not digests)
    gaps.append("model_digest: 타깃 모델 digest 미고정(런타임 provenance에만 기록)")
    # the freeze pins the DATASET, not the active index version used at run time
    gaps.append("index_version: 실행 시 활성 인덱스 버전은 프리즈가 고정하지 않음")
    return gaps


def _candidate_digest(frozen: dict[str, Any]) -> str:
    stable = {k: v for k, v in frozen.items() if k != "frozen_at"}
    return sha256_text(json.dumps(stable, sort_keys=True, ensure_ascii=False))[:16]


def run_preflight(settings: Settings, m: ExperimentManifest, *, rule_mapping_result: dict | None = None,
                  approved_freeze: dict | None = None) -> ReadinessReport:
    report = ReadinessReport(manifest_id=m.experiment_id, readiness_status=ReadinessStatus.BLOCKED)
    inputs: list[RequiredInput] = []

    # ---- load dataset once (read-only); G3 depends on this and so do later gates
    ds: Dataset | None = None
    ds_error: str | None = None
    try:
        root = resolve_dataset_dir(settings, m.dataset_dir)
        ds = load_dataset(root, verify_hash=True)
    except RagSecError as e:
        ds_error = f"{e.code}: {e.message}"

    selected = select_cases(ds, m) if ds is not None else []
    selected_ids = {c.case_id for c in selected}
    attacks = [c for c in selected if c.case_type == CaseType.ATTACK]

    # ===================================================================== G1 Policy and evaluation
    pm_summary: PolicyMappingSummary | None = None
    if rule_mapping_result is None:
        inputs.append(RequiredInput(input_id="legal_disclosure_rules", owner="Legal/Privacy (Role 1)",
                                    review_state=ReviewState.MISSING, review_match=MatchState.ABSENT,
                                    note="검토된 공개 규칙 매핑 결과(rule-map 산출물) 미제출"))
        report.gates.append(_gate("G1", "Policy and evaluation", GateStatus.BLOCKED, [ReasonCode.MISSING_INPUT],
                                  "Legal 공개 규칙 매핑 결과가 없습니다. `ragsec rule-map`을 먼저 실행해 결과를 전달하세요."))
    else:
        pm = rule_mapping_result.get("policy_mapping", {})
        pm_summary = PolicyMappingSummary(**pm) if pm else PolicyMappingSummary()
        behavior_ok = bool(rule_mapping_result.get("behavior_ok", False))
        codes: list[ReasonCode] = []
        if pm_summary.semantic_mismatches or not behavior_ok:
            codes.append(ReasonCode.POLICY_MAPPING_MISMATCH)
        if pm_summary.unresolved_rules:
            codes.append(ReasonCode.UNRESOLVED_DECISION)
        status = GateStatus.PASS if not codes else GateStatus.BLOCKED
        inputs.append(RequiredInput(
            input_id="legal_disclosure_rules", owner="Legal/Privacy (Role 1)",
            review_state=ReviewState.REVIEWED if status == GateStatus.PASS else ReviewState.UNREVIEWED,
            artifact_version=str(rule_mapping_result.get("submission_id")),
            review_match=MatchState.UNKNOWN,
            note=f"지원 규칙 {pm_summary.supported_rules} · 미지원 {len(pm_summary.semantic_mismatches)} · "
                 f"미결 {len(pm_summary.unresolved_rules)}"))
        report.gates.append(_gate("G1", "Policy and evaluation", status, codes,
                                  "매핑 의미/행동 일치" if status == GateStatus.PASS
                                  else "미지원 매핑 또는 미결/행동 불일치가 있습니다(대조표 확인)."))
    report.policy_mapping = pm_summary

    # ===================================================================== G2 Human review
    if ds is None:
        report.gates.append(_gate("G2", "Human review", GateStatus.BLOCKED, [ReasonCode.DATASET_INTEGRITY],
                                  "데이터셋을 로드할 수 없어 리뷰를 확인할 수 없습니다(G3 참조)."))
        inputs.append(RequiredInput(input_id="security_cases_d14", owner="Security/Guardrails (Role 3)",
                                    review_state=ReviewState.MISSING, review_match=MatchState.UNKNOWN))
    else:
        doc_text = {}
        for meta, p in ds.documents:
            try:
                doc_text[meta.document_id] = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                doc_text[meta.document_id] = ""
        unreviewed, placeholders, ineligible = [], [], []
        for c in attacks:
            reviewed = c.review is not None and c.review.status == "reviewed" and c.review.reviewer and c.review.reviewed_at
            if not reviewed:
                unreviewed.append(c.case_id)
            if not (c.evaluation_eligible and c.attack_active):
                ineligible.append(c.case_id)
            if any(PLACEHOLDER in doc_text.get(d, "") for d in c.ground_truth.attack_document_ids):
                placeholders.append(c.case_id)
        codes, msgs = [], []
        if unreviewed:
            codes.append(ReasonCode.REVIEW_REQUIRED); msgs.append(f"미검토 공격 {len(unreviewed)}건")
        if placeholders:
            codes.append(ReasonCode.PLACEHOLDER_PAYLOAD); msgs.append(f"플레이스홀더 잔존 {len(placeholders)}건")
        if ineligible and not unreviewed:
            codes.append(ReasonCode.REVIEW_REQUIRED); msgs.append(f"비적격/비활성 공격 {len(ineligible)}건")
        status = GateStatus.PASS if not codes else GateStatus.BLOCKED
        state = ReviewState.REVIEWED if (attacks and not codes) else (
            ReviewState.MISSING if not attacks else ReviewState.UNREVIEWED)
        inputs.append(RequiredInput(
            input_id="security_cases_d14", owner="Security/Guardrails (Role 3)", review_state=state,
            artifact_version=frozen_prefix(ds), review_match=MatchState.MATCH if status == GateStatus.PASS else MatchState.MISMATCH,
            note=f"선택 공격 {len(attacks)}건 · " + ("모두 검토/적격" if not codes else "; ".join(msgs))))
        report.gates.append(_gate("G2", "Human review", status, codes,
                                  "선택된 모든 공격 케이스가 정확한 버전으로 사람 검토됨" if status == GateStatus.PASS
                                  else "사람 검토/적격성 증거가 부족합니다: " + "; ".join(msgs)))

    # ===================================================================== G3 Data integrity
    if ds is None:
        report.gates.append(_gate("G3", "Data integrity", GateStatus.FAIL, [ReasonCode.DATASET_INTEGRITY],
                                  f"데이터셋 로드 실패: {ds_error}"))
    else:
        problems: list[str] = []
        doc_ids = {meta.document_id for meta, _ in ds.documents}
        case_ids_all = {c.case_id for c in ds.cases}
        for c in selected:
            if c.control_case_id and c.control_case_id not in case_ids_all:
                problems.append(f"{c.case_id}: control {c.control_case_id} 없음")
            for d in c.ground_truth.attack_document_ids:
                if d not in doc_ids:
                    problems.append(f"{c.case_id}: 문서 {d} 없음")
        if not selected:
            problems.append("manifest가 선택하는 케이스가 없음")
        status = GateStatus.PASS if not problems else GateStatus.FAIL
        report.gates.append(_gate("G3", "Data integrity", status,
                                  [] if not problems else [ReasonCode.DATASET_INTEGRITY],
                                  "스키마·해시·계보·분할·참조 정합성 확인" if not problems
                                  else "; ".join(problems[:8])))

    # ===================================================================== G4 Experiment settings
    planned = len(plan(m, selected)) if ds is not None and selected else 0
    n_conditions = len(conditions(m))
    budgets_unset = m.max_requests is None and m.max_errors is None and m.max_run_seconds is None
    g4_codes = [ReasonCode.UNRESOLVED_BUDGET] if budgets_unset else []
    g4_status = GateStatus.BLOCKED if budgets_unset else GateStatus.PASS
    report.gates.append(_gate("G4", "Experiment settings", g4_status, g4_codes,
                              f"케이스 {len(selected)} · 조건 {n_conditions} · 반복 {m.repetitions} · "
                              f"enforcement={m.enforcement_profile} · 계획요청 {planned}" +
                              ("" if not budgets_unset else " · 예산(max_requests/errors/run_seconds) 미설정")))
    report.execution_accounting = ExecutionAccounting(planned_requests=planned or None)

    # ===================================================================== G5 Freeze preparation
    freeze_status = FreezeStatus()
    try:
        candidate = compute_freeze(settings, m, require_reviewed=False)  # CANDIDATE only; never approves
        freeze_status.candidate_digest = _candidate_digest(candidate)
        freeze_status.coverage_gaps = _coverage_gaps(m, candidate, ds) if ds is not None else []
        report.gates.append(_gate("G5", "Freeze preparation", GateStatus.PASS, [],
                                  f"정확한 아티팩트로 후보 프리즈 계산 가능(digest {freeze_status.candidate_digest}). "
                                  f"커버리지 공백 {len(freeze_status.coverage_gaps)}건은 보고됨."))
    except RagSecError as e:
        report.gates.append(_gate("G5", "Freeze preparation", GateStatus.BLOCKED, [ReasonCode.DATASET_INTEGRITY],
                                  f"후보 프리즈 계산 불가: {e.message}"))

    # ===================================================================== G6 Verification before execution
    if approved_freeze is None:
        freeze_status.approved_baseline = "absent"
        freeze_status.verification = "not_run"
        report.gates.append(_gate("G6", "Verification before execution", GateStatus.NOT_RUN,
                                  [ReasonCode.BASELINE_ABSENT],
                                  "사람이 승인한 프리즈 기준선이 없어 대조 검증을 실행하지 않음(not_run)."))
    else:
        freeze_status.approved_baseline = "present"
        try:
            drift = verify_freeze(settings, approved_freeze)
            if drift:
                freeze_status.verification = "drift"
                freeze_status.drift = drift[:20]
                report.gates.append(_gate("G6", "Verification before execution", GateStatus.FAIL,
                                          [ReasonCode.FREEZE_DRIFT],
                                          f"승인 기준선과 현재 아티팩트가 불일치(drift {len(drift)}건)."))
            else:
                freeze_status.verification = "match"
                report.gates.append(_gate("G6", "Verification before execution", GateStatus.PASS, [],
                                          "승인 기준선과 현재 아티팩트가 일치."))
        except RagSecError as e:
            freeze_status.verification = "unverifiable"
            report.gates.append(_gate("G6", "Verification before execution", GateStatus.FAIL,
                                      [ReasonCode.FREEZE_DRIFT], f"검증 불가: {e.message}"))
    report.freeze = freeze_status

    # UI/Metrics input (③) — a Backend→UI contract exists (doc 05); the UI→Backend submission is under-defined.
    inputs.append(RequiredInput(
        input_id="uiux_metrics", owner="UI/UX·Metrics (Role 4)", review_state=ReviewState.MISSING,
        review_match=MatchState.ABSENT,
        note="문서 05는 Backend→UI 계약. 지표 정의 서명/신규 API 필드 요구는 별도 제출 필요(미정)."))
    report.required_inputs = inputs
    report.notes.append("efficacy execution은 HOLD입니다. READY여도 실행 권한이 아니며, 사람 승인 + 승인 프리즈 검증이 필요합니다.")
    return report.rollup()


def frozen_prefix(ds: Dataset) -> str:
    return ds.manifest.content_hash[:16]
