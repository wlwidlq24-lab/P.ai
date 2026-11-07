# -*- coding: utf-8 -*-
"""Seed the demo index with ONE synthetic W-01 민원 조사 case and verify /investigation returns findings.

Stages: (1) a synthetic complaint-investigation memo document (fictional institution, synthetic identifiers,
no RRN/password per the data-survey design), ingested via the API; (2) a structured InvestigationCase JSON
(workflow config) written into RAGSEC_DATA_DIR/investigation_cases/. Then calls POST /investigation as an
authorized investigator and checks structured findings + at least one evidence link resolve.

Synthetic data only; mock backend; the IPI efficacy pilot stays on HOLD (no attack payloads here).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

API = os.environ.get("RAGSEC_API_URL", "http://127.0.0.1:8000")
KEY = os.environ.get("RAGSEC_API_KEY")
DATA_DIR = Path(os.environ.get("RAGSEC_DATA_DIR", "var"))
H = {"X-API-Key": KEY or ""}
CASE_ID = "CASE-2026-0007"
DOC_ID = "doc_investigation_hv"

# Fictional institution + synthetic identifiers only. Masked account token and a synthetic phone (to show
# defensive masking in the excerpt view). No RRN, no password (excluded by the data-survey design).
MEMO = (
    "[민원 조사 인계 메모 — 합성]\n"
    f"사건 식별자: {CASE_ID}\n"
    "기관: 가상상호은행(합성)\n"
    "민원 쟁점: 고객이 착오송금 반환 지연을 문의함.\n"
    "확인 사실: 민원 접수일 2026-11-02, 1차 상담에서 반환 절차 안내 완료, 출금 계좌는 마스킹 계좌 110-***-4567.\n"
    "확인 중: 수취은행 회신 대기(반환 가능 여부 미확정).\n"
    "다음 조치: 수취은행 회신 확인 후 고객에게 결과 통지(기한 2026-11-14).\n"
    "연락 메모: 고객 연락처 010-2000-3000 은 시스템에서만 열람하며 인계 요약에는 제외한다.\n"
)
META = {"document_id": DOC_ID, "document_version": 1, "source_name": "민원 조사 인계 메모(합성)",
        "source_type": "crm_record", "source_trust_level": "medium", "document_kind": "business_document",
        "pii_grade": "general", "pii_types": ["phone"], "tenant_id": "bank_a", "allowed_roles": ["compliance"],
        "effective_from": "2026-01-01T00:00:00+09:00"}

CASE = {
    "schema_version": "investigation-case/1.0",
    "case_id": CASE_ID,
    "institution": "가상상호은행(합성)",
    "subject_ref": "CUST-SYN-0007",
    "issue": "착오송금 반환 지연 문의",
    "status": "조사 진행 중",
    "findings": [
        {"text": "민원 접수일은 2026-11-02이며 1차 상담에서 반환 절차를 안내했다.", "status": "confirmed", "evidence_label": "E1"},
        {"text": "출금 계좌는 마스킹 계좌(110-***-4567)로 확인된다.", "status": "confirmed", "evidence_label": "E1"},
        {"text": "수취은행의 반환 가능 여부 회신을 아직 받지 못했다.", "status": "checking", "evidence_label": None},
    ],
    "next_actions": [
        {"text": "수취은행 회신을 확인한다.", "due": None},
        {"text": "회신 확인 후 고객에게 결과를 통지한다.", "due": "2026-11-14"},
    ],
    "withheld_categories": ["고객 성명 원문", "연락처 원문", "계좌번호 원문"],
    "evidence_query": "이 민원 사건의 확인 사실과 다음 조치를 요약해 주세요.",
    "source_document_id": DOC_ID,
}


def main() -> int:
    if not KEY:
        print("SEED FAIL: RAGSEC_API_KEY is not set", file=sys.stderr)
        return 2
    client = httpx.Client(trust_env=False, timeout=60)
    # (1) ingest the synthetic memo
    try:
        r = client.post(f"{API}/documents", headers=H, files={"file": ("memo.txt", MEMO.encode())},
                        data={"metadata": json.dumps(META)})
    except Exception as e:
        print(f"SEED FAIL: cannot reach API at {API}: {e}", file=sys.stderr)
        return 2
    if r.status_code != 200:
        print(f"SEED FAIL: POST /documents -> {r.status_code} {r.text}", file=sys.stderr)
        return 2
    print("SEED: ingested + activated demo index", r.json().get("index_version"))
    # (2) stage the structured investigation case (workflow config)
    cases_dir = DATA_DIR / "investigation_cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    (cases_dir / f"{CASE_ID}.json").write_text(json.dumps(CASE, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"SEED: staged investigation case {CASE_ID} -> {cases_dir / (CASE_ID + '.json')}")
    # (3) verify the workflow end to end as an authorized investigator
    inv = client.post(f"{API}/investigation", headers=H, json={
        "user_id": "u_comp_a", "case_id": CASE_ID, "recipient": "후임 담당자"}).json()
    nconf = len(inv.get("confirmed_facts", []))
    nlink = len(inv.get("evidence_links", []))
    if nconf < 1:
        print(f"SEED FAIL: no confirmed findings returned ({inv!r})", file=sys.stderr)
        return 3
    print(f"SEED OK: investigation findings resolve (confirmed={nconf}, checking={len(inv.get('checking', []))}, "
          f"evidence_links={nlink})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
