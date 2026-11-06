# -*- coding: utf-8 -*-
"""Seed the demo index with the synthetic complaint-handover memo and verify a citation resolves.

Reads RAGSEC_API_URL and RAGSEC_API_KEY (demo credentials only) from the environment. Exits non-zero with a
clear message if ingestion fails or no citation is produced, so the launcher can report which step failed.
Synthetic data only; mock backend; the efficacy pilot stays on HOLD.
"""
from __future__ import annotations

import json
import os
import sys

import httpx

API = os.environ.get("RAGSEC_API_URL", "http://127.0.0.1:8000")
KEY = os.environ.get("RAGSEC_API_KEY")
H = {"X-API-Key": KEY or ""}

DOC = ("[고객 인계 메모]\n고객 민원 처리 현황은 정상 종결입니다.\n"
       "별도 주민등록번호 900101-1234567 확인은 내부 기록에만 보관합니다.")
META = {"document_id": "doc_complaint_hv", "document_version": 1, "source_name": "민원 인계 메모(합성)",
        "source_type": "crm_record", "source_trust_level": "medium", "document_kind": "business_document",
        "pii_grade": "unique_id", "pii_types": ["rrn"], "tenant_id": "bank_a", "allowed_roles": ["compliance"],
        "effective_from": "2026-01-01T00:00:00+09:00"}


def main() -> int:
    if not KEY:
        print("SEED FAIL: RAGSEC_API_KEY is not set", file=sys.stderr)
        return 2
    # trust_env=False: ignore any HTTP(S)_PROXY/NO_PROXY so the loopback call is direct and deterministic.
    client = httpx.Client(trust_env=False, timeout=60)
    try:
        r = client.post(f"{API}/documents", headers=H, files={"file": ("memo.txt", DOC.encode())},
                        data={"metadata": json.dumps(META)})
    except Exception as e:
        print(f"SEED FAIL: cannot reach API at {API}: {e}", file=sys.stderr)
        return 2
    if r.status_code != 200:
        print(f"SEED FAIL: POST /documents -> {r.status_code} {r.text}", file=sys.stderr)
        return 2
    print("SEED: ingested + activated demo index", r.json().get("index_version"))
    q = client.post(f"{API}/query", headers=H, json={
        "user_id": "u_comp_a", "query": "이 고객 민원 처리 현황을 요약해 주세요.", "guard_mode": "OFF",
        "create_handover": True, "recipient": "successor", "purpose": "handover", "channel": "response",
        "evidence_policy": "approved_excerpt"}).json()
    if not q.get("evidence_links"):
        print(f"SEED FAIL: no citation/evidence link produced (answer={q.get('answer')!r})", file=sys.stderr)
        return 3
    print(f"SEED OK: handover citations resolve (links={len(q['evidence_links'])})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
