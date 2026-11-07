"""W-01 민원 조사 workflow through the real API (mock backend, no network/GPU).

Covers: an authorized investigator receives STRUCTURED findings (confirmed vs still-checking) + evidence links;
the requester's right to consult records is distinct from a recipient's right to open the evidence (per-click
grant at OpenEvidence, unchanged); an unauthorized role is refused; an unknown case is 404; and missing evidence
yields findings with no links and an explanatory note (not a crash).
"""
from __future__ import annotations

import json

import httpx
import pytest

from ragsec.api import create_app
from ragsec.config import Settings
from ragsec.investigation import FactStatus, FindingItem, InvestigationCase, NextAction, write_case
from ragsec.llm import MockLLMClient
from ragsec.services import build_services

KEY = "test-key-123456"
MEMO = ("[민원 조사 인계 메모 — 합성]\n사건 식별자: CASE-TEST\n기관: 가상상호은행(합성)\n"
        "민원 쟁점: 고객이 착오송금 반환 지연을 문의함.\n"
        "확인 사실: 민원 접수일 2026-11-02, 1차 상담에서 반환 절차 안내 완료, 출금 계좌는 마스킹 계좌 110-***-4567.\n"
        "다음 조치: 수취은행 회신 확인 후 고객에게 결과 통지(기한 2026-11-14).\n"
        "연락 메모: 고객 연락처 010-2000-3000 은 시스템에서만 열람한다.\n")
META = {"document_id": "doc_inv", "document_version": 1, "source_name": "민원 조사 인계 메모(합성)",
        "source_type": "crm_record", "source_trust_level": "medium", "document_kind": "business_document",
        "pii_grade": "general", "pii_types": ["phone"], "tenant_id": "bank_a", "allowed_roles": ["compliance"],
        "effective_from": "2026-01-01T00:00:00+09:00"}


def _case(case_id="CASE-TEST", source="doc_inv") -> InvestigationCase:
    return InvestigationCase(
        case_id=case_id, institution="가상상호은행(합성)", subject_ref="CUST-SYN-TEST",
        issue="착오송금 반환 지연 문의", status="조사 진행 중",
        findings=[FindingItem(text="민원 접수일은 2026-11-02이며 1차 상담에서 반환 절차를 안내했다.",
                              status=FactStatus.CONFIRMED, evidence_label="E1"),
                  FindingItem(text="출금 계좌는 마스킹 계좌(110-***-4567)로 확인된다.",
                              status=FactStatus.CONFIRMED, evidence_label="E1"),
                  FindingItem(text="수취은행의 반환 가능 여부 회신을 아직 받지 못했다.",
                              status=FactStatus.CHECKING)],
        next_actions=[NextAction(text="수취은행 회신을 확인한다."),
                      NextAction(text="회신 확인 후 고객에게 결과를 통지한다.", due="2026-11-14")],
        withheld_categories=["고객 성명 원문", "연락처 원문", "계좌번호 원문"],
        evidence_query="이 민원 사건의 확인 사실과 다음 조치를 요약해 주세요.", source_document_id=source)


@pytest.fixture
def built(tmp_path):
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key=KEY, vram_profile="vram_6gb", max_distance=2.0)
    svc = build_services(s, client=MockLLMClient(available={"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}))
    return svc, create_app(svc)


async def _ingest(c):
    r = await c.post("/documents", files={"file": ("m.txt", MEMO.encode())}, data={"metadata": json.dumps(META)})
    assert r.status_code == 200 and r.json()["activated"], r.text


async def test_investigation_structured_findings_and_separation(built):
    svc, app = built
    write_case(svc.settings.data_dir, _case())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            await _ingest(c)
            r = await c.post("/investigation", json={"user_id": "u_comp_a", "case_id": "CASE-TEST",
                                                     "recipient": "후임 담당자"})
            assert r.status_code == 200, r.text
            d = r.json()
            # structured separation: confirmed vs still-checking are distinct buckets
            assert [f["text"] for f in d["confirmed_facts"]] and len(d["confirmed_facts"]) == 2
            assert len(d["checking"]) == 1 and d["checking"][0]["status"] == "checking"
            assert d["next_actions"][-1]["due"] == "2026-11-14"
            assert "연락처 원문" in d["withheld_categories"]
            assert d["handover_id"] and d["evidence_links"], d
            hid = d["handover_id"]
            eid = d["evidence_links"][0]["evidence_id"]
            # requester consulted records; a RECIPIENT still cannot open evidence without a grant (separation)
            denied = (await c.get(f"/handover/{hid}/evidence/{eid}", params={"viewer": "u_staff_a"})).json()
            assert denied["outcome"] == "restricted" and denied["title"] is None
            svc.grants.grant(hid, "u_staff_a")   # protected mechanism, never the client
            exc = (await c.get(f"/handover/{hid}/evidence/{eid}", params={"viewer": "u_staff_a"})).json()
            assert exc["outcome"] == "excerpt" and exc["excerpt"]
            assert exc["page"] is None and exc["document_version"] is None   # source location withheld
            # defensive masking: the synthetic phone is not shown in the clear
            assert "010-2000-3000" not in exc["excerpt"]


async def test_insufficient_authority_is_refused(built):
    svc, app = built
    write_case(svc.settings.data_dir, _case())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            await _ingest(c)
            r = await c.post("/investigation", json={"user_id": "u_staff_a", "case_id": "CASE-TEST"})
            assert r.status_code == 403, r.text   # general_staff may not initiate an investigation


async def test_unknown_case_is_404(built):
    svc, app = built
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            await _ingest(c)
            r = await c.post("/investigation", json={"user_id": "u_comp_a", "case_id": "NOPE-0000"})
            assert r.status_code == 404, r.text


async def test_missing_evidence_returns_findings_with_note(built):
    svc, app = built
    write_case(svc.settings.data_dir, _case())   # case staged, but NO document ingested -> no active index
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            r = await c.post("/investigation", json={"user_id": "u_comp_a", "case_id": "CASE-TEST",
                                                     "recipient": "후임 담당자"})
            assert r.status_code == 200, r.text
            d = r.json()
            assert d["confirmed_facts"] and not d["evidence_links"]   # findings still delivered, no links
            assert d["handover_id"] is None and d["notes"]            # explanatory note, not a crash


def test_path_traversal_case_id_rejected(built):
    svc, app = built
    from ragsec.errors import InvestigationCaseNotFoundError
    from ragsec.investigation import load_case
    for bad in ("../secrets", "a/b", "..", ".hidden"):
        with pytest.raises(InvestigationCaseNotFoundError):
            load_case(svc.settings.data_dir, bad)
