"""Evidence-navigation slice tested through the real API (httpx ASGITransport, mock backend, no network/GPU).

Covers: authorized excerpt, denied full-source access, cross-handover/forged evidence id, metadata non-leakage,
same-link replay after revocation, the two evidence policies differing for an excerpt-only viewer, and controls
(unchanged grant, authorized original-document reviewer). Grants are changed only through the trusted GrantStore
(a protected mechanism), never the client. Evidence access is independent of D8 guard modes.
"""
from __future__ import annotations

import json

import httpx
import pytest

from ragsec.api import create_app
from ragsec.config import Settings
from ragsec.llm import MockLLMClient
from ragsec.services import build_services

KEY = "test-key-123456"
DOC = ("[고객 인계 메모]\n고객 민원 처리 현황은 정상 종결입니다.\n"
       "별도 주민등록번호 900101-1234567 확인은 내부 기록에만 보관합니다.")
META = {"document_id": "doc_hv", "document_version": 1, "source_name": "민원 인계 메모(합성)",
        "source_type": "crm_record", "source_trust_level": "medium", "document_kind": "business_document",
        "pii_grade": "unique_id", "pii_types": ["rrn"], "tenant_id": "bank_a", "allowed_roles": ["compliance"],
        "effective_from": "2026-01-01T00:00:00+09:00"}


@pytest.fixture
def built(tmp_path):
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key=KEY, vram_profile="vram_6gb", max_distance=2.0)
    svc = build_services(s, client=MockLLMClient(available={"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}))
    return svc, create_app(svc)


async def _create_handover(c, policy):
    q = await c.post("/query", json={"user_id": "u_comp_a", "query": "이 고객 민원 처리 현황을 요약해 주세요.",
                                     "guard_mode": "OFF", "create_handover": True, "recipient": "successor",
                                     "purpose": "handover", "channel": "response", "evidence_policy": policy})
    assert q.status_code == 200, q.text
    body = q.json()
    assert body["handover_id"] and body["evidence_links"], body
    return body["handover_id"], body["evidence_links"][0]["evidence_id"]


async def _open(c, hid, eid, viewer):
    r = await c.get(f"/handover/{hid}/evidence/{eid}", params={"viewer": viewer})
    assert r.headers.get("cache-control") == "no-store"
    return r.json()


def _assert_no_leak(res):
    assert res["outcome"] == "restricted"
    assert res["title"] is None and res["excerpt"] is None and res["page"] is None
    assert res["document_version"] is None


async def test_evidence_navigation_end_to_end(built):
    svc, app = built
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            r = await c.post("/documents", files={"file": ("m.txt", DOC.encode())},
                             data={"metadata": json.dumps(META)})
            assert r.status_code == 200 and r.json()["activated"], r.text

            hid_ae, eid_ae = await _create_handover(c, "approved_excerpt")
            hid_oo, eid_oo = await _create_handover(c, "original_only")

            # Grants are set only through the trusted store (protected mechanism), never the client/request body.
            svc.grants.grant(hid_ae, "u_staff_a")   # successor: may receive an excerpt, cannot read the source
            svc.grants.grant(hid_ae, "u_comp_a")    # authorized original-document reviewer control
            svc.grants.grant(hid_oo, "u_staff_a")

            # (A) authorized excerpt: granted recipient without original access -> EXCERPT with the cited title and
            # the permitted excerpt, but source LOCATION/provenance (page, document_version) withheld.
            exc = await _open(c, hid_ae, eid_ae, "u_staff_a")
            assert exc["outcome"] == "excerpt" and exc["excerpt"] and exc["title"]
            assert exc["page"] is None and exc["document_version"] is None

            # (B) denied full-source access: same viewer under original_only -> RESTRICTED, no leaked metadata
            den = await _open(c, hid_oo, eid_oo, "u_staff_a")
            _assert_no_leak(den)

            # control: authorized original-document reviewer -> ORIGINAL with source provenance shown
            orig = await _open(c, hid_ae, eid_ae, "u_comp_a")
            assert orig["outcome"] == "original" and orig["excerpt"] and orig["document_version"] == 1

            # cross-handover id (eid from the other handover) and a forged id -> RESTRICTED, no leak
            _assert_no_leak(await _open(c, hid_ae, eid_oo, "u_staff_a"))
            _assert_no_leak(await _open(c, hid_ae, "ev_forged000000", "u_staff_a"))

            # a viewer with no grant -> RESTRICTED
            _assert_no_leak(await _open(c, hid_ae, eid_ae, "u_teller_a"))

            # (C) same-link replay after revocation: unchanged url + identity, second call exposes nothing
            before = await _open(c, hid_ae, eid_ae, "u_staff_a")
            assert before["outcome"] == "excerpt"
            svc.grants.revoke(hid_ae, "u_staff_a")
            after = await _open(c, hid_ae, eid_ae, "u_staff_a")   # exact same URL, same identity
            _assert_no_leak(after)

            # control: the reviewer's unchanged grant is unaffected by the successor's revocation
            assert (await _open(c, hid_ae, eid_ae, "u_comp_a"))["outcome"] == "original"

            # safe log written without protected text
            logp = svc.settings.log_dir / "evidence_access.jsonl"
            assert logp.exists()
            text = logp.read_text(encoding="utf-8")
            assert "900101-1234567" not in text and "민원 처리 현황" not in text
            assert '"outcome": "restricted"' in text and '"outcome": "excerpt"' in text


async def test_metadata_regression_handover_and_restricted(built):
    """Regression on both delivery points: the initial handover response (requester) returns scoped links with no
    credentials in the URL; the recipient-facing OpenEvidence result never leaks requester-side source provenance
    (restricted leaks nothing; excerpt withholds page and document_version)."""
    svc, app = built
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            r = await c.post("/documents", files={"file": ("m.txt", DOC.encode())}, data={"metadata": json.dumps(META)})
            assert r.status_code == 200 and r.json()["activated"], r.text
            q = (await c.post("/query", json={"user_id": "u_comp_a", "query": "이 고객 민원 처리 현황을 요약해 주세요.",
                 "guard_mode": "OFF", "create_handover": True, "recipient": "successor", "purpose": "handover",
                 "channel": "response", "evidence_policy": "approved_excerpt"})).json()
            # (1) initial handover response
            assert q["handover_id"] and q["evidence_links"]
            hid = q["handover_id"]
            eid = q["evidence_links"][0]["evidence_id"]
            for ln in q["evidence_links"]:
                assert ln["url"] == f"/handover/{hid}/evidence/{ln['evidence_id']}"
                assert "X-API-Key" not in ln["url"] and "key" not in ln["url"].lower()
                # recipient-facing links carry NO forbidden source metadata (title/page/document id)
                assert set(ln.keys()) == {"label", "evidence_id", "url"}
            # (2) restricted evidence response (no grant) -> nothing leaks
            _assert_no_leak(await _open(c, hid, eid, "u_staff_a"))
            # (3) excerpt -> cited title + excerpt only; page and document_version withheld
            svc.grants.grant(hid, "u_staff_a")
            exc = await _open(c, hid, eid, "u_staff_a")
            assert exc["outcome"] == "excerpt" and exc["title"] and exc["excerpt"]
            assert exc["page"] is None and exc["document_version"] is None


async def test_index_version_pinned_to_retrieval(built):
    """The handover pins the EXACT version used to retrieve the cited chunk; a later index activation does not
    repoint the link, which still resolves to the original version."""
    svc, app = built
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            await c.post("/documents", files={"file": ("m.txt", DOC.encode())}, data={"metadata": json.dumps(META)})
            v_a = svc.repo.active_version()
            q = (await c.post("/query", json={"user_id": "u_comp_a", "query": "이 고객 민원 처리 현황을 요약해 주세요.",
                 "guard_mode": "OFF", "create_handover": True, "recipient": "successor",
                 "evidence_policy": "approved_excerpt"})).json()
            hid, eid = q["handover_id"], q["evidence_links"][0]["evidence_id"]
            assert q["active_index_version"] == v_a                        # pinned to the retrieval version
            assert svc.handovers.get(hid).evidence[eid].index_version == v_a
            # activate a NEW index version AFTER persistence by ingesting another document
            meta2 = {**META, "document_id": "doc_hv2"}
            await c.post("/documents", files={"file": ("m2.txt", DOC.encode())}, data={"metadata": json.dumps(meta2)})
            v_b = svc.repo.active_version()
            assert v_b != v_a
            assert svc.handovers.get(hid).evidence[eid].index_version == v_a   # unchanged pin
            svc.grants.grant(hid, "u_comp_a")
            res = await _open(c, hid, eid, "u_comp_a")                      # still resolves to the original version
            assert res["outcome"] == "original" and res["excerpt"]


async def test_admin_grant_revoke_endpoint(built):
    """The UI's permission-change path: the protected admin grant/revoke endpoint flips a viewer's entitlement."""
    svc, app = built
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            await c.post("/documents", files={"file": ("m.txt", DOC.encode())}, data={"metadata": json.dumps(META)})
            hid, eid = await _create_handover(c, "approved_excerpt")
            g = await c.post(f"/handover/{hid}/grant", params={"viewer": "u_staff_a", "action": "grant"})
            assert g.status_code == 200
            assert (await _open(c, hid, eid, "u_staff_a"))["outcome"] == "excerpt"
            rv = await c.post(f"/handover/{hid}/grant", params={"viewer": "u_staff_a", "action": "revoke"})
            assert rv.status_code == 200
            _assert_no_leak(await _open(c, hid, eid, "u_staff_a"))


async def test_open_evidence_requires_auth(built):
    svc, app = built
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:  # no key
        async with app.router.lifespan_context(app):
            r = await c.get("/handover/hv_x/evidence/ev_x", params={"viewer": "u_comp_a"})
            assert r.status_code == 401
