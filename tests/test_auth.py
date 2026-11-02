"""Authentication boundary: legacy + multi-user principals, spoof rejection, tenant/admin gating."""
from __future__ import annotations

import httpx
import pytest

from ragsec.api import create_app
from ragsec.auth import PrincipalStore, authenticate
from ragsec.config import Settings
from ragsec.llm import MockLLMClient
from ragsec.services import build_services

AVAIL = {"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}


# ------------------------------------------------------------------ unit
def test_legacy_authenticate():
    s = Settings(api_key="shared-key-123456", auth_mode="legacy")
    p = authenticate(s, None, "shared-key-123456")
    assert p and p.is_admin and p.legacy
    assert authenticate(s, None, "wrong-key") is None
    assert authenticate(s, None, None) is None


def test_store_add_resolve_revoke_no_plaintext(tmp_path):
    store = PrincipalStore(path=tmp_path / "principals.json")
    tok = store.add("p1", user_id="u_comp_a", tenant_id="bank_a", roles=["compliance"], is_admin=False)
    p = store.resolve(tok)
    assert p and p.user_id == "u_comp_a" and p.tenant_id == "bank_a" and not p.is_admin
    assert store.resolve("not-a-token") is None
    assert store.revoke("p1") and store.resolve(tok) is None
    assert tok not in (tmp_path / "principals.json").read_text(encoding="utf-8")  # only the hash is stored


def test_multiuser_legacy_key_disabled_by_default(tmp_path):
    store = PrincipalStore(path=tmp_path / "p.json")
    tok = store.add("p1", user_id="u_comp_a", tenant_id="bank_a", roles=["compliance"], is_admin=False)
    s = Settings(api_key="shared-key-123456", auth_mode="multiuser", allow_legacy_key=False)
    assert authenticate(s, store, tok).user_id == "u_comp_a"
    assert authenticate(s, store, "shared-key-123456") is None  # shared key NOT accepted in multiuser by default
    s2 = Settings(api_key="shared-key-123456", auth_mode="multiuser", allow_legacy_key=True)
    assert authenticate(s2, store, "shared-key-123456").is_admin  # explicit opt-in


# ------------------------------------------------------------------ API
def _multiuser_app(tmp_path):
    princ = tmp_path / "principals.json"
    store = PrincipalStore(path=princ)
    user_tok = store.add("pu", user_id="u_comp_a", tenant_id="bank_a", roles=["compliance"], is_admin=False)
    admin_tok = store.add("pa", user_id=None, tenant_id=None, roles=[], is_admin=True)
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key="shared-key-123456", vram_profile="vram_6gb", auth_mode="multiuser", principals_file=princ)
    svc = build_services(s, client=MockLLMClient(available=AVAIL))
    return create_app(svc), user_tok, admin_tok


async def test_api_multiuser_permitted_denied_spoof_tenant(tmp_path):
    app, user_tok, admin_tok = _multiuser_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        async with app.router.lifespan_context(app):
            # unauthenticated / bad token
            assert (await c.post("/query", json={"user_id": "u_comp_a", "query": "안녕"})).status_code == 401
            bad = await c.post("/query", json={"user_id": "u_comp_a", "query": "안녕"},
                               headers={"X-API-Key": "nope"})
            assert bad.status_code == 401
            import json as _json
            meta = {"document_id": "d1", "document_version": 1, "source_name": "w", "source_type": "internal_wiki",
                    "source_trust_level": "high", "document_kind": "business_document", "pii_grade": "none",
                    "tenant_id": "bank_a", "allowed_roles": ["compliance"]}
            # admin-only endpoint denied to a non-admin principal
            denied = await c.post("/documents", files={"file": ("a.txt", "내용".encode())},
                                  data={"metadata": _json.dumps(meta)}, headers={"X-API-Key": user_tok})
            assert denied.status_code == 403, denied.text
            # admin principal can ingest (also creates the active index)
            okdoc = await c.post("/documents", files={"file": ("a.txt", "내용 문서입니다.".encode())},
                                 data={"metadata": _json.dumps(meta)}, headers={"X-API-Key": admin_tok})
            assert okdoc.status_code == 200, okdoc.text
            # permitted: scoped user acting as itself
            ok = await c.post("/query", json={"user_id": "u_comp_a", "query": "안녕"},
                              headers={"X-API-Key": user_tok})
            assert ok.status_code == 200, ok.text
            # spoof: scoped user tries to act as a different user -> 403
            spoof = await c.post("/query", json={"user_id": "u_comp_b", "query": "안녕"},
                                 headers={"X-API-Key": user_tok})
            assert spoof.status_code == 403, spoof.text


async def test_api_tenant_scoped_admin_cannot_cross_tenant_ingest(tmp_path):
    princ = tmp_path / "principals.json"
    store = PrincipalStore(path=princ)
    # an admin SCOPED to bank_a
    scoped = store.add("pb", user_id=None, tenant_id="bank_a", roles=[], is_admin=True)
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key="shared-key-123456", vram_profile="vram_6gb", auth_mode="multiuser", principals_file=princ)
    app = create_app(build_services(s, client=MockLLMClient(available=AVAIL)))
    transport = httpx.ASGITransport(app=app)
    import json as _json
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        async with app.router.lifespan_context(app):
            meta = {"document_id": "d2", "document_version": 1, "source_name": "w", "source_type": "internal_wiki",
                    "source_trust_level": "high", "document_kind": "business_document", "pii_grade": "none",
                    "tenant_id": "bank_b", "allowed_roles": ["compliance"]}  # cross-tenant!
            r = await c.post("/documents", files={"file": ("a.txt", "내용".encode())},
                             data={"metadata": _json.dumps(meta)}, headers={"X-API-Key": scoped})
            assert r.status_code == 403, r.text
            # a tenant-scoped admin may not perform the GLOBAL index activation either
            act = await c.post("/index/activate/v-does-not-matter", headers={"X-API-Key": scoped})
            assert act.status_code == 403, act.text


async def test_health_reports_auth_mode_and_tenants(tmp_path):
    princ = tmp_path / "principals.json"
    PrincipalStore(path=princ).add("pa", user_id=None, tenant_id=None, roles=[], is_admin=True)
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key="shared-key-123456", vram_profile="vram_6gb", auth_mode="multiuser", principals_file=princ)
    app = create_app(build_services(s, client=MockLLMClient(available=AVAIL)))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        async with app.router.lifespan_context(app):
            h = (await c.get("/health")).json()
            assert h["auth_mode"] == "multiuser"
            assert "bank_a" in h["tenants_enabled"]
