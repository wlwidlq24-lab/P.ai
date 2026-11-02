"""API-layer tests using httpx ASGITransport against the mock backend (no network, no GPU)."""
from __future__ import annotations

import httpx
import pytest

from ragsec.api import create_app
from ragsec.llm import MockLLMClient
from ragsec.services import build_services

KEY = "test-key-123456"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("RAGSEC_API_KEY", KEY)
    from ragsec.config import Settings
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key=KEY, vram_profile="vram_6gb")
    svc = build_services(s, client=MockLLMClient(available={"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}))
    return create_app(svc)


async def test_health_open_and_query_requires_key(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        async with app.router.lifespan_context(app):  # runs lifespan -> app.state.svc
            h = await c.get("/health")
            assert h.status_code == 200 and h.json()["backend"] == "mock"
            r = await c.post("/query", json={"user_id": "u_staff_a", "query": "안녕"})  # no key
            assert r.status_code == 401


async def test_upload_and_query_flow(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-API-Key": KEY}) as c:
        async with app.router.lifespan_context(app):
            meta = {"document_id": "doc_api_fee", "document_version": 1, "source_name": "wiki",
                    "source_type": "internal_wiki", "source_trust_level": "high",
                    "document_kind": "business_document", "pii_grade": "none", "tenant_id": "bank_a",
                    "allowed_roles": ["general_staff"], "effective_from": "2026-01-01T00:00:00+09:00"}
            import json
            r = await c.post("/documents", files={"file": ("fee.txt", "타행 이체 수수료는 1,000원입니다.".encode())},
                             data={"metadata": json.dumps(meta)})
            assert r.status_code == 200, r.text
            assert r.json()["activated"]
            q = await c.post("/query", json={"user_id": "u_staff_a", "query": "타행 이체 수수료는?",
                                             "guard_mode": "HYBRID"})
            assert q.status_code == 200, q.text
            assert "1,000원" in q.json()["answer"]
