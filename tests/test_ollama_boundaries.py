"""HTTP endpoint-boundary tests for the runtime and admin Ollama clients, using httpx MockTransport.

No external network and no vulnerability exploitation: a mock transport records every request the client
actually attempts, so we can prove forbidden endpoints are rejected BEFORE transmission.
"""
from __future__ import annotations

import httpx
import pytest

from ragsec.errors import ModelError, ModelNotFoundError
from ragsec.llm.admin import OllamaAdminClient
from ragsec.llm.ollama import OllamaClient
from ragsec.netguard import UrlPolicyError

ALLOWED = {"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}


class Recorder:
    def __init__(self, status=200, body=None, redirect=False):
        self.seen: list[tuple[str, str]] = []
        self.status = status
        self.body = body or {}
        self.redirect = redirect

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append((request.method, request.url.path))
        if self.redirect:
            return httpx.Response(307, headers={"location": "http://127.0.0.1:11434/api/pull"})
        if self.status >= 400:
            return httpx.Response(self.status, json={"error": "not found"})
        # minimal valid shapes per endpoint
        if request.url.path == "/api/chat":
            return httpx.Response(200, json={"model": "m", "message": {"role": "assistant", "content": "ok"},
                                             "done_reason": "stop"})
        if request.url.path == "/api/embed":
            return httpx.Response(200, json={"model": "m", "embeddings": [[0.1, 0.2, 0.3]]})
        if request.url.path == "/api/generate":
            return httpx.Response(200, json={"model": "m", "done": True, "done_reason": "unload"})
        return httpx.Response(200, json=self.body)


def _runtime(rec: Recorder, allowed=ALLOWED) -> OllamaClient:
    c = OllamaClient("http://127.0.0.1:11434", allowed_models=allowed)
    # swap the real transport for the recorder; keep the hardened flags
    c._client = httpx.AsyncClient(base_url=c._conn.base_url, transport=httpx.MockTransport(rec.handler),
                                  follow_redirects=False, trust_env=False)
    return c


def test_client_sets_hardened_flags():
    c = OllamaClient("http://127.0.0.1:11434", allowed_models=ALLOWED)
    assert c._client.follow_redirects is False
    assert c._client.trust_env is False


async def test_three_allowed_endpoints_succeed():
    rec = Recorder()
    c = _runtime(rec)
    await c.chat("exaone3.5:2.4b", [{"role": "user", "content": "hi"}], options={}, keep_alive="5m", timeout_s=10)
    await c.embed("bge-m3", ["x"], keep_alive="5m", timeout_s=10)
    await c.unload("exaone3.5:2.4b")  # uses /api/generate
    await c.aclose()
    assert rec.seen == [("POST", "/api/chat"), ("POST", "/api/embed"), ("POST", "/api/generate")]


async def test_forbidden_paths_rejected_before_send():
    rec = Recorder()
    c = _runtime(rec)
    for path in ["/api/pull", "/api/create", "/api/push", "/api/delete", "/api/copy", "/api/tags", "/api/ps"]:
        with pytest.raises(UrlPolicyError):
            await c._post(path, model="exaone3.5:2.4b", json_body={}, timeout_s=5, deadline=None)
    await c.aclose()
    assert rec.seen == []  # NOTHING was transmitted


async def test_encoded_and_absolute_paths_rejected():
    rec = Recorder()
    c = _runtime(rec)
    for path in ["/api/chat%2f..%2fpull", "http://127.0.0.1/api/chat", "//evil/api/chat", "/api/../api/pull"]:
        with pytest.raises(UrlPolicyError):
            await c._post(path, model="exaone3.5:2.4b", json_body={}, timeout_s=5, deadline=None)
    await c.aclose()
    assert rec.seen == []


async def test_redirect_not_followed():
    rec = Recorder(redirect=True)
    c = _runtime(rec)
    with pytest.raises(ModelError):
        await c.chat("exaone3.5:2.4b", [{"role": "user", "content": "hi"}], options={}, keep_alive="5m", timeout_s=10)
    await c.aclose()
    assert rec.seen == [("POST", "/api/chat")]  # exactly one request; the 307 target was NOT fetched


async def test_model_not_in_allowlist_rejected_before_send():
    rec = Recorder()
    c = _runtime(rec)
    with pytest.raises(ModelNotFoundError):
        await c.chat("evil-model:latest", [{"role": "user", "content": "x"}], options={}, keep_alive="5m", timeout_s=10)
    await c.aclose()
    assert rec.seen == []


async def test_missing_model_errors_without_autopull():
    rec = Recorder(status=404)
    c = _runtime(rec)
    with pytest.raises(ModelNotFoundError):
        await c.chat("exaone3.5:2.4b", [{"role": "user", "content": "x"}], options={}, keep_alive="5m", timeout_s=10)
    await c.aclose()
    # the client asked /api/chat and got 404; it must NOT then call /api/pull
    assert ("POST", "/api/pull") not in rec.seen


async def test_runtime_client_has_no_diagnostic_methods():
    c = OllamaClient("http://127.0.0.1:11434", allowed_models=ALLOWED)
    assert not hasattr(c, "ps")
    assert not hasattr(c, "tags")
    assert not hasattr(c, "version")
    await c.aclose()


async def test_admin_client_only_allows_diagnostics():
    rec = Recorder(body={"version": "test", "models": []})
    a = OllamaAdminClient("http://127.0.0.1:11434")
    a._client = httpx.AsyncClient(base_url=a._conn.base_url, transport=httpx.MockTransport(rec.handler),
                                  follow_redirects=False, trust_env=False)
    await a.version()
    await a.tags()
    await a.ps()
    assert rec.seen == [("GET", "/api/version"), ("GET", "/api/tags"), ("GET", "/api/ps")]
    # admin client cannot reach generation endpoints
    with pytest.raises(UrlPolicyError):
        await a._get("/api/chat")
    await a.aclose()


def test_client_construction_rejects_bad_url_no_client():
    # a rejected URL must raise at construction (no usable client, so no request can ever be sent)
    with pytest.raises(UrlPolicyError):
        OllamaClient("http://0.0.0.0:11434", allowed_models=ALLOWED)
