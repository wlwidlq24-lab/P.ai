"""Separate ADMINISTRATIVE Ollama client for read-only diagnostics.

This client is strictly separated from the experiment runtime (llm/ollama.py). It is used only by the
admin CLI (`ragsec doctor` / `ragsec admin-probe`) and by the experiment runner to build the PRE-RUN
manifest. FastAPI request handlers, Streamlit, the scheduler and RAG orchestration must NOT use it.

Same loopback-only validation and transport hardening as the runtime client, but a DIFFERENT, fixed
allowlist of read-only diagnostic endpoints. It cannot generate, embed, load/unload, or manage models.
"""
from __future__ import annotations

from typing import Any

import httpx

from ..errors import ModelError, ModelUnavailableError
from ..netguard import OllamaConnection, UrlPolicyError, assert_in_allowlist, validate_loopback_url

DIAGNOSTIC_ALLOWLIST: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/api/version"),
    ("GET", "/api/tags"),
    ("GET", "/api/ps"),
})


class OllamaAdminClient:
    def __init__(self, base_url: str, timeout_s: float = 10.0):
        self._conn: OllamaConnection = validate_loopback_url(base_url)
        self._client = httpx.AsyncClient(base_url=self._conn.base_url, timeout=timeout_s,
                                         follow_redirects=False, trust_env=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _get(self, path: str) -> dict[str, Any]:
        assert_in_allowlist("GET", path, DIAGNOSTIC_ALLOWLIST)
        try:
            resp = await self._client.get(path)
        except httpx.HTTPError as e:
            raise ModelUnavailableError(f"ollama diagnostics unreachable: {type(e).__name__}") from e
        if resp.is_redirect or 300 <= resp.status_code < 400:
            raise ModelError(f"diagnostic {path}: unexpected redirect {resp.status_code} (not followed)")
        if resp.request.url.host != self._conn.host or resp.request.url.port != self._conn.port:
            raise UrlPolicyError(f"diagnostic request left the validated host: {resp.request.url}")
        if resp.status_code >= 400:
            raise ModelError(f"diagnostic {path}: HTTP {resp.status_code}")
        data = resp.json()
        if not isinstance(data, dict):
            raise ModelError(f"diagnostic {path}: unexpected JSON type")
        return data

    async def version(self) -> str | None:
        v = (await self._get("/api/version")).get("version")
        return v if isinstance(v, str) else None

    async def tags(self) -> list[dict[str, Any]]:
        return list((await self._get("/api/tags")).get("models") or [])

    async def ps(self) -> list[dict[str, Any]]:
        return list((await self._get("/api/ps")).get("models") or [])
