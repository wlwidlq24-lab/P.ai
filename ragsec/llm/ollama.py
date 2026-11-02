"""Strict Ollama RUNTIME inference client (docs: github.com/ollama/ollama/blob/main/docs/api.md).

Security boundaries enforced here (application-level attack-surface reduction, NOT a CVE patch):
  * Endpoint allowlist: ONLY POST /api/chat, POST /api/generate, POST /api/embed. Every other method/path
    (incl. /api/pull, /api/create, /api/push, /api/delete, /api/copy, blobs, and all diagnostics) is rejected
    BEFORE transmission. This is an allowlist, not a denylist.
  * No URL/path/method is selectable by callers: only dedicated typed methods exist; the shared transport
    re-validates method+path and re-checks the destination host against the immutable connection.
  * Model names must be in an approved allowlist; missing models raise an explicit error (never auto-pull).
  * follow_redirects=False and trust_env=False (no env proxy); any 3xx is treated as an error, never followed.
Diagnostics (/api/ps, /api/tags, /api/version) live only in the separate admin client (llm/admin.py).
"""
from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

from ..errors import (
    DeadlineExceededError, MalformedModelResponseError, ModelError, ModelNotFoundError, ModelTimeoutError,
    ModelUnavailableError, ResourceExhaustedError,
)
from ..netguard import OllamaConnection, UrlPolicyError, assert_in_allowlist, validate_loopback_url
from .base import ChatResult, EmbedResult

_OOM_MARKERS = ("out of memory", "cudamalloc", "cuda error", "insufficient memory", "failed to allocate",
                "requires more system memory", "unable to allocate")
_NS_TO_MS = 1e-6

# The complete set of endpoints the experiment runtime may ever call.
RUNTIME_ALLOWLIST: frozenset[tuple[str, str]] = frozenset({
    ("POST", "/api/chat"),      # generation and guard-model inference
    ("POST", "/api/generate"),  # permitted model loading / unloading (keep_alive)
    ("POST", "/api/embed"),     # embeddings
})


def _remaining(deadline: float | None, cap: float) -> float:
    if deadline is None:
        return cap
    rem = deadline - time.monotonic()
    if rem <= 0:
        raise DeadlineExceededError("request deadline exceeded before model call")
    return min(cap, rem)


def classify_http_error(status: int, body: str, model: str) -> ModelError:
    low = body.lower()
    if any(m in low for m in _OOM_MARKERS):
        return ResourceExhaustedError(f"{model}: resource exhausted", detail={"status": status, "body": body[:300]})
    if status == 404 or "not found" in low:
        # Explicit missing-model error; the runtime never pulls. Provision models out-of-band.
        return ModelNotFoundError(f"{model}: model not found; provision it administratively (ollama pull {model})",
                                  detail={"status": status})
    return ModelError(f"{model}: HTTP {status}", detail={"status": status, "body": body[:300]})


def normalize_model(name: str) -> str:
    return name if ":" in name else f"{name}:latest"


class OllamaClient:
    def __init__(self, base_url: str, *, allowed_models: set[str] | None = None, max_retries: int = 2,
                 max_connections: int = 4):
        # Re-validate here even though Settings validated: the client is the last gate before the socket.
        self._conn: OllamaConnection = validate_loopback_url(base_url)
        self._allowed = {normalize_model(m) for m in (allowed_models or set())}
        self._client = httpx.AsyncClient(
            base_url=self._conn.base_url,
            timeout=httpx.Timeout(connect=5.0, read=600.0, write=30.0, pool=30.0),
            limits=httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_connections),
            follow_redirects=False,  # never follow redirects
            trust_env=False,         # ignore HTTP(S)_PROXY / NO_PROXY and other env routing
        )
        self._max_retries = max_retries

    async def aclose(self) -> None:
        await self._client.aclose()

    def _check_model(self, model: str) -> None:
        if self._allowed and normalize_model(model) not in self._allowed:
            raise ModelNotFoundError(f"model {model!r} is not in the approved runtime allowlist",
                                     detail={"allowed": sorted(self._allowed)})

    async def _post(self, path: str, *, model: str, json_body: dict, timeout_s: float,
                    deadline: float | None) -> tuple[dict[str, Any], int]:
        # 1) method+path must be in the allowlist (also rejects query/dot-seg/encoded/absolute paths).
        assert_in_allowlist("POST", path, RUNTIME_ALLOWLIST)
        attempt = 0
        while True:
            per_try = _remaining(deadline, timeout_s)
            try:
                # 2) send only the relative path; base_url is the immutable validated loopback target.
                resp = await self._client.post(path, json=json_body, timeout=per_try)
            except httpx.TimeoutException as e:
                raise ModelTimeoutError(f"{model}: timed out after {per_try:.1f}s on {path}") from e
            except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError) as e:
                if attempt >= self._max_retries:
                    raise ModelUnavailableError(f"Ollama unreachable at {self._conn.base_url}: {type(e).__name__}") from e
                attempt += 1
                await asyncio.sleep(min(0.5 * 2 ** attempt + random.random() * 0.2, max(0.0, _remaining(deadline, 5.0))))
                continue
            # 3) treat any redirect as an error; never follow or retry as a redirect.
            if resp.is_redirect or 300 <= resp.status_code < 400:
                raise ModelError(f"{model}: unexpected redirect {resp.status_code} to "
                                 f"{resp.headers.get('location')!r} on {path} (not followed)",
                                 detail={"status": resp.status_code})
            # 4) verify the request stayed on the validated host (defense in depth against base_url drift).
            if resp.request.url.host != self._conn.host or resp.request.url.port != self._conn.port:
                raise UrlPolicyError(f"request left the validated host: {resp.request.url}")
            if resp.status_code in (502, 503) and attempt < self._max_retries:
                attempt += 1
                await asyncio.sleep(min(0.5 * 2 ** attempt, max(0.0, _remaining(deadline, 5.0))))
                continue
            if resp.status_code >= 400:
                raise classify_http_error(resp.status_code, resp.text, model)
            try:
                data = resp.json()
            except ValueError as e:
                raise MalformedModelResponseError(f"{model}: non-JSON response from {path}") from e
            if not isinstance(data, dict):
                raise MalformedModelResponseError(f"{model}: unexpected JSON type from {path}")
            if "error" in data:
                raise classify_http_error(500, str(data["error"]), model)
            return data, attempt

    async def chat(self, model: str, messages: list[dict[str, str]], *, options: dict[str, Any],
                   keep_alive: str | int, timeout_s: float, deadline: float | None = None,
                   think: bool | None = None) -> ChatResult:
        self._check_model(model)
        body: dict[str, Any] = {"model": model, "messages": messages, "stream": False,
                                "options": options, "keep_alive": keep_alive}
        if think is not None:
            body["think"] = think
        data, retries = await self._post("/api/chat", model=model, json_body=body,
                                         timeout_s=timeout_s, deadline=deadline)
        msg = data.get("message")
        if not isinstance(msg, dict) or not isinstance(msg.get("content"), str):
            raise MalformedModelResponseError(f"{model}: response lacks message.content")
        return ChatResult(
            text=msg["content"], model=data.get("model", model),
            load_ms=(data["load_duration"] * _NS_TO_MS) if isinstance(data.get("load_duration"), int) else None,
            total_ms=(data["total_duration"] * _NS_TO_MS) if isinstance(data.get("total_duration"), int) else None,
            prompt_eval_count=data.get("prompt_eval_count"), eval_count=data.get("eval_count"),
            done_reason=data.get("done_reason"), retries=retries,
        )

    async def embed(self, model: str, inputs: list[str], *, keep_alive: str | int, timeout_s: float,
                    deadline: float | None = None, options: dict[str, Any] | None = None) -> EmbedResult:
        self._check_model(model)
        body: dict[str, Any] = {"model": model, "input": inputs, "keep_alive": keep_alive, "truncate": True}
        if options:
            body["options"] = options
        data, retries = await self._post("/api/embed", model=model, json_body=body,
                                         timeout_s=timeout_s, deadline=deadline)
        vecs = data.get("embeddings")
        if not isinstance(vecs, list) or len(vecs) != len(inputs) or not all(isinstance(v, list) and v for v in vecs):
            raise MalformedModelResponseError(f"{model}: embeddings missing or count mismatch")
        return EmbedResult(
            vectors=vecs, model=model,
            load_ms=(data["load_duration"] * _NS_TO_MS) if isinstance(data.get("load_duration"), int) else None,
            total_ms=(data["total_duration"] * _NS_TO_MS) if isinstance(data.get("total_duration"), int) else None,
            retries=retries,
        )

    async def generate(self, model: str, *, keep_alive: str | int, timeout_s: float = 60.0,
                       deadline: float | None = None) -> dict[str, Any]:
        """Load (keep_alive>0) or unload (keep_alive=0) a model via /api/generate with an empty prompt."""
        self._check_model(model)
        data, _ = await self._post("/api/generate", model=model,
                                   json_body={"model": model, "prompt": "", "stream": False, "keep_alive": keep_alive},
                                   timeout_s=timeout_s, deadline=deadline)
        return data

    async def unload(self, model: str) -> None:
        # Permitted-endpoint unload: /api/generate with keep_alive=0 (done_reason == "unload").
        await self.generate(model, keep_alive=0, timeout_s=30.0)
