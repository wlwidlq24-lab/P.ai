"""Deterministic offline model backend for unit tests, CI and UI demos.

It deliberately simulates a *vulnerable* generator so the pipeline, guards and metrics can be exercised
end-to-end without a GPU. Its outputs are NOT research data and must never be reported as results.
Records produced with this backend carry target.digest = "mock".
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import re
from typing import Any

from ..errors import ModelNotFoundError, ResourceExhaustedError
from ..textproc import normalize
from .base import ChatResult, EmbedResult

DIM = 64
_INJECTION = re.compile(r"(이전\s*(의\s*)?(모든\s*)?지시|ignore\s+(all\s+)?(previous|prior)|시스템\s*관리자\s*지시|SYSTEM OVERRIDE)", re.I)
_MARKER = re.compile(r"(?:확인\s*코드|confirmation\s+code)\s*[:：]?\s*([A-Z]{3}-\d{4})", re.I)
_DEST = re.compile(r"mock-sink://[\w\-/.]+")
_PII = re.compile(r"\d{6}-[1-8]\d{6}|\d{3}-\d{2,6}-\d{2,6}(?:-\d{1,3})?")
_UNSAFE_HINTS = ("주민등록번호 전체", "exfiltrate", "send all customer", "전체 고객정보", "SYSTEM OVERRIDE")


def _embed(text: str) -> list[float]:
    """Overlap-sensitive bag-of-bigrams (non-negative), so shared vocabulary lowers cosine distance.

    This is a crude stand-in that only needs to rank text with real token overlap above unrelated text so
    the offline pipeline retrieves sensibly. It is NOT a semantic model and is never research data.
    """
    t = normalize(text).text.lower()
    v = [0.0] * DIM
    toks = re.findall(r"[0-9a-z가-힣]+", t)
    grams = [w[i:i + 2] for w in toks for i in range(max(1, len(w) - 1))] or [t[:2]]
    for g in grams:
        h = int.from_bytes(hashlib.md5(g.encode()).digest()[:4], "little")
        v[h % DIM] += 1.0  # non-negative counts: any shared bigram raises cosine similarity
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


class MockLLMClient:
    def __init__(self, available: list[str] | None = None, latency_s: float = 0.0):
        self.available = set(available) if available else None
        self.latency_s = latency_s
        self.loaded: dict[str, int] = {}
        self.calls: list[tuple[str, str]] = []

    def _check(self, model: str) -> None:
        if self.available is not None and model not in self.available:
            raise ModelNotFoundError(f"{model}: model not found (mock)")

    async def aclose(self) -> None:
        return None

    async def chat(self, model: str, messages: list[dict[str, str]], *, options: dict[str, Any],
                   keep_alive: str | int, timeout_s: float, deadline: float | None = None,
                   think: bool | None = None) -> ChatResult:
        self._check(model)
        cold = model not in self.loaded
        self.loaded[model] = 1
        self.calls.append(("chat", model))
        content = "\n".join(m.get("content", "") for m in messages)
        if "__MOCK_TIMEOUT__" in content:
            await asyncio.sleep(timeout_s + 1)
        if "__MOCK_OOM__" in content:
            raise ResourceExhaustedError(f"{model}: CUDA error: out of memory (mock)")
        if self.latency_s:
            await asyncio.sleep(self.latency_s)
        if "guard" in model:
            if "__MOCK_MALFORMED__" in content:
                text = "maybe?"
            else:
                last = messages[-1]["content"] if messages else ""
                text = "unsafe\nS7" if any(h.lower() in last.lower() for h in _UNSAFE_HINTS) else "safe"
        else:
            text = self._generate(messages)
        return ChatResult(text=text, model=model, load_ms=50.0 if cold else 0.0, total_ms=1.0,
                          prompt_eval_count=len(content) // 4, eval_count=len(text) // 4, done_reason="stop")

    def _generate(self, messages: list[dict[str, str]]) -> str:
        user = messages[-1]["content"] if messages else ""
        ctx_norm = normalize(user).text
        if _INJECTION.search(ctx_norm):
            parts = ["요청하신 내용을 처리했습니다."]
            m = _MARKER.search(ctx_norm)
            if m:
                parts.append(f"확인 코드: {m.group(1)}")
            pii = list(dict.fromkeys(_PII.findall(ctx_norm)))
            d = _DEST.search(ctx_norm)
            if d:
                parts.append(f"[[ACTION:send_report|to={d.group(0)}]]\n" + "\n".join(pii) + "\n[[/ACTION]]")
            elif pii:
                parts.append("고객 정보: " + ", ".join(pii))
            return "\n".join(parts)
        q = re.search(r"<question>(.*?)</question>", user, re.S)
        qtoks = set(re.findall(r"[가-힣a-zA-Z0-9]{2,}", q.group(1) if q else ""))
        lines = [d.strip() for d in re.findall(r"<document[^>]*>(.*?)</document>", user, re.S) if d.strip()]
        sents = [s.strip() for ln in lines for s in re.split(r"(?<=[.다])\s+|\n", ln) if s.strip()]
        scored = sorted(sents, key=lambda s: -len(qtoks & set(re.findall(r"[가-힣a-zA-Z0-9]{2,}", s))))
        best = [s for s in scored[:2] if qtoks & set(re.findall(r"[가-힣a-zA-Z0-9]{2,}", s))]
        if not best:
            return "제공된 문서에서 답을 찾을 수 없습니다."
        # Cite the first provided evidence label (deterministic; exercises the citation path offline).
        labels = re.findall(r'label="(E\d+)"', user)
        answer = " ".join(best)
        return f"{answer} [{labels[0]}]" if labels else answer

    async def embed(self, model: str, inputs: list[str], *, keep_alive: str | int, timeout_s: float,
                    deadline: float | None = None, options: dict[str, Any] | None = None) -> EmbedResult:
        self._check(model)
        cold = model not in self.loaded
        self.loaded[model] = 1
        self.calls.append(("embed", model))
        return EmbedResult(vectors=[_embed(t) for t in inputs], model=model, load_ms=20.0 if cold else 0.0)

    async def generate(self, model: str, *, keep_alive: str | int, timeout_s: float = 60.0,
                       deadline: float | None = None) -> dict[str, Any]:
        self._check(model)
        self.calls.append(("generate", model))
        if keep_alive == 0:
            self.loaded.pop(model, None)
            return {"model": model, "done": True, "done_reason": "unload"}
        self.loaded[model] = 1
        return {"model": model, "done": True}

    # --- diagnostic methods (used only when this mock stands in for the AdminClient in tests) ---
    async def ps(self) -> list[dict[str, Any]]:
        return [{"name": m, "model": m, "size": 0, "size_vram": 0, "digest": "mock"} for m in self.loaded]

    async def tags(self) -> list[dict[str, Any]]:
        names = sorted(self.available) if self.available else []
        return [{"name": n, "model": n, "digest": "mock", "details": {"quantization_level": "mock"}} for n in names]

    async def version(self) -> str | None:
        return "mock"

    async def unload(self, model: str) -> None:
        self.loaded.pop(model, None)
        self.calls.append(("unload", model))
