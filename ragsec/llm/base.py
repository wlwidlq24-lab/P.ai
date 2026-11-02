"""Model-serving client protocol shared by the Ollama client and the offline mock."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ChatResult:
    text: str
    model: str
    load_ms: float | None = None
    total_ms: float | None = None
    prompt_eval_count: int | None = None
    eval_count: int | None = None
    done_reason: str | None = None
    retries: int = 0
    raw_meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class EmbedResult:
    vectors: list[list[float]]
    model: str
    load_ms: float | None = None
    total_ms: float | None = None
    retries: int = 0


class LLMClient(Protocol):
    """RUNTIME inference client. Deliberately has NO diagnostics (ps/tags/version) and NO model management;
    those live only in the separate AdminClient (llm/admin.py)."""

    async def chat(self, model: str, messages: list[dict[str, str]], *, options: dict[str, Any],
                   keep_alive: str | int, timeout_s: float, deadline: float | None = None,
                   think: bool | None = None) -> ChatResult: ...

    async def embed(self, model: str, inputs: list[str], *, keep_alive: str | int, timeout_s: float,
                    deadline: float | None = None, options: dict[str, Any] | None = None) -> EmbedResult: ...

    async def generate(self, model: str, *, keep_alive: str | int, timeout_s: float = 60.0,
                       deadline: float | None = None) -> dict[str, Any]: ...

    async def unload(self, model: str) -> None: ...

    async def aclose(self) -> None: ...


class AdminClient(Protocol):
    """Read-only diagnostics client, used only administratively (never by request handlers / RAG)."""

    async def version(self) -> str | None: ...

    async def tags(self) -> list[dict[str, Any]]: ...

    async def ps(self) -> list[dict[str, Any]]: ...

    async def aclose(self) -> None: ...
