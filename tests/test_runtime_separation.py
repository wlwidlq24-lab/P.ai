"""Diagnostics-vs-runtime separation and hardening-independent-of-guard-mode tests."""
from __future__ import annotations

import asyncio

from ragsec.config import get_settings
from ragsec.llm import MockLLMClient
from ragsec.scheduler import ModelScheduler


def _profile():
    return get_settings().model_copy(update={"vram_profile": "vram_6gb"}).profile()


def test_scheduler_never_calls_ps(tmp_path):
    client = MockLLMClient()
    sched = ModelScheduler(client, _profile(), tmp_path / "locks")

    async def run():
        async with sched.slot("exaone3.5:2.4b") as info:
            assert info.is_cold is True  # first use is cold (internal tracking, not /api/ps)
            await client.chat("exaone3.5:2.4b", [{"role": "user", "content": "hi"}], options={},
                              keep_alive="5m", timeout_s=10)
        async with sched.slot("exaone3.5:2.4b") as info2:
            assert info2.is_cold is False  # now tracked resident
    asyncio.run(run())
    # the scheduler must never have issued a diagnostic ps() call
    assert all(kind != "ps" for kind, _ in client.calls)


def test_scheduler_unload_uses_generate_endpoint(tmp_path):
    client = MockLLMClient()
    sched = ModelScheduler(client, _profile(), tmp_path / "locks")

    async def run():
        async with sched.slot("exaone3.5:2.4b"):
            pass
        async with sched.slot("exaone3.5:7.8b") as info:  # exclusive in 6gb -> unloads the small model
            assert "exaone3.5:2.4b:latest" in info.unloaded or "exaone3.5:2.4b" in info.unloaded
    asyncio.run(run())
    # unload is routed through generate() (keep_alive=0), a permitted endpoint
    assert ("generate", "exaone3.5:2.4b") in client.calls or ("unload", "exaone3.5:2.4b") in client.calls


def test_hardening_active_regardless_of_guard_mode(services):
    """The runtime client's endpoint allowlist is structural and independent of guard mode (incl. OFF)."""
    from ragsec.llm.ollama import OllamaClient, RUNTIME_ALLOWLIST
    # OFF mode does not loosen the allowlist; forbidden endpoints are never present in it.
    for forbidden in [("POST", "/api/pull"), ("POST", "/api/create"), ("GET", "/api/tags")]:
        assert forbidden not in RUNTIME_ALLOWLIST
    # services runtime client exposes no diagnostics/management methods
    assert not hasattr(services.client, "pull")
    assert not hasattr(services.client, "create")
