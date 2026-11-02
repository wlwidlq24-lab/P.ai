from __future__ import annotations

import asyncio
import threading

import pytest

from ragsec.config import get_settings
from ragsec.llm import MockLLMClient
from ragsec.logstore import JsonlWriter, read_jsonl
from ragsec.scheduler import ModelScheduler


def _profile():
    return get_settings().model_copy(update={"vram_profile": "vram_6gb"}).profile()


def test_plan_unloads_exclusive_model(tmp_path):
    sched = ModelScheduler(MockLLMClient(), _profile(), tmp_path / "locks")
    # 6GB profile: large model is exclusive -> must unload everything else
    assert set(sched.plan_unloads("exaone3.5:7.8b", ["exaone3.5:2.4b", "llama-guard3:1b"])) == {
        "exaone3.5:2.4b", "llama-guard3:1b"}
    # small + guard are coresident -> no unload needed
    assert sched.plan_unloads("exaone3.5:2.4b", ["llama-guard3:1b"]) == []


def test_scheduler_serializes_and_unloads_incompatible(tmp_path):
    client = MockLLMClient()
    sched = ModelScheduler(client, _profile(), tmp_path / "locks")

    async def run():
        async with sched.slot("exaone3.5:2.4b"):
            await client.chat("exaone3.5:2.4b", [{"role": "user", "content": "hi"}],
                              options={}, keep_alive="5m", timeout_s=10)
        # now switch to the exclusive large model: scheduler should unload the small one
        async with sched.slot("exaone3.5:7.8b") as info:
            assert "exaone3.5:2.4b" in info.unloaded
    asyncio.run(run())
    assert ("unload", "exaone3.5:2.4b") in client.calls


def test_concurrent_jsonl_writes_no_corruption(tmp_path):
    path = tmp_path / "log.jsonl"
    writer = JsonlWriter(path)
    n = 200

    def worker(i):
        writer.write({"i": i, "payload": "x" * (i % 50)})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    records, malformed = read_jsonl(path)
    assert malformed == 0
    assert sorted(r["i"] for r in records) == list(range(n))


def test_read_jsonl_tolerates_torn_line(tmp_path):
    path = tmp_path / "log.jsonl"
    path.write_text('{"a":1}\n{"b":2}\n{"c":', encoding="utf-8")  # last line torn
    records, malformed = read_jsonl(path)
    assert len(records) == 2
    assert malformed == 1
