"""Single GPU resource scheduler.

* All model calls go through `slot(model)`, which serializes them with an asyncio.Lock (in-process) AND a
  file lock (cross-process). An asyncio.Lock alone does not coordinate several uvicorn workers or a CLI
  runner sharing the GPU, hence the file lock.
* Before a call, residency is planned from the VRAM profile: models that may not co-reside with the target
  are unloaded via keep_alive=0 (through the permitted /api/generate endpoint). We never assume all fit.
* Residency is tracked INTERNALLY (the scheduler serializes every GPU call, so it knows what it has loaded).
  It does NOT query /api/ps at runtime — diagnostics are administrative and separated from the inference
  client. Cold start = the model was not in the tracked resident set before this slot.
  Limitation: tracking covers only models loaded via THIS scheduler in THIS process; a model loaded by
  another process or left resident from a previous run is unknown here (first use counts as cold). The
  cross-process file lock still serializes GPU access, but not residency knowledge.
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncIterator

from filelock import FileLock, Timeout

from .config import VramProfile
from .errors import DeadlineExceededError, ModelError
from .llm.base import LLMClient

log = logging.getLogger(__name__)


@dataclass
class SlotInfo:
    model: str
    is_cold: bool | None
    wait_ms: float
    unloaded: list[str] = field(default_factory=list)
    residents_before: list[str] | None = None


class ModelScheduler:
    def __init__(self, client: LLMClient, profile: VramProfile, lock_dir: Path, *, cpu_models: set[str] | None = None):
        self.client = client
        self.profile = profile
        self.cpu_models = cpu_models or set()
        self._lock = asyncio.Lock()
        lock_dir.mkdir(parents=True, exist_ok=True)
        # thread_local=False: acquire/release happen in different worker threads via asyncio.to_thread.
        self._file_lock = FileLock(str(lock_dir / "gpu.lock"), thread_local=False)
        self.switch_count = 0
        self._resident: set[str] = set()  # normalized model names this scheduler has loaded (not from /api/ps)

    def _compatible(self, a: str, b: str) -> bool:
        if a == b:
            return True
        if a in self.cpu_models or b in self.cpu_models:
            return True
        if a in self.profile.exclusive or b in self.profile.exclusive:
            return False
        return any(a in g and b in g for g in self.profile.coresident)

    def plan_unloads(self, target: str, residents: list[str]) -> list[str]:
        return [r for r in residents if not self._compatible(target, r)]

    @staticmethod
    def _norm(s: str) -> str:
        return s if ":" in s else f"{s}:latest"  # Ollama reports implicit :latest

    def _same(self, a: str, b: str) -> bool:
        return self._norm(a) == self._norm(b)

    @asynccontextmanager
    async def slot(self, model: str, *, deadline: float | None = None) -> AsyncIterator[SlotInfo]:
        t0 = time.perf_counter()
        timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        try:
            await asyncio.wait_for(self._lock.acquire(), timeout=timeout)
        except TimeoutError as e:
            raise DeadlineExceededError("deadline exceeded waiting for the GPU slot") from e
        file_locked = False
        try:
            remaining = -1 if deadline is None else max(0.0, deadline - time.monotonic())
            try:
                await asyncio.to_thread(self._file_lock.acquire, timeout=remaining)
                file_locked = True
            except Timeout as e:
                raise DeadlineExceededError("deadline exceeded waiting for cross-process GPU lock") from e
            wait_ms = (time.perf_counter() - t0) * 1000.0
            target = self._norm(model)
            residents = sorted(self._resident)
            is_cold = target not in self._resident
            unloaded: list[str] = []
            others = [r for r in self._resident if r != target]
            for r in self.plan_unloads(target, others):
                try:
                    await self.client.unload(r)
                except ModelError as e:
                    log.warning("unload of %s failed: %s", r, e)
                finally:
                    self._resident.discard(r)  # treat as unloaded even if the call errored (conservative)
                    unloaded.append(r)
            if is_cold:
                self.switch_count += 1
            self._resident.add(target)  # the imminent call will load it (keep_alive keeps it resident)
            yield SlotInfo(model=model, is_cold=is_cold, wait_ms=wait_ms, unloaded=unloaded,
                           residents_before=residents)
        finally:
            if file_locked:
                await asyncio.to_thread(self._file_lock.release)
            self._lock.release()

    async def unload_all(self) -> list[str]:
        """Unload every model this scheduler tracks as resident, so cold-start measurements start clean.

        Only models loaded via this scheduler are known; models left resident by other processes/runs are
        not unloaded here (documented limitation — provision/measurement should start from a fresh server)."""
        async with self._lock:
            await asyncio.to_thread(self._file_lock.acquire)
            try:
                residents = sorted(self._resident)
                for r in residents:
                    try:
                        await self.client.unload(r)
                    except ModelError as e:
                        log.warning("unload of %s failed: %s", r, e)
                self._resident.clear()
                return residents
            finally:
                await asyncio.to_thread(self._file_lock.release)
