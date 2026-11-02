"""Time helpers. Wall-clock timestamps are timezone-aware UTC; durations use a monotonic clock."""
from __future__ import annotations

import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator
from zoneinfo import ZoneInfo

KST = ZoneInfo("Asia/Seoul")
# Sentinels used in Chroma metadata for open-ended effective intervals (Chroma rejects None).
FAR_PAST_TS = 0                 # 1970-01-01T00:00:00Z
FAR_FUTURE_TS = 253402300799    # 9999-12-31T23:59:59Z


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(dt: datetime) -> datetime:
    """Naive datetimes are interpreted as Korea Standard Time (documented assumption for KR documents)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=KST)
    return dt


def to_epoch(dt: datetime) -> int:
    return int(ensure_aware(dt).timestamp())


class Stopwatch:
    """Accumulates named durations in milliseconds using time.perf_counter()."""

    def __init__(self) -> None:
        self.durations: dict[str, float] = {}
        self._t0 = time.perf_counter()

    @contextmanager
    def measure(self, name: str) -> Iterator[None]:
        t = time.perf_counter()
        try:
            yield
        finally:
            self.durations[name] = self.durations.get(name, 0.0) + (time.perf_counter() - t) * 1000.0

    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self._t0) * 1000.0
