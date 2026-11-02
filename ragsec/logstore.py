"""Concurrency-safe JSONL logging and the opt-in raw-artifact store.

* Each record is serialized fully BEFORE taking the lock and written with a single write() call, then
  flushed and fsync'ed. A thread lock serializes writers in-process; a file lock serializes processes.
* Readers tolerate a torn trailing line (crash mid-write) and report how many lines were skipped.
* Ordinary logs never contain raw PII or full prompts. Raw artifacts go to a separate, opt-in store
  with a retention period enforced by `purge_expired`.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Iterator

from filelock import FileLock
from pydantic import BaseModel


class JsonlWriter:
    _locks: dict[str, threading.Lock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self._locks_guard:
            self._lock = self._locks.setdefault(str(path.resolve()), threading.Lock())
        self._flock = FileLock(str(path) + ".lock", thread_local=False)

    def write(self, record: BaseModel | dict[str, Any]) -> None:
        if isinstance(record, BaseModel):
            line = record.model_dump_json()
        else:
            line = json.dumps(record, ensure_ascii=False, default=str)
        if "\n" in line:
            raise ValueError("serialized record contains a newline")
        data = (line + "\n").encode("utf-8")
        with self._lock, self._flock:
            with self.path.open("ab") as f:
                # Repair a torn previous line so this record starts on its own line.
                if f.tell() > 0:
                    with self.path.open("rb") as r:
                        r.seek(-1, os.SEEK_END)
                        if r.read(1) != b"\n":
                            f.write(b"\n")
                f.write(data)
                f.flush()
                os.fsync(f.fileno())


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    malformed = 0
    if not path.exists():
        return records, 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if isinstance(obj, dict):
                records.append(obj)
            else:
                malformed += 1
    return records, malformed


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    recs, _ = read_jsonl(path)
    yield from recs


class RawArtifactStore:
    """Opt-in store for full prompts/outputs needed for exact reproduction. Synthetic data only."""

    def __init__(self, root: Path, enabled: bool, retention_days: int):
        self.root = root
        self.enabled = enabled
        self.retention_s = retention_days * 86400

    def put(self, run_id: str, request_id: str, payload: dict[str, Any]) -> str | None:
        if not self.enabled:
            return None
        d = self.root / run_id
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{request_id}.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps({"stored_at": time.time(), **payload}, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
        return str(p.relative_to(self.root))

    def purge_expired(self) -> int:
        if not self.root.exists():
            return 0
        now = time.time()
        n = 0
        for d in self.root.iterdir():
            if d.is_dir() and now - d.stat().st_mtime > self.retention_s:
                shutil.rmtree(d, ignore_errors=True)
                n += 1
        return n
