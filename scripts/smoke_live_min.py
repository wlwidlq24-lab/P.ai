"""Minimal, bounded LIVE smoke test (real Ollama): ingest one benign doc + one OFF query.

System check only (plumbing of embed + generate against the local models). NOT attack-efficacy evidence.
Guard is skipped at ingestion to keep the budget small. Run: uv run python scripts/smoke_live_min.py
"""
from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

from ragsec.config import Settings
from ragsec.ingestion import IngestItem
from ragsec.parsing import ParsedDocument
from ragsec.schemas import DocumentKind, DocumentMetadataIn, GuardMode, PiiGrade, QueryRequest, SourceType, TrustLevel
from ragsec.services import build_services


async def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="ragsec_live_"))
    s = Settings(llm_backend="ollama", data_dir=tmp / "var", policy_dir="policies", dataset_root="data",
                 vram_profile="vram_6gb", llm_call_timeout_s=120, request_deadline_s=150, guard_call_timeout_s=60)
    svc = build_services(s)
    try:
        item = IngestItem(meta=DocumentMetadataIn(
            document_id="live_fee", document_version=1, source_name="수수료 안내",
            source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
            document_kind=DocumentKind.BUSINESS_DOCUMENT, pii_grade=PiiGrade.NONE, tenant_id="bank_a",
            allowed_roles=["general_staff"]),
            parsed=ParsedDocument(text="[안내]\n타행 이체 수수료는 건당 1,000원입니다.", file_type="txt",
                                  safe_filename="fee.txt"))
        t0 = time.monotonic()
        res = await svc.ingestor.ingest([item], svc.policies(), run_llama_guard=False)
        print(f"[live] ingest: activated={res.activated} embed_ms={res.embed_ms:.0f} "
              f"elapsed={time.monotonic() - t0:.1f}s", flush=True)
        t1 = time.monotonic()
        resp = await svc.rag.answer(QueryRequest(user_id="u_staff_a", query="타행 이체 수수료는 얼마인가요?",
                                                 guard_mode=GuardMode.OFF))
        print(f"[live] query: status={resp.status} blocked={resp.blocked} model={resp.target_model} "
              f"elapsed={time.monotonic() - t1:.1f}s", flush=True)
        print(f"[live] answer[:120]={resp.answer[:120]!r}", flush=True)
        print(f"[live] timings_ms={ {k: round(v) for k, v in resp.timings.model_dump().items() if v} }", flush=True)
        ok = resp.status == "ok"
        print("[live] LIVE SMOKE " + ("PASSED" if ok else "FAILED") + " (plumbing only, not efficacy)", flush=True)
        return 0 if ok else 1
    finally:
        await svc.aclose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
