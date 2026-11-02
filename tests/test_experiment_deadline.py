"""Global run deadline enforced DURING an in-flight request, with resource cleanup (ragsec/experiments.py)."""
from __future__ import annotations

import json
from pathlib import Path

from ragsec.config import Settings
from ragsec.experiments import dataset_content_hash
from ragsec.llm import MockLLMClient
from ragsec.schemas import (
    Case, CaseType, DatasetManifest, DocumentMetadataIn, DocumentKind, ExperimentManifest, GroundTruth, GuardMode,
    PiiGrade, QueryRequest, SourceType, TrustLevel,
)
from ragsec.services import build_services
from ragsec.timeutil import utc_now

AVAIL = {"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}


def _make_dataset(root: Path) -> None:
    (root / "documents").mkdir(parents=True)
    (root / "documents" / "d1.txt").write_text("요약 대상 문서입니다. 수수료 안내.", encoding="utf-8")
    meta = DocumentMetadataIn(document_id="d1", document_version=1, source_name="w",
                             source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
                             document_kind=DocumentKind.BUSINESS_DOCUMENT, pii_grade=PiiGrade.NONE,
                             tenant_id="bank_a", allowed_roles=["general_staff"])
    (root / "documents.jsonl").write_text(json.dumps({**meta.model_dump(mode="json"), "file": "d1.txt"},
                                          ensure_ascii=False) + "\n", encoding="utf-8")
    # one benign case whose query forces the mock to hang at generation (__MOCK_TIMEOUT__)
    case = Case(case_id="c1", lineage_id="L1", split="dev", case_type=CaseType.BENIGN, language="ko",
                user_id="u_staff_a", query="__MOCK_TIMEOUT__ 요약", ground_truth=GroundTruth(is_attack=False))
    (root / "cases.jsonl").write_text(case.model_dump_json() + "\n", encoding="utf-8")
    ch = dataset_content_hash(root)
    man = DatasetManifest(dataset_id="ds", dataset_version="1.0.0", generator="test", generator_seed=1,
                          created_at=utc_now(), content_hash=ch, n_documents=1, n_cases=1, split_counts={"dev": 1})
    (root / "dataset_manifest.json").write_text(man.model_dump_json(), encoding="utf-8")


async def test_run_deadline_cancels_in_flight_and_cleans_up(tmp_path):
    _make_dataset(tmp_path / "ds")
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root=tmp_path,
                 api_key="test-key-123456", vram_profile="vram_6gb", llm_call_timeout_s=30, request_deadline_s=60,
                 max_distance=2.0)  # permissive retrieval so the doc is always retrieved and generation is reached
    svc = build_services(s, client=MockLLMClient(available=AVAIL))
    m = ExperimentManifest(experiment_id="deadline-test", dataset_dir="ds", splits=["dev"],
                           case_types=[CaseType.BENIGN], guard_modes=[GuardMode.OFF],
                           target_models=["exaone3.5:2.4b"], repetitions=1, warmup_requests=0,
                           cold_start_samples=0, max_run_seconds=1, require_reviewed_attacks=False)
    job = svc.jobs.submit(m)
    await job.task  # the single unit hangs ~31s; wait_for cancels it at the ~1s budget (large, non-fragile margin)

    assert job.status == "completed"                       # loop ended via stop, not an unhandled failure
    assert job.error and "in-flight" in job.error          # explicit stop reason
    assert job.done == 0                                    # the hung request was not completed/logged
    assert (job.dir / "stop_reason.txt").exists()

    # cleanup: the scheduler/GPU lock was released by cancellation -> a fresh normal request still runs
    resp = await svc.rag.answer(QueryRequest(user_id="u_staff_a", query="요약", guard_mode=GuardMode.OFF))
    assert resp.status == "ok"
    await svc.aclose()
