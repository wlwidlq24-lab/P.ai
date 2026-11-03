"""Dataset loading, run planning (counterbalanced), background job execution and status tracking.

Rerunning: POST the same manifest again. The plan is a deterministic function of (manifest, dataset hash),
so a rerun executes identical (case, condition, repetition) units in the identical order under a new run_id.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .config import Settings
from .errors import DatasetError, JobNotFoundError
from .hardware import hardware_snapshot, package_versions
from .ingestion import IngestItem, Ingestor
from .logstore import JsonlWriter, read_jsonl
from .metrics import aggregate, write_outputs
from .parsing import parse_document
from .policy import PolicyBundle
from .rag import ExperimentContext, RagService
from .scheduler import ModelScheduler
from .schemas import (
    Case, CaseType, ConditionKey, DatasetManifest, DocumentMetadataIn, ExperimentManifest, GuardMode,
    ModelProvenance, OrderStrategy, QueryRequest, RunManifestRecord,
)
from .textproc import sha256_bytes
from .timeutil import utc_now

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------- dataset
@dataclass
class Dataset:
    root: Path
    manifest: DatasetManifest
    documents: list[tuple[DocumentMetadataIn, Path]]
    cases: list[Case]


def dataset_content_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted([root / "documents.jsonl", root / "cases.jsonl", *sorted((root / "documents").glob("*"))]):
        h.update(p.relative_to(root).as_posix().encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def resolve_dataset_dir(settings: Settings, rel: str) -> Path:
    base = settings.dataset_root.resolve()
    p = (base / rel).resolve()
    if base not in p.parents and p != base:
        raise DatasetError("dataset_dir escapes dataset_root")
    if not (p / "dataset_manifest.json").exists():
        raise DatasetError(f"no dataset_manifest.json in {rel}")
    return p


def load_dataset(root: Path, verify_hash: bool = True) -> Dataset:
    manifest = DatasetManifest.model_validate_json((root / "dataset_manifest.json").read_text(encoding="utf-8"))
    if verify_hash:
        actual = dataset_content_hash(root)
        if actual != manifest.content_hash:
            raise DatasetError("dataset content hash mismatch (files changed after generation)",
                               detail={"expected": manifest.content_hash, "actual": actual})
    docs: list[tuple[DocumentMetadataIn, Path]] = []
    for line in (root / "documents.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            obj = json.loads(line)
            fname = obj.pop("file")
            path = (root / "documents" / fname).resolve()
            if (root / "documents").resolve() not in path.parents:
                raise DatasetError(f"document path escapes dataset: {fname}")
            docs.append((DocumentMetadataIn.model_validate(obj), path))
    cases = [Case.model_validate_json(l) for l in (root / "cases.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    ids = [c.case_id for c in cases]
    if len(ids) != len(set(ids)):
        raise DatasetError("duplicate case_id")
    # Lineage isolation: one lineage must never span multiple splits.
    lin_split: dict[str, str] = {}
    for c in cases:
        if lin_split.setdefault(c.lineage_id, c.split) != c.split:
            raise DatasetError(f"lineage {c.lineage_id} appears in multiple splits")
    return Dataset(root=root, manifest=manifest, documents=docs, cases=cases)


async def ingest_dataset(ds: Dataset, ingestor: Ingestor, policies: PolicyBundle, settings: Settings,
                         run_llama_guard: bool = True):
    items = []
    for meta, path in ds.documents:
        data = await asyncio.to_thread(path.read_bytes)
        parsed = await asyncio.to_thread(parse_document, data, path.name, max_bytes=settings.max_upload_bytes,
                                         max_pages=settings.max_pdf_pages, max_chars=settings.max_extracted_chars,
                                         min_chars_per_page=settings.min_chars_per_page_for_text_pdf)
        items.append(IngestItem(meta=meta, parsed=parsed))
    return await ingestor.ingest(items, policies, run_llama_guard=run_llama_guard, fresh=True,
                                 note=f"dataset {ds.manifest.dataset_id}@{ds.manifest.dataset_version}")


# ----------------------------------------------------------------------------- planning
@dataclass(frozen=True)
class Unit:
    order_index: int
    case: Case
    condition: ConditionKey
    repetition: int


def select_cases(ds: Dataset, m: ExperimentManifest) -> list[Case]:
    cases = [c for c in ds.cases if c.split in m.splits and c.case_type in m.case_types]
    if m.case_ids:
        wanted = set(m.case_ids)
        cases = [c for c in cases if c.case_id in wanted]
    cases.sort(key=lambda c: c.case_id)
    if m.max_cases:
        rng = random.Random(m.seed)
        cases = sorted(rng.sample(cases, min(m.max_cases, len(cases))), key=lambda c: c.case_id)
    return cases


def conditions(m: ExperimentManifest) -> list[ConditionKey]:
    out = []
    for model in m.target_models:
        for acm in m.access_control_modes:
            for mode in m.guard_modes:
                for st in m.stage_sets:
                    if mode == GuardMode.OFF and st != m.stage_sets[0]:
                        continue  # stage sets are irrelevant when no plugins run
                    out.append(ConditionKey(target_model=model, guard_mode=mode, stages=st, access_control_mode=acm))
    return out


def plan(m: ExperimentManifest, cases: list[Case]) -> list[Unit]:
    """Blocks = (target_model, repetition, case). Within a block the remaining conditions are shuffled
    (randomized_blocks), so every case is measured under every condition, adjacent in time, in varying order.
    Target models are kept in contiguous blocks to avoid a model switch per request on limited VRAM."""
    rng = random.Random(m.seed)
    conds = conditions(m)
    units: list[Unit] = []
    i = 0
    for model in m.target_models:
        mconds = [c for c in conds if c.target_model == model]
        for rep in range(m.repetitions):
            order = list(cases)
            if m.order_strategy == OrderStrategy.RANDOMIZED_BLOCKS:
                rng.shuffle(order)
            for case in order:
                block = list(mconds)
                if m.order_strategy == OrderStrategy.RANDOMIZED_BLOCKS:
                    rng.shuffle(block)
                for cond in block:
                    units.append(Unit(order_index=i, case=case, condition=cond, repetition=rep))
                    i += 1
    return units


def manifest_hash(m: ExperimentManifest) -> str:
    return hashlib.sha256(m.model_dump_json().encode()).hexdigest()


# ----------------------------------------------------------------------------- jobs
@dataclass
class Job:
    experiment_id: str
    run_id: str
    dir: Path
    status: str = "pending"  # pending | running | completed | failed | cancelled
    total: int = 0
    done: int = 0
    errors: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    task: asyncio.Task | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {"experiment_id": self.experiment_id, "run_id": self.run_id, "status": self.status,
                "total": self.total, "done": self.done, "errors": self.errors, "started_at": self.started_at,
                "finished_at": self.finished_at, "error": self.error,
                "log_file": str(self.dir / "requests.jsonl"), "metrics_file": str(self.dir / "metrics.json")}

    def persist(self) -> None:
        tmp = self.dir / "status.json.tmp"
        tmp.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.dir / "status.json")


class JobManager:
    """In-process background jobs. Run the API with ONE uvicorn worker: job state lives in this process
    (status.json is persisted for inspection, but other workers cannot cancel a job they do not own)."""

    def __init__(self, settings: Settings, rag: RagService, ingestor: Ingestor, scheduler: ModelScheduler,
                 policies: Callable[[], PolicyBundle], provenance: Callable[[str], ModelProvenance],
                 ollama_version: Callable[[], str | None], admin_probe=None, vram_probe=None):
        self.s = settings
        self.rag = rag
        self.ingestor = ingestor
        self.scheduler = scheduler
        self.policies = policies
        self.provenance = provenance
        self.ollama_version = ollama_version
        # Administrative, run-once hooks that build the pre-run manifest via the ADMIN diagnostics client.
        self.admin_probe = admin_probe       # async () -> populates provenance snapshot (version + digests)
        self.vram_probe = vram_probe         # async () -> VramSample measured once before the run
        self.jobs: dict[str, Job] = {}
        self._run_lock = asyncio.Lock()  # one experiment at a time (GPU is serialized anyway)

    def get(self, job_id: str) -> Job:
        if job_id in self.jobs:
            return self.jobs[job_id]
        for j in self.jobs.values():
            if j.experiment_id == job_id:
                return j
        # Completed runs from earlier processes: read persisted status.
        for st in sorted(self.s.log_dir.glob(f"*/{job_id}/status.json")) + sorted(self.s.log_dir.glob(f"{job_id}/*/status.json")):
            d = json.loads(st.read_text(encoding="utf-8"))
            return Job(experiment_id=d["experiment_id"], run_id=d["run_id"], dir=st.parent, status=d["status"],
                       total=d["total"], done=d["done"], errors=d["errors"], started_at=d["started_at"],
                       finished_at=d["finished_at"], error=d["error"])
        raise JobNotFoundError(f"no experiment run {job_id!r}")

    def submit(self, m: ExperimentManifest) -> Job:
        run_id = f"run-{utc_now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"
        d = self.s.log_dir / m.experiment_id / run_id
        d.mkdir(parents=True, exist_ok=True)
        job = Job(experiment_id=m.experiment_id, run_id=run_id, dir=d)
        job.persist()
        self.jobs[run_id] = job
        job.task = asyncio.create_task(self._run(job, m), name=f"experiment-{run_id}")
        return job

    def cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        if job.task and not job.task.done():
            job.task.cancel()
        return job

    async def _run(self, job: Job, m: ExperimentManifest) -> None:
        async with self._run_lock:
            job.status, job.started_at = "running", utc_now().isoformat()
            job.persist()
            try:
                await self._execute(job, m)
                job.status = "completed"
            except asyncio.CancelledError:
                job.status = "cancelled"
            except Exception as e:  # recorded; never swallowed silently
                log.exception("experiment %s failed", job.run_id)
                job.status, job.error = "failed", f"{type(e).__name__}: {e}"
            finally:
                job.finished_at = utc_now().isoformat()
                job.persist()
                try:  # metrics over whatever completed (partial runs are labelled by status)
                    recs, malformed = read_jsonl(job.dir / "requests.jsonl")
                    if recs:
                        agg = aggregate(recs)
                        agg["run_status"] = job.status
                        agg["malformed_log_lines"] = malformed
                        write_outputs(agg, job.dir)
                except Exception:
                    log.exception("metric aggregation failed for %s", job.run_id)

    async def _execute(self, job: Job, m: ExperimentManifest) -> None:
        ds = load_dataset(resolve_dataset_dir(self.s, m.dataset_dir))
        policies = self.policies()
        ing = await ingest_dataset(ds, self.ingestor, policies, self.s)
        if ing.validation_errors:
            raise DatasetError("index validation failed", detail={"errors": ing.validation_errors})
        cases = select_cases(ds, m)
        if not cases:
            raise DatasetError("no cases selected by manifest")
        # Readiness gate: refuse to run selected ATTACK cases that are not reviewed+eligible, so placeholders are
        # never executed as an efficacy experiment. Benign controls are always allowed.
        if m.require_reviewed_attacks:
            unreviewed = [c.case_id for c in cases if c.case_type == CaseType.ATTACK
                          and not (c.evaluation_eligible and c.review is not None and c.review.status == "reviewed")]
            if unreviewed:
                raise DatasetError(
                    "manifest selects unreviewed/ineligible attack cases; set require_reviewed_attacks=false ONLY "
                    "for a plumbing (non-efficacy) run",
                    detail={"unreviewed_attack_cases": unreviewed[:20], "n_unreviewed": len(unreviewed)})
        units = plan(m, cases)
        job.total = len(units)
        # PRE-RUN manifest: populate model provenance (version + digests) and a one-time VRAM measurement via
        # the ADMIN diagnostics client. This is the only diagnostics touchpoint; per-request code never probes.
        vram_pre = None
        if self.admin_probe is not None:
            try:
                await self.admin_probe()
            except Exception as e:  # diagnostics are best-effort; the run proceeds with null provenance
                log.warning("pre-run admin probe failed: %s", e)
        if self.vram_probe is not None:
            try:
                vram_pre = await self.vram_probe()
            except Exception as e:
                log.warning("pre-run vram probe failed: %s", e)
        models = {name: self.provenance(name) for name in {*m.target_models, self.s.guard_model, self.s.embedding_model}}
        hw = hardware_snapshot()
        if vram_pre is not None:
            hw["ollama_vram_pre_run"] = vram_pre.model_dump()
        (job.dir / "manifest.json").write_text(m.model_dump_json(indent=2), encoding="utf-8")
        run_rec = RunManifestRecord(
            experiment_id=m.experiment_id, run_id=job.run_id, manifest=m, manifest_hash=manifest_hash(m),
            dataset=ds.manifest, settings_snapshot=self.s.model_dump(mode="json", exclude={"api_key", "gemini_api_key"}),
            models=models, ollama_version=self.ollama_version(), policy_versions=policies.versions,
            active_index_version=ing.index_version, hardware=hw, python_packages=package_versions(),
            started_at=utc_now(), planned_requests=len(units))
        (job.dir / "run_manifest.json").write_text(run_rec.model_dump_json(indent=2), encoding="utf-8")
        (job.dir / "plan.jsonl").write_text("\n".join(json.dumps(
            {"order_index": u.order_index, "case_id": u.case.case_id, "condition": u.condition.label(),
             "repetition": u.repetition}) for u in units) + "\n", encoding="utf-8")
        job.persist()

        main_w = JsonlWriter(job.dir / "requests.jsonl")
        warm_w = JsonlWriter(job.dir / "warmup.jsonl")
        cold_w = JsonlWriter(job.dir / "coldstart.jsonl")
        common = dict(experiment_id=m.experiment_id, run_id=job.run_id, dataset_version=ds.manifest.dataset_version,
                      dataset_hash=ds.manifest.content_hash, judge_enabled=m.judge_enabled)

        def req_for(u_case: Case, cond: ConditionKey) -> QueryRequest:
            # recipient/purpose/channel are OPERATIONAL request facts (who/why/how), not the evaluation oracle;
            # the trusted disclosure policy decides from them. The oracle (allowed/prohibited atoms) is NOT passed.
            az = u_case.authorization
            return QueryRequest(user_id=u_case.user_id, query=u_case.query, subject_id=u_case.subject_id,
                                guard_mode=cond.guard_mode, stages=cond.stages, target_model=cond.target_model,
                                access_control_mode=cond.access_control_mode, normalization=m.normalization,
                                case_id=u_case.case_id, tool_egress=m.tool_egress,
                                markdown_image_egress=m.markdown_image_egress,
                                recipient=(az.recipient if az else None), purpose=(az.permitted_purpose if az else None),
                                channel=(az.channel if az else None), enforcement_profile=m.enforcement_profile)

        for model in m.target_models:
            probe = cases[0]
            cond = ConditionKey(target_model=model, guard_mode=GuardMode.OFF, stages=m.stage_sets[0],
                                access_control_mode=m.access_control_modes[0])
            for k in range(m.cold_start_samples):
                await self.scheduler.unload_all()
                await self.rag.answer(req_for(probe, cond), ExperimentContext(case=probe, repetition=k, order_index=-1,
                                                                              log_writer=cold_w, **common))
            for k in range(m.warmup_requests):
                await self.rag.answer(req_for(probe, cond), ExperimentContext(case=probe, repetition=k, order_index=-1,
                                                                              log_writer=warm_w, **common))
        stop_reason = None
        run_start = time.monotonic()
        for u in units:
            if m.max_requests is not None and job.done >= m.max_requests:
                stop_reason = f"max_requests={m.max_requests} reached"
                break
            async def _answer_unit():
                return await self.rag.answer(req_for(u.case, u.condition), ExperimentContext(
                    case=u.case, repetition=u.repetition, order_index=u.order_index, log_writer=main_w, **common))
            if m.max_run_seconds is not None:
                # Propagate the REMAINING run budget into the in-flight request: if the overall deadline expires
                # mid-request, wait_for cancels it (scheduler slots release via their async context managers; the
                # abandoned request is not logged, prior records are preserved) and the run stops.
                remaining = m.max_run_seconds - (time.monotonic() - run_start)
                if remaining <= 0:
                    stop_reason = f"max_run_seconds={m.max_run_seconds} reached after {job.done} requests"
                    break
                try:
                    resp = await asyncio.wait_for(_answer_unit(), timeout=remaining)
                except asyncio.TimeoutError:
                    stop_reason = (f"max_run_seconds={m.max_run_seconds} exceeded DURING an in-flight request "
                                   f"after {job.done} completed requests")
                    break
            else:
                resp = await _answer_unit()
            job.done += 1
            job.errors += resp.status != "ok"
            if m.max_errors is not None and job.errors >= m.max_errors:
                stop_reason = f"max_errors={m.max_errors} reached after {job.done} requests"
                break
            if job.done % 5 == 0 or job.done == job.total:
                job.persist()
        if stop_reason:
            job.error = f"stopped: {stop_reason} (partial results preserved)"
            log.warning("experiment %s %s", job.run_id, job.error)
            (job.dir / "stop_reason.txt").write_text(stop_reason, encoding="utf-8")


def dataset_file_hash(path: Path) -> str:
    return sha256_bytes(path.read_bytes())
