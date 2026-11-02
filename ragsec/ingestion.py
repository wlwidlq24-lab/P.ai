"""Document ingestion: parse -> views -> whole-document checks -> chunk -> batch embed -> staging index.

Whole-document PII detection runs on the full normalized text and is mapped back to every chunk whose
span overlaps a match, so PII split across a chunk boundary is attributed to both chunks.
Ingestion-time detectors only record flags; per-mode enforcement happens at retrieval (see guards.modes).
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass, field

from .config import Settings
from .errors import IndexValidationError
from .guards.base import InspectionContext
from .guards.ipi import IpiRulePlugin
from .guards.llama_guard import LlamaGuardPlugin
from .guards.pii import detect_pii
from .legalseg import segment_document
from .llm.base import LLMClient
from .parsing import ParsedDocument, page_for_offset
from .policy import PolicyBundle
from .scheduler import ModelScheduler
from .schemas import (
    Artifact, ArtifactKind, ChunkMetadata, DocumentKind, DocumentMetadataIn, HookStage, IngestionFlags,
    NormalizationOptions, PiiType,
)
from .tenants import TenantRegistry
from .store import ChromaRepository
from .textproc import normalize, sha256_text
from .timeutil import utc_now

log = logging.getLogger(__name__)


@dataclass
class IngestItem:
    meta: DocumentMetadataIn
    parsed: ParsedDocument


@dataclass
class IngestResult:
    ingestion_run_id: str
    index_version: str | None
    activated: bool
    documents: list[dict] = field(default_factory=list)
    skipped_duplicates: list[str] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    embed_ms: float = 0.0


class Ingestor:
    def __init__(self, settings: Settings, client: LLMClient, scheduler: ModelScheduler, repo: ChromaRepository,
                 guard_plugin: LlamaGuardPlugin | None):
        self.s = settings
        self.client = client
        self.scheduler = scheduler
        self.repo = repo
        self.ipi = IpiRulePlugin()
        self.guard_plugin = guard_plugin
        self._lock = asyncio.Lock()  # one index build at a time per process

    async def embed_batched(self, texts: list[str]) -> tuple[list[list[float]], float]:
        prof = self.s.profile()
        vecs: list[list[float]] = []
        total = 0.0
        for i in range(0, len(texts), prof.embed_batch_size):
            async with self.scheduler.slot(self.s.embedding_model):
                res = await self.client.embed(self.s.embedding_model, texts[i:i + prof.embed_batch_size],
                                              keep_alive=prof.keep_alive, timeout_s=self.s.llm_call_timeout_s,
                                              options={"num_gpu": 0} if prof.embed_on_cpu else None)
            vecs.extend(res.vectors)
            total += res.total_ms or 0.0
        dims = {len(v) for v in vecs}
        if len(dims) > 1:
            raise IndexValidationError(f"embedding model returned mixed dimensions {sorted(dims)}")
        return vecs, total

    async def ingest(self, items: list[IngestItem], policies: PolicyBundle, *, auto_activate: bool = True,
                     run_llama_guard: bool = True, note: str = "", fresh: bool = False) -> IngestResult:
        async with self._lock:
            return await self._ingest(items, policies, auto_activate=auto_activate,
                                      run_llama_guard=run_llama_guard, note=note, fresh=fresh)

    async def _ingest(self, items: list[IngestItem], policies: PolicyBundle, *, auto_activate: bool,
                      run_llama_guard: bool, note: str, fresh: bool) -> IngestResult:
        run_id = f"ing-{utc_now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3)}"
        result = IngestResult(ingestion_run_id=run_id, index_version=None, activated=False)
        # fresh=True builds a self-contained index from empty (reproducible per-dataset experiment rebuild);
        # the active index is neither consulted for de-duplication nor used as the staging base.
        active = None if fresh else await asyncio.to_thread(self.repo.active_version)

        # 1. Validate against policy and drop idempotent duplicates (same id, version and content hash).
        todo: list[tuple[IngestItem, str]] = []
        registry = TenantRegistry.from_policies(policies, self.s.disabled_tenants)
        for it in items:
            m = it.meta
            # Reject unknown AND disabled tenants (configurable registry), not just "not in policy".
            registry.assert_enabled(m.tenant_id)
            unknown = [r for r in m.allowed_roles if r not in policies.access.roles]
            if unknown:
                raise IndexValidationError(f"{m.document_id}: roles {unknown} not in access policy")
            doc_hash = sha256_text(it.parsed.text)
            if active:
                existing = await asyncio.to_thread(self.repo.document_versions, active, m.document_id)
                if any(int(e["document_version"]) == m.document_version and e["document_content_hash"] == doc_hash
                       for e in existing):
                    result.skipped_duplicates.append(m.document_id)
                    continue
                if any(int(e["document_version"]) == m.document_version and e["document_content_hash"] != doc_hash
                       for e in existing):
                    raise IndexValidationError(
                        f"{m.document_id} v{m.document_version} already indexed with different content; bump document_version")
                if any(int(e["document_version"]) > m.document_version for e in existing):
                    raise IndexValidationError(f"{m.document_id}: a newer version is already active")
            todo.append((it, doc_hash))
        if not todo:
            result.index_version = active
            return result

        # 2. Chunk, whole-document scans, ingestion detectors.
        ids, texts_for_embed, docs, metas = [], [], [], []
        ctx = InspectionContext(request_id=run_id, stage=HookStage.INGESTION, user=None, role_policy=None,
                                guard_policy=policies.guard, normalization=NormalizationOptions())
        lg_available = run_llama_guard and self.guard_plugin is not None
        for it, doc_hash in todo:
            m = it.meta
            text = it.parsed.text
            nt = normalize(text)
            doc_pii = [(nt.original_span(p.start, p.end), p.pii_type) for p in detect_pii(nt.text)]
            use_article = (self.s.article_aware_chunking
                           and m.document_kind in (DocumentKind.LEGISLATION, DocumentKind.INTERNAL_POLICY))
            spans, fb_reason = segment_document(text, self.s.chunk_size, self.s.chunk_overlap,
                                                article_aware=use_article)
            created = utc_now()
            for sp in spans:
                c_norm = normalize(sp.text).text
                art = Artifact(artifact_id=f"{m.document_id}#c{sp.index}", kind=ArtifactKind.CHUNK, original=sp.text,
                               normalized=c_norm, trust=m.source_trust_level)
                ipi_res = await self.ipi.inspect(ctx, art)
                ipi_score = next((f.score for f in ipi_res.findings if f.category == "ipi.score"), 0.0)
                lg_flag = -1
                if lg_available:
                    try:
                        unsafe, _ = await self.guard_plugin.classify([{"role": "user", "content": c_norm}], None)
                        lg_flag = int(unsafe)
                    except Exception as e:  # recorded as not evaluated (-1); never silently 0
                        log.warning("llama guard at ingestion failed for %s: %s", art.artifact_id, e)
                detected = sorted({t for (s, e), t in doc_pii if s < sp.end and sp.start < e}, key=lambda t: t.value)
                chunk_hash = sha256_text(sp.text)
                cid = f"{m.document_id}::v{m.document_version}::c{sp.index}::{chunk_hash[:8]}"
                meta = ChunkMetadata(
                    document_id=m.document_id, document_version=m.document_version, chunk_id=cid,
                    chunk_index=sp.index, char_start=sp.start, char_end=sp.end, source_name=m.source_name,
                    source_type=m.source_type, source_trust_level=m.source_trust_level, document_kind=m.document_kind,
                    jurisdiction=m.jurisdiction, law_or_policy_id=m.law_or_policy_id,
                    issuing_organization=m.issuing_organization, source_url=m.source_url,
                    publication_date=m.publication_date, review_status=m.review_status,
                    segment_strategy=sp.strategy, article_label=sp.article_label, article_title=sp.article_title,
                    section_label=sp.section_label, segment_fallback_reason=sp.fallback_reason,
                    page=page_for_offset(sp.start, it.parsed.page_offsets),
                    effective_from=m.effective_from,
                    effective_to=m.effective_to, supersedes_document_id=m.supersedes_document_id,
                    pii_grade=m.pii_grade, pii_types=list(m.pii_types), detected_pii_types=[PiiType(t) for t in detected],
                    tenant_id=m.tenant_id, allowed_roles=m.allowed_roles, subject_id=m.subject_id,
                    content_hash=chunk_hash, document_content_hash=doc_hash, normalization_version=nt.version,
                    embedding_model=self.s.embedding_model, embedding_dimension=0, ingestion_run_id=run_id,
                    created_at=created,
                    ingestion=IngestionFlags(ipi_rule=int(ipi_score >= policies.guard.ipi_block_threshold),
                                             ipi_score=ipi_score, llama_guard_unsafe=lg_flag,
                                             pii_detected=int(bool(detected))),
                    experimental_label=m.experimental_label,
                )
                ids.append(cid)
                texts_for_embed.append(c_norm)  # embed the normalized view; the original is stored for generation
                docs.append(sp.text)
                metas.append(meta)
            result.documents.append({"document_id": m.document_id, "document_version": m.document_version,
                                     "chunks": len(spans), "content_hash": doc_hash,
                                     "segment_strategy": "article_aware" if use_article and fb_reason is None else "generic",
                                     "segment_fallback_reason": fb_reason if use_article else None,
                                     "normalization": nt.transforms, "warnings": it.parsed.warnings})

        # 3. Batch embeddings (reused: embeddings are copied, not recomputed, when staging from the active index).
        vecs, result.embed_ms = await self.embed_batched(texts_for_embed)
        dim = len(vecs[0])
        chroma_metas = []
        for meta in metas:
            meta.embedding_dimension = dim
            chroma_metas.append(meta.to_chroma())

        # 4. Staging index derived from active; remove superseded / previous versions; validate; activate.
        staging = await asyncio.to_thread(self.repo.create_staging, active, note or run_id)
        try:
            for it, _ in todo:
                await asyncio.to_thread(self.repo.delete_document, staging, it.meta.document_id)
                if it.meta.supersedes_document_id:
                    await asyncio.to_thread(self.repo.delete_document, staging, it.meta.supersedes_document_id)
            await asyncio.to_thread(self.repo.add_chunks, staging, ids, vecs, docs, chroma_metas)
            report = await asyncio.to_thread(self.repo.validate, staging, self.s.embedding_model)
        except Exception:
            await asyncio.to_thread(self.repo.discard, staging)
            raise
        result.index_version = staging
        result.validation_errors = report.errors
        if report.ok and auto_activate:
            await asyncio.to_thread(self.repo.activate, staging)
            result.activated = True
        return result
