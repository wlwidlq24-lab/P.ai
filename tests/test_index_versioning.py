"""Versioned index: one consistent version per query, isolation, rollback-without-delete."""
from __future__ import annotations

import asyncio

from ragsec.ingestion import IngestItem
from ragsec.parsing import ParsedDocument
from ragsec.schemas import DocumentKind, DocumentMetadataIn, GuardMode, PiiGrade, QueryRequest, SourceType, TrustLevel

BASE = dict(document_id="docver", source_name="w", source_type=SourceType.INTERNAL_WIKI,
            source_trust_level=TrustLevel.HIGH, document_kind=DocumentKind.BUSINESS_DOCUMENT,
            pii_grade=PiiGrade.NONE, tenant_id="bank_a", allowed_roles=["general_staff"])


def test_query_pins_single_index_version(services, monkeypatch):
    async def run():
        await services.ingestor.ingest([IngestItem(
            meta=DocumentMetadataIn(document_version=1, **BASE),
            parsed=ParsedDocument(text="수수료 안내 문서입니다.", file_type="txt", safe_filename="f"))],
            services.policies())
        captured: list[str] = []
        orig = services.repo.query

        def spy(version, *a, **k):
            captured.append(version)
            return orig(version, *a, **k)
        monkeypatch.setattr(services.repo, "query", spy)
        # HYBRID + INGESTION stage issues both a filtered and an unfiltered retrieval; both must use ONE version.
        await services.rag.answer(QueryRequest(user_id="u_staff_a", query="수수료", guard_mode=GuardMode.HYBRID))
        return captured
    captured = asyncio.run(run())
    assert len(captured) >= 2 and len(set(captured)) == 1  # every retrieval in the request used the same version


def test_versions_isolated_and_rollback_keeps_prior(services):
    async def run():
        r1 = await services.ingestor.ingest([IngestItem(
            meta=DocumentMetadataIn(document_version=1, **BASE),
            parsed=ParsedDocument(text="수수료는 500원입니다.", file_type="txt", safe_filename="v1"))],
            services.policies())
        v1 = r1.index_version
        r2 = await services.ingestor.ingest([IngestItem(
            meta=DocumentMetadataIn(document_version=2, **BASE),
            parsed=ParsedDocument(text="수수료는 1000원입니다.", file_type="txt", safe_filename="v2"))],
            services.policies())
        v2 = r2.index_version
        reg = services.repo.registry()
        assert reg["active"] == v2 and reg["versions"][v1]["status"] == "retired"
        assert services.repo.count(v1) > 0            # prior version is retired, NOT deleted
        back = services.repo.rollback()
        assert back == v1 and services.repo.active_version() == v1
        return v1, v2
    v1, v2 = asyncio.run(run())
    assert v1 != v2
