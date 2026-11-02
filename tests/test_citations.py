"""Answer citation resolution (ragsec/citations.py) + end-to-end citation wiring on the mock backend."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

from ragsec.citations import extract_labels, resolve_citations
from ragsec.ingestion import IngestItem
from ragsec.parsing import ParsedDocument
from ragsec.schemas import (
    DocumentKind, DocumentMetadataIn, GuardMode, PiiGrade, QueryRequest, SourceType, TrustLevel,
)


def _chunk(cid="d::c0"):
    md = SimpleNamespace(document_id="d", document_version=1, source_name="t", source_trust_level=TrustLevel.HIGH,
                         article_label="제15조", article_title="수집", section_label="제2장",
                         char_start=0, char_end=10, source_url=None)
    return SimpleNamespace(chunk_id=cid, metadata=md)


def test_extract_labels_distinct_in_order():
    assert extract_labels("근거 [E2] 그리고 [E1] 다시 [E2]") == ["E2", "E1"]


def test_resolve_valid_citation():
    cits, invalid, uncited = resolve_citations("답입니다 [E1].", {"E1": _chunk()})
    assert invalid == [] and uncited == []
    assert len(cits) == 1 and cits[0].document_id == "d" and cits[0].article_label == "제15조"


def test_resolve_invalid_citation_reported_not_dropped():
    cits, invalid, uncited = resolve_citations("답 [E1] 과 [E2].", {"E1": _chunk()})
    assert invalid == ["E2"] and [c.label for c in cits] == ["E1"]


def test_resolve_uncited_evidence_listed():
    cits, invalid, uncited = resolve_citations("라벨 없는 답입니다.", {"E1": _chunk(), "E2": _chunk("d::c1")})
    assert cits == [] and invalid == [] and uncited == ["E1", "E2"]


def test_resolve_empty_evidence_marks_all_cited_invalid():
    cits, invalid, uncited = resolve_citations("출처 [E1].", {})
    assert cits == [] and invalid == ["E1"]


def test_pipeline_emits_valid_citation(services):
    async def run():
        meta = DocumentMetadataIn(
            document_id="doc_fee", document_version=1, source_name="수수료 안내",
            source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
            document_kind=DocumentKind.BUSINESS_DOCUMENT, effective_from="2026-01-01T00:00:00+09:00",
            pii_grade=PiiGrade.NONE, tenant_id="bank_a", allowed_roles=["general_staff"],
            source_url="https://example.local/fee")
        item = IngestItem(meta=meta, parsed=ParsedDocument(
            text="[안내]\n타행 이체 수수료는 건당 1,000원입니다.", file_type="txt", safe_filename="f.txt"))
        await services.ingestor.ingest([item], services.policies())
        return await services.rag.answer(QueryRequest(user_id="u_staff_a", query="타행 이체 수수료는 얼마인가요?",
                                                      guard_mode=GuardMode.HYBRID))
    resp = asyncio.run(run())
    assert not resp.blocked
    assert resp.invalid_citations == []
    assert len(resp.citations) == 1
    c = resp.citations[0]
    assert c.document_id == "doc_fee" and c.label == "E1"
    assert c.provenance_url == "https://example.local/fee"  # provenance surfaced, never fetched


def test_block_policy_prevents_action_execution(tmp_path):
    """Action-execution ordering: a blocking citation decision must stop pending actions BEFORE they execute."""
    from ragsec.config import Settings
    from ragsec.llm import MockLLMClient
    from ragsec.services import build_services
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key="test-key-123456", vram_profile="vram_6gb", citation_policy="block")
    client = MockLLMClient(available={"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"})
    # model cites a label it was never given (E9) AND proposes a local action
    client._generate = lambda messages: "확인 [E9] [[ACTION:send_report|to=mock-sink://x/y]]\n내용\n[[/ACTION]]"
    svc = build_services(s, client=client)

    async def run():
        meta = DocumentMetadataIn(document_id="doc_c", document_version=1, source_name="수수료 안내",
                                  source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
                                  document_kind=DocumentKind.BUSINESS_DOCUMENT, pii_grade=PiiGrade.NONE,
                                  tenant_id="bank_a", allowed_roles=["general_staff"])
        await svc.ingestor.ingest([IngestItem(meta=meta, parsed=ParsedDocument(
            text="수수료 안내 문서입니다.", file_type="txt", safe_filename="c"))], svc.policies())
        return await svc.rag.answer(QueryRequest(user_id="u_staff_a", query="수수료 안내", guard_mode=GuardMode.OFF))
    resp = asyncio.run(run())
    assert resp.blocked and "INVALID_CITATION" in resp.block_reasons
    assert resp.invalid_citations == ["E9"]
    assert resp.actions and all(not a.executed for a in resp.actions)  # proposal observed, never executed


def test_annotate_policy_allows_action_and_reports_invalid(tmp_path):
    from ragsec.config import Settings
    from ragsec.llm import MockLLMClient
    from ragsec.services import build_services
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key="test-key-123456", vram_profile="vram_6gb", citation_policy="annotate")
    client = MockLLMClient(available={"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"})
    client._generate = lambda messages: "확인 [E9] [[ACTION:send_report|to=mock-sink://x/y]]\n내용\n[[/ACTION]]"
    svc = build_services(s, client=client)

    async def run():
        meta = DocumentMetadataIn(document_id="doc_c2", document_version=1, source_name="수수료 안내",
                                  source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
                                  document_kind=DocumentKind.BUSINESS_DOCUMENT, pii_grade=PiiGrade.NONE,
                                  tenant_id="bank_a", allowed_roles=["general_staff"])
        await svc.ingestor.ingest([IngestItem(meta=meta, parsed=ParsedDocument(
            text="수수료 안내 문서입니다.", file_type="txt", safe_filename="c"))], svc.policies())
        return await svc.rag.answer(QueryRequest(user_id="u_staff_a", query="수수료 안내", guard_mode=GuardMode.OFF))
    resp = asyncio.run(run())
    assert not resp.blocked and resp.invalid_citations == ["E9"]       # reported, not blocked
    assert any(a.executed for a in resp.actions)                        # annotate permits the local action


def test_empty_retrieval_has_no_citations(services):
    async def run():
        # no documents ingested for this tenant/role -> no evidence, no citations
        meta = DocumentMetadataIn(
            document_id="doc_other", document_version=1, source_name="w", source_type=SourceType.INTERNAL_WIKI,
            source_trust_level=TrustLevel.HIGH, document_kind=DocumentKind.BUSINESS_DOCUMENT,
            effective_from="2026-01-01T00:00:00+09:00", pii_grade=PiiGrade.NONE, tenant_id="bank_b",
            allowed_roles=["general_staff"])
        item = IngestItem(meta=meta, parsed=ParsedDocument(text="무관한 내용", file_type="txt", safe_filename="o"))
        await services.ingestor.ingest([item], services.policies())
        return await services.rag.answer(QueryRequest(user_id="u_staff_a", query="존재하지 않는 주제",
                                                      guard_mode=GuardMode.HYBRID))
    resp = asyncio.run(run())
    assert resp.citations == [] and resp.invalid_citations == []
