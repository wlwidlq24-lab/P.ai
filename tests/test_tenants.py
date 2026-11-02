"""Configurable tenant registry: unknown + disabled tenant rejection, ingestion enforcement."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ragsec.config import Settings
from ragsec.ingestion import IngestItem
from ragsec.llm import MockLLMClient
from ragsec.parsing import ParsedDocument
from ragsec.policy import load_active
from ragsec.schemas import DocumentKind, DocumentMetadataIn, PiiGrade, SourceType, TrustLevel
from ragsec.services import build_services
from ragsec.tenants import TenantError, TenantRegistry

AVAIL = {"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}


def _pols():
    return load_active(Path("policies"))


def test_registry_defaults_include_bank_a_and_b():
    r = TenantRegistry.from_policies(_pols())
    assert {"bank_a", "bank_b"} <= set(r.enabled)


def test_unknown_tenant_rejected():
    r = TenantRegistry.from_policies(_pols())
    with pytest.raises(TenantError):
        r.assert_enabled("bank_unknown")


def test_disabled_tenant_rejected_but_others_ok():
    r = TenantRegistry.from_policies(_pols(), disabled=["bank_b"])
    assert not r.is_enabled("bank_b") and r.is_enabled("bank_a")
    with pytest.raises(TenantError):
        r.assert_enabled("bank_b")
    r.assert_enabled("bank_a")


def _doc(tenant: str):
    meta = DocumentMetadataIn(document_id="t_doc", document_version=1, source_name="w",
                             source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
                             document_kind=DocumentKind.BUSINESS_DOCUMENT, pii_grade=PiiGrade.NONE,
                             tenant_id=tenant, allowed_roles=["compliance"])
    return IngestItem(meta=meta, parsed=ParsedDocument(text="내용 문서", file_type="txt", safe_filename="t"))


def test_ingestion_rejects_disabled_tenant(tmp_path):
    s = Settings(llm_backend="mock", data_dir=tmp_path / "var", policy_dir="policies", dataset_root="data",
                 api_key="test-key-123456", vram_profile="vram_6gb", disabled_tenants=["bank_b"])
    svc = build_services(s, client=MockLLMClient(available=AVAIL))

    async def run():
        with pytest.raises(TenantError):
            await svc.ingestor.ingest([_doc("bank_b")], svc.policies())
        # a known, enabled tenant still ingests
        res = await svc.ingestor.ingest([_doc("bank_a")], svc.policies())
        return res
    res = asyncio.run(run())
    assert res.activated
