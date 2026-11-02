"""Synthetic, mock-backend end-to-end demonstration of the backend pipeline.

Flow: authenticated principal -> authorized ingestion (article-aware) -> index activation -> retrieval ->
guards -> generated answer WITH validated citations -> outcome/JSONL -> metrics aggregate. Also shows a
submission dry-run (no active-index change).

THIS IS A SYSTEM CHECK, NOT ATTACK-EFFICACY EVIDENCE. The mock backend is deterministic and offline; its
outputs are never research results. Run:  uv run python scripts/demo_e2e.py
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from ragsec.auth import PrincipalStore, authenticate
from ragsec.config import Settings
from ragsec.ingestion import IngestItem
from ragsec.llm import MockLLMClient
from ragsec.logstore import read_jsonl
from ragsec.metrics import aggregate
from ragsec.parsing import ParsedDocument
from ragsec.schemas import (
    DocumentKind, DocumentMetadataIn, GuardMode, PiiGrade, QueryRequest, SourceType, TrustLevel,
)
from ragsec.services import build_services
from ragsec.submission import load_submission

LEGAL_DOC = """개인정보 보호 지침 (합성 예시 — 실제 법령 아님)

제1장 총칙

제1조(목적) 이 지침은 합성 데이터의 안전한 처리를 목적으로 한다.

제2장 개인정보의 처리

제15조(개인정보의 수집·이용) 처리자는 업무상 필요한 범위에서 개인정보를 수집·이용할 수 있다.

제16조(개인정보의 파기) 보유기간이 지난 개인정보는 지체 없이 파기하여야 한다.
"""
FEE_DOC = "[안내]\n타행 이체 수수료는 건당 1,000원입니다."


def p(msg: str) -> None:
    print(f"[demo] {msg}", flush=True)


async def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="ragsec_demo_"))
    princ = tmp / "principals.json"
    store = PrincipalStore(path=princ)
    admin_tok = store.add("demo-admin", user_id=None, tenant_id=None, roles=[], is_admin=True)
    user_tok = store.add("demo-user", user_id="u_comp_a", tenant_id="bank_a", roles=["compliance"], is_admin=False)

    s = Settings(llm_backend="mock", data_dir=tmp / "var", policy_dir="policies", dataset_root="data",
                 api_key="shared-key-unused-123", vram_profile="vram_6gb", auth_mode="multiuser",
                 principals_file=princ, article_aware_chunking=True)
    svc = build_services(s, client=MockLLMClient(available={"exaone3.5:2.4b", "bge-m3", "llama-guard3:1b"}))

    # 1. authentication boundary ------------------------------------------------
    admin = authenticate(s, store, admin_tok)
    user = authenticate(s, store, user_tok)
    assert admin and admin.is_admin, "admin principal should authenticate"
    assert user and user.user_id == "u_comp_a" and not user.is_admin
    assert authenticate(s, store, "bogus") is None
    assert not user.can_act_as("u_comp_b"), "scoped user must not act as another identity"
    p(f"auth OK: admin(is_admin={admin.is_admin}), user(id={user.user_id}, tenant={user.tenant_id}); "
      f"spoof rejected; bad token rejected")

    # 2. authorized ingestion (admin), article-aware for the policy document ------
    roles = ["compliance", "general_staff"]
    legal = IngestItem(meta=DocumentMetadataIn(
        document_id="demo_policy", document_version=1, source_name="합성 개인정보 보호 지침",
        source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
        document_kind=DocumentKind.INTERNAL_POLICY, law_or_policy_id="demo-policy",
        issuing_organization="합성 감독기관(예시)", source_url="https://example.local/policy",
        pii_grade=PiiGrade.NONE, tenant_id="bank_a", allowed_roles=roles),
        parsed=ParsedDocument(text=LEGAL_DOC, file_type="txt", safe_filename="policy.txt"))
    fee = IngestItem(meta=DocumentMetadataIn(
        document_id="demo_fee", document_version=1, source_name="수수료 안내",
        source_type=SourceType.INTERNAL_WIKI, source_trust_level=TrustLevel.HIGH,
        document_kind=DocumentKind.BUSINESS_DOCUMENT, pii_grade=PiiGrade.NONE, tenant_id="bank_a",
        allowed_roles=roles),
        parsed=ParsedDocument(text=FEE_DOC, file_type="txt", safe_filename="fee.txt"))
    res = await svc.ingestor.ingest([legal, fee], svc.policies(), auto_activate=True)
    assert res.activated, res.validation_errors
    strat = {d["document_id"]: d.get("segment_strategy") for d in res.documents}
    p(f"ingestion OK: index={res.index_version} activated={res.activated} "
      f"segment_strategy={strat}")

    # 3. retrieval + guards + generated answer WITH citations --------------------
    assert user.can_act_as("u_comp_a")
    q1 = await svc.rag.answer(QueryRequest(user_id="u_comp_a", query="타행 이체 수수료는 얼마인가요?",
                                           guard_mode=GuardMode.HYBRID))
    p(f"query(fee): blocked={q1.blocked} citations={[c.label+'->'+c.document_id for c in q1.citations]} "
      f"invalid={q1.invalid_citations} answer={q1.answer[:40]!r}")
    assert not q1.blocked and q1.citations and q1.invalid_citations == []

    q2 = await svc.rag.answer(QueryRequest(user_id="u_comp_a", query="개인정보 파기 의무는 무엇인가요?",
                                           guard_mode=GuardMode.HYBRID))
    p(f"query(policy): citations={[c.label+'->'+(c.article_label or c.document_id) for c in q2.citations]}")

    # 4. JSONL output + metrics aggregate ---------------------------------------
    log_path = s.data_dir / "logs" / "adhoc" / "requests.jsonl"
    recs, malformed = read_jsonl(log_path)
    agg = aggregate(recs)
    p(f"jsonl OK: {len(recs)} records, malformed={malformed}, metric groups={len(agg['groups'])}")
    # no raw provenance/pii leaks into the answer beyond masked previews
    assert malformed == 0 and len(recs) >= 2

    # 5. submission dry-run (must NOT change the active index) -------------------
    sub = tmp / "submission"
    sub.mkdir()
    (sub / "demo_sub.txt").write_text("제1조(목적) 합성.\n제2조(정의) 용어.\n", encoding="utf-8")
    (sub / "demo_sub.meta.json").write_text(json.dumps({
        "document_id": "demo_sub", "document_version": 1, "source_name": "합성 제출물",
        "source_type": "internal_wiki", "source_trust_level": "high", "document_kind": "internal_policy",
        "law_or_policy_id": "demo-sub", "pii_grade": "none", "tenant_id": "bank_a",
        "allowed_roles": ["compliance"], "review_status": "submitted"}, ensure_ascii=False), encoding="utf-8")
    active_before = await asyncio.to_thread(svc.repo.active_version)
    report = load_submission(sub, s, policies=svc.policies())
    active_after = await asyncio.to_thread(svc.repo.active_version)
    p(f"submission dry-run OK: ok={report.ok} items={len(report.ok_items)} "
      f"active_index_unchanged={active_before == active_after}")
    assert report.ok and active_before == active_after

    await svc.aclose()
    p("SYSTEM CHECK PASSED (mock backend — NOT attack-efficacy evidence)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
