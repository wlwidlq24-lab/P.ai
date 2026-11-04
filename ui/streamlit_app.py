"""Streamlit experiment console. Communicates ONLY through the FastAPI backend (never imports ragsec.*).

Run:  uv run streamlit run ui/streamlit_app.py
Set RAGSEC_API_URL and RAGSEC_API_KEY (defaults: http://127.0.0.1:8000 / change-me-local-only).
"""
from __future__ import annotations

import json
import os
import time

import httpx
import streamlit as st

API = os.environ.get("RAGSEC_API_URL", "http://127.0.0.1:8000")
KEY = os.environ.get("RAGSEC_API_KEY", "change-me-local-only")
H = {"X-API-Key": KEY}

st.set_page_config(page_title="ragsec — Korean financial RAG IPI testbed", layout="wide")


def api_get(path: str, **kw):
    return httpx.get(f"{API}{path}", headers=H, timeout=30, **kw)


def api_post(path: str, **kw):
    return httpx.post(f"{API}{path}", headers=H, timeout=300, **kw)


def rerun():
    (getattr(st, "rerun", None) or getattr(st, "experimental_rerun", lambda: None))()


st.title("ragsec — IPI / PII exfiltration testbed")
st.caption("All data is synthetic. The mock sink blocks real egress. This console only calls the FastAPI backend.")

# --- health banner
# NOTE: /health reports LOCAL status only. Ollama reachability/version are checked administratively
# (ragsec doctor / the Models tab's cached snapshot), never from the /health request handler.
try:
    h = api_get("/health").json()
    cols = st.columns(4)
    cols[0].metric("Backend", h.get("backend", "?"))
    cols[1].metric("Health", h.get("status", "?"))
    cols[2].metric("Active index", (h.get("active_index") or "none")[:14])
    cols[3].metric("VRAM profile", h.get("vram_profile", "?"))
    if h.get("status") != "ok":
        st.warning(f"Health degraded: {h}")
except Exception as e:
    st.error(f"Cannot reach API at {API}: {e}. Start it with: uv run uvicorn ragsec.api:app --port 8000")
    st.stop()

tab_handover, tab_query, tab_upload, tab_models, tab_exp = st.tabs(
    ["인수인계 자료", "Single query", "Upload document", "Models", "Experiments"])

# ============================================================ single query
with tab_query:
    st.subheader("Run one request through the pipeline")
    try:
        users = api_get("/users").json()
    except Exception:
        users = []
    uids = [u["user_id"] for u in users] or ["u_comp_a"]
    c1, c2, c3 = st.columns(3)
    user_id = c1.selectbox("User (role/tenant)", uids,
                           format_func=lambda u: next((f"{x['user_id']} — {x['display_name']}" for x in users if x['user_id'] == u), u))
    guard_mode = c2.selectbox("Guard mode", ["OFF", "REGEX_ONLY", "LLAMA_GUARD", "HYBRID", "HYBRID_NO_IPI", "IPI_ONLY"], index=3)
    acm = c3.selectbox("Access control", ["ENFORCED", "WEAKENED_NO_ROLE_FILTER"])
    c4, c5, c6 = st.columns(3)
    try:
        models = api_get("/models/status").json().get("models", {})
        model_opts = [m for m, v in models.items() if "guard" not in m and "bge" not in m]
    except Exception:
        model_opts = ["exaone3.5:2.4b"]
    target_model = c4.selectbox("Target model", model_opts or ["exaone3.5:2.4b"])
    subject_id = c5.text_input("Subject id (optional)", "")
    stages = c6.multiselect("Stages", ["INGESTION", "PRE_GENERATION", "POST_GENERATION"],
                            default=["INGESTION", "PRE_GENERATION", "POST_GENERATION"])
    detect_norm = st.checkbox("Detectors inspect normalized view", value=True)
    gen_norm = st.checkbox("Generate from normalized view (default: original)", value=False)
    query = st.text_area("Query", "고객 문의 이메일을 요약해 주세요.")
    hc1, hc2, hc3 = st.columns(3)
    create_handover = hc1.checkbox("핸드오프 근거 링크 생성", value=False)
    recipient = hc2.text_input("Recipient (수신자)", "successor")
    evidence_policy = hc3.selectbox("Evidence policy", ["approved_excerpt", "original_only"])

    # optionally preload a case
    with st.expander("Load a dataset case into this form"):
        ds_dir = st.text_input("dataset_dir", "synthetic/v1", key="q_ds")
        if st.button("List cases"):
            try:
                st.session_state["cases"] = api_get("/cases", params={"dataset_dir": ds_dir}).json()
            except Exception as e:
                st.error(e)
        for c in (st.session_state.get("cases") or [])[:40]:
            if st.button(f"{c['case_id']} [{c['case_type']}/{c['language']}/{c['unicode_transform']}]", key="case_" + c["case_id"]):
                st.session_state["preset"] = c
        if p := st.session_state.get("preset"):
            st.info(f"Loaded {p['case_id']} — set User to {p['user_id']}, subject {p.get('subject_id')}. Query below.")
            query = p["query"]

    if st.button("Run query", type="primary"):
        body = {"user_id": user_id, "query": query, "guard_mode": guard_mode, "access_control_mode": acm,
                "target_model": target_model, "stages": stages, "subject_id": subject_id or None,
                "normalization": {"detect_on_normalized": detect_norm, "generate_from_normalized": gen_norm},
                "create_handover": create_handover, "recipient": recipient, "purpose": "handover",
                "channel": "response", "evidence_policy": evidence_policy}
        try:
            r = api_post("/query", json=body)
            if r.status_code != 200:
                st.error(f"{r.status_code}: {r.text}")
            else:
                d = r.json()
                st.session_state["evnav"] = {"handover_id": d.get("handover_id"),
                                             "links": d.get("evidence_links", [])}
                a, b = st.columns([2, 1])
                with a:
                    st.markdown(("**BLOCKED** — " if d["blocked"] else "**Answer**"))
                    st.write(d["answer"])
                    if d["block_reasons"]:
                        st.warning("Block reasons: " + ", ".join(d["block_reasons"]))
                    st.markdown("**Retrieved evidence (masked)**")
                    for v in d["retrieved"]:
                        st.caption(f"[{v['decision']}] {v['chunk_id'][-28:]} trust={v['source_trust_level']} "
                                   f"dist={v['distance']:.3f}")
                        st.text(v["preview_masked"])
                    if d.get("citations"):
                        st.markdown("**인용 / Citations**")
                        for c in d["citations"]:
                            loc = c.get("article_label") or (
                                f"chars {c['char_start']}–{c['char_end']}" if c.get("char_start") is not None else "")
                            st.caption(f"[{c['label']}] {c['display_title']} "
                                       f"({c['document_id']} v{c['document_version']}) {loc}")
                    if d.get("invalid_citations"):
                        st.warning("유효하지 않은 인용(제공되지 않은 근거 라벨): " + ", ".join(d["invalid_citations"]))
                    if d["actions"]:
                        st.markdown("**Tool actions (simulated)**")
                        st.json(d["actions"])
                with b:
                    st.markdown("**Status**")
                    st.write(f"status={d['status']} code={d.get('error_code')}")
                    st.markdown("**Stage latency (ms)**")
                    st.json({k: v for k, v in d["timings"].items() if v is not None})
        except Exception as e:
            st.error(e)

    # evidence navigation — three plain states (original / permitted excerpt / access restricted).
    # Each click re-authorizes server-side; no source bytes or public file URL are exposed in the UI.
    ev = st.session_state.get("evnav")
    if ev and ev.get("links"):
        st.markdown("**근거 탐색 / Evidence navigation**")
        viewer_open = st.text_input("Viewer (user_id)", value=user_id, key="ev_viewer")
        for ln in ev["links"]:
            if st.button(f"근거 열기 [{ln['label']}] {ln.get('title', '')}", key="open_" + ln["evidence_id"]):
                try:
                    res = api_get(f"/handover/{ev['handover_id']}/evidence/{ln['evidence_id']}",
                                  params={"viewer": viewer_open}).json()
                except Exception as e:
                    st.error(e); res = {}
                o = res.get("outcome")
                if o == "original":
                    st.success(f"원본 근거 · {res.get('title')} (p.{res.get('page')})")
                    st.text(res.get("excerpt", ""))
                elif o == "excerpt":
                    st.info(f"허용된 발췌 · {res.get('title')}")
                    st.text(res.get("excerpt", ""))
                else:
                    st.warning("접근 제한 — 표시할 근거가 없습니다 (restricted).")

# ============================================================ upload
with tab_upload:
    st.subheader("Upload a synthetic PDF/TXT with metadata")
    up = st.file_uploader("File (.pdf / .txt)", type=["pdf", "txt"])
    c1, c2, c3 = st.columns(3)
    doc_id = c1.text_input("document_id", "doc_manual_001")
    version = c2.number_input("document_version", 1, 9999, 1)
    tenant = c3.text_input("tenant_id", "bank_a")
    c4, c5, c6 = st.columns(3)
    kind = c4.selectbox("document_kind", ["business_document", "internal_policy", "legislation", "experimental_document"])
    grade = c5.selectbox("pii_grade", ["none", "general", "credit", "unique_id", "sensitive"])
    trust = c6.selectbox("source_trust_level", ["high", "medium", "low", "untrusted"])
    roles = st.text_input("allowed_roles (comma)", "compliance")
    src_type = st.selectbox("source_type", ["internal_wiki", "crm_record", "customer_email", "uploaded_file", "statute_db", "partner_feed"])
    law_id = st.text_input("law_or_policy_id (required for legislation/internal_policy)", "")
    if st.button("Upload & ingest") and up is not None:
        meta = {"document_id": doc_id, "document_version": int(version), "source_name": up.name,
                "source_type": src_type, "source_trust_level": trust, "document_kind": kind,
                "pii_grade": grade, "tenant_id": tenant,
                "allowed_roles": [r.strip() for r in roles.split(",") if r.strip()],
                "law_or_policy_id": law_id or None}
        if kind == "experimental_document":
            meta["experimental_label"] = {"is_attack": False, "lineage_id": doc_id, "language": "ko"}
        try:
            r = api_post("/documents", files={"file": (up.name, up.getvalue())},
                         data={"metadata": json.dumps(meta), "auto_activate": "true"})
            st.json(r.json()) if r.status_code == 200 else st.error(f"{r.status_code}: {r.text}")
        except Exception as e:
            st.error(e)

# ============================================================ models
with tab_models:
    st.subheader("Model and scheduler status")
    if st.button("Refresh models"):
        st.session_state.pop("models_status", None)
    try:
        ms = st.session_state.setdefault("models_status", api_get("/models/status").json())
        st.write(f"Ollama {ms.get('ollama_version')} — scheduler switches: {ms.get('scheduler_switches')}")
        st.caption(ms.get("note", ""))
        st.markdown("**Required models** (from the cached admin snapshot; run `ragsec doctor` to refresh)")
        st.json(ms["models"])
        st.markdown("**Scheduler-tracked resident (in-process bookkeeping, not a live /api/ps query)**")
        st.json(ms.get("scheduler_tracked_resident") or {"note": "none tracked resident in this process"})
        st.markdown("**Active VRAM profile**")
        st.json(ms["profile"])
    except Exception as e:
        st.error(e)

# ============================================================ experiments
with tab_exp:
    st.subheader("Launch and monitor experiments")
    default_manifest = {
        "experiment_id": "ui-run", "dataset_dir": "synthetic/v1", "splits": ["dev"],
        "case_types": ["attack", "benign", "benign_pii"], "max_cases": 6,
        "guard_modes": ["OFF", "HYBRID"], "target_models": ["exaone3.5:2.4b"],
        "stage_sets": [["INGESTION", "PRE_GENERATION", "POST_GENERATION"]],
        "access_control_modes": ["ENFORCED"], "repetitions": 1, "warmup_requests": 1, "cold_start_samples": 0}
    txt = st.text_area("Experiment manifest (JSON)", json.dumps(default_manifest, indent=2, ensure_ascii=False), height=320)
    if st.button("Submit experiment", type="primary"):
        try:
            r = api_post("/experiments/run", json=json.loads(txt))
            if r.status_code == 200:
                st.session_state["run_id"] = r.json()["run_id"]
                st.success(f"submitted run_id={st.session_state['run_id']}")
            else:
                st.error(f"{r.status_code}: {r.text}")
        except Exception as e:
            st.error(e)

    run_id = st.text_input("run_id (or experiment_id) to monitor", st.session_state.get("run_id", ""))
    if run_id and st.button("Poll status"):
        for _ in range(600):
            d = api_get(f"/experiments/{run_id}").json()
            ph = st.empty()
            ph.progress(min(1.0, d["done"] / d["total"]) if d.get("total") else 0.0,
                        text=f"status={d['status']} done={d['done']}/{d['total']} errors={d['errors']}")
            if d["status"] in ("completed", "failed", "cancelled"):
                st.write(d)
                if "metrics" in d:
                    st.markdown("**Metrics by condition**")
                    rows = []
                    for g, s in d["metrics"]["groups"].items():
                        rows.append({"condition": g, "n": s["ASR_valid"]["n"], "ASR": s["ASR_valid"]["rate"],
                                     "UPDR_atk": s["UPDR_attack"]["rate"], "FPR": s["FPR_block"]["rate"],
                                     "F1": s["detection"]["f1"], "warm_p50_ms": s["latency_warm"]["p50_ms"]})
                    st.dataframe(rows, use_container_width=True)
                st.markdown(f"Download: `GET {API}/experiments/{run_id}/log` (JSONL), "
                            f"`/metrics?format=csv` (CSV)")
                break
            time.sleep(2)

# ============================================================ handover (evidence navigation draft for UI/UX)
with tab_handover:
    st.subheader("인수인계 자료 — 근거 탐색 초안")
    try:
        hv_users = [u["user_id"] for u in api_get("/users").json()] or ["u_comp_a"]
    except Exception:
        hv_users = ["u_comp_a"]
    hv = st.session_state.setdefault("hvflow", {"screen": "request"})

    # ---------- screen 1: 인수인계 자료 만들기
    if hv["screen"] == "request":
        st.markdown("### 인수인계 자료 만들기")
        st.caption("합성 시나리오: 고객 민원 조사 결과를 후임 담당자에게 인계합니다.")
        requester = st.selectbox("작성자 (requester)", hv_users,
                                 index=hv_users.index("u_comp_a") if "u_comp_a" in hv_users else 0)
        task = st.text_area("업무 (task)", "이 고객 민원 처리 현황을 요약해 주세요.")
        recipient = st.text_input("수신자 (recipient)", "successor")
        st.write("목적 (purpose): **handover** · 채널 (channel): **response** — 이 시나리오에서는 고정값")
        if st.button("자료 만들기", type="primary"):
            with st.spinner("자료 생성 중…"):
                try:
                    r = api_post("/query", json={"user_id": requester, "query": task, "guard_mode": "OFF",
                                 "create_handover": True, "recipient": recipient, "purpose": "handover",
                                 "channel": "response", "evidence_policy": "approved_excerpt"})
                except Exception as e:
                    st.error(f"요청 오류: {e}"); r = None
            if r is not None and r.status_code != 200:
                st.error(f"오류 {r.status_code}: {r.text}")
            elif r is not None:
                d = r.json()
                hv.update({"screen": "summary", "handover_id": d.get("handover_id"), "answer": d.get("answer", ""),
                           "links": d.get("evidence_links", []), "invalid": d.get("invalid_citations", []),
                           "recipient": recipient, "requester": requester, "open": None, "viewer": requester})
                if not d.get("handover_id"):
                    st.warning("이 응답에는 인용 근거가 없어 링크가 생성되지 않았습니다.")
                rerun()

    # ---------- screen 2: 인수인계 요약 + 근거 링크 + 근거 패널
    elif hv["screen"] == "summary":
        st.markdown("### 인수인계 요약")
        st.write(f"수신자 **{hv.get('recipient')}** · 목적 **handover** · 채널 **response**")
        st.markdown("**허용된 요약**")
        st.write(hv.get("answer") or "(요약 없음)")

        st.markdown("**근거 (citations)**")
        viewer = st.selectbox("열람자 (viewer)", hv_users,
                              index=hv_users.index(hv.get("viewer")) if hv.get("viewer") in hv_users else 0,
                              help="클릭할 때마다 이 사용자의 현재 권한을 서버가 재확인합니다.")
        hv["viewer"] = viewer
        for i, ln in enumerate(hv.get("links", []), 1):
            if st.button(f"[근거 {i}]", key="hv_ev_" + ln["evidence_id"]):
                try:
                    rr = api_get(f"/handover/{hv['handover_id']}/evidence/{ln['evidence_id']}",
                                 params={"viewer": viewer})
                    body = rr.json() if rr.headers.get("content-type", "").startswith("application/json") else {}
                    hv["open"] = {"status": rr.status_code, "body": body}
                except Exception as e:
                    hv["open"] = {"status": -1, "error": str(e), "body": {}}
                rerun()
        for inv in hv.get("invalid", []):
            st.write(f"[{inv}] 근거를 확인할 수 없습니다.")

        op = hv.get("open")
        if op is not None:
            st.markdown("---")
            st.markdown("#### 근거 패널")
            if op["status"] == 401:
                st.error("인증 실패 — 자격 증명을 확인하세요.")
            elif op["status"] != 200:
                st.error(f"요청 오류 (status={op['status']}) {op.get('error', '')}")
            else:
                b = op.get("body", {})
                outcome = b.get("outcome")
                if outcome == "original":
                    st.success("원문 근거 위치")
                    st.write(f"출처: **{b.get('title')}**"
                             + (f" · p.{b.get('page')}" if b.get("page") else "")
                             + (f" · v{b.get('document_version')}" if b.get("document_version") else ""))
                    st.caption("마스킹된 근거")
                    st.text(b.get("excerpt", ""))
                elif outcome == "excerpt":
                    st.info("허용된 발췌")
                    if b.get("title"):
                        st.write(f"출처: **{b.get('title')}**")
                    st.text(b.get("excerpt", ""))
                else:
                    st.warning("근거 열람 제한")
                    st.write("이 열람자는 현재 이 근거에 접근할 수 없습니다. 작성자/관리자에게 권한을 요청하세요.")
                    # restricted: no title / page / preview / evidence text is rendered.
            if st.button("요약으로 돌아가기"):
                hv["open"] = None; rerun()

        st.markdown("---")
        if st.button("새 인수인계 만들기"):
            st.session_state["hvflow"] = {"screen": "request"}; rerun()

        # same-link demonstration (admin-only; kept OUT of the ordinary viewer area above)
        with st.expander("데모(관리자 전용): 동일 링크 권한 변경"):
            st.caption("권한 변경은 보호된 관리자 경로로만. 일반 열람자 화면에는 노출하지 마세요.")
            dv = st.selectbox("대상 열람자", hv_users, key="hv_grant_viewer")
            g1, g2 = st.columns(2)
            if g1.button("권한 부여 (grant)") and hv.get("handover_id"):
                rr = api_post(f"/handover/{hv['handover_id']}/grant", params={"viewer": dv, "action": "grant"})
                st.write(f"grant → {rr.status_code}")
            if g2.button("권한 종료 (revoke)") and hv.get("handover_id"):
                rr = api_post(f"/handover/{hv['handover_id']}/grant", params={"viewer": dv, "action": "revoke"})
                st.write(f"revoke → {rr.status_code}")
            st.caption("같은 [근거] 링크를 같은 열람자로 다시 열어 상태 변화를 확인하세요. 대조: 권한이 그대로인 열람자와 "
                       "원본 열람 권한이 있는 리뷰어는 영향을 받지 않아야 합니다.")
