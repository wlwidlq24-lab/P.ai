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
    st.subheader("인수인계 자료")
    st.caption("합성 데모입니다. 실제 고객 데이터·실제 전송은 없습니다.")
    try:
        _users = api_get("/users").json()
    except Exception:
        _users = [{"user_id": "u_comp_a", "display_name": "담당자"}]
    hv_users = [u["user_id"] for u in _users] or ["u_comp_a"]
    _dn = {u["user_id"]: (u.get("display_name") or u["user_id"]) for u in _users}
    def _nm(uid):
        return _dn.get(uid, uid)
    hv = st.session_state.setdefault("hvflow", {"screen": "request"})
    # 화면에 보이는 한국어 라벨. API로 보내는 값(handover / response)은 그대로 유지합니다.
    PURPOSE_LABEL, CHANNEL_LABEL = "민원 조사", "내부 인수인계 화면"

    # ---------- 1) 인수인계 자료 만들기 ----------
    if hv["screen"] == "request":
        st.markdown("### 인수인계 자료 만들기")
        st.write("고객 민원 조사 결과를 후임 담당자에게 넘길 요약을 만듭니다.")
        requester = st.selectbox("작성자", hv_users, format_func=_nm,
                                 index=hv_users.index("u_comp_a") if "u_comp_a" in hv_users else 0)
        task = st.text_area("정리할 업무", "이 고객 민원 처리 현황을 요약해 주세요.")
        recipient = st.text_input("받는 사람(수신자)", "후임 담당자")
        st.markdown(f"- 전달 목적: **{PURPOSE_LABEL}** (고정)")
        st.markdown(f"- 전달 경로: **{CHANNEL_LABEL}** (고정)")
        st.caption("‘자료 만들기’를 누르면 권한 범위 안에서 요약을 만들고, 각 문장의 근거를 열 수 있는 링크를 만듭니다.")
        if st.button("자료 만들기", type="primary"):
            with st.spinner("자료를 만드는 중입니다…"):
                try:
                    r = api_post("/query", json={"user_id": requester, "query": task, "guard_mode": "OFF",
                                 "create_handover": True, "recipient": recipient, "purpose": "handover",
                                 "channel": "response", "evidence_policy": "approved_excerpt"})
                except Exception:
                    st.error("요청 실패 — 백엔드에 연결할 수 없습니다. 잠시 후 다시 시도하세요."); r = None
            if r is not None and r.status_code != 200:
                st.error(f"자료를 만들지 못했습니다. (상태 {r.status_code})")
                with st.expander("진단 정보"):
                    st.code(r.text)
            elif r is not None:
                d = r.json()
                hv.update({"screen": "summary", "handover_id": d.get("handover_id"), "answer": d.get("answer", ""),
                           "links": d.get("evidence_links", []), "invalid": d.get("invalid_citations", []),
                           "recipient": recipient, "requester": requester, "open": None, "viewer": requester})
                if not d.get("handover_id"):
                    st.warning("요약에 연결할 근거가 없어 근거 링크가 만들어지지 않았습니다.")
                rerun()

    # ---------- 2) 인수인계 요약 + 근거 확인 ----------
    elif hv["screen"] == "summary":
        st.markdown("### 인수인계 요약")
        st.write(f"**받는 사람:** {hv.get('recipient')}  ·  전달 목적: {PURPOSE_LABEL}  ·  전달 경로: {CHANNEL_LABEL}")
        st.markdown("#### 요약")
        st.write(hv.get("answer") or "(요약 없음)")

        st.markdown("#### 근거 확인")
        st.caption("문장의 근거를 보려면 아래에서 선택하세요. 열람자의 현재 권한을 클릭할 때마다 서버가 다시 확인합니다.")
        prev_viewer = hv.get("viewer")
        viewer = st.selectbox("열람자 전환 (데모)", hv_users, format_func=_nm,
                              index=hv_users.index(prev_viewer) if prev_viewer in hv_users else 0,
                              help="실제 서비스에서는 로그인한 사용자가 열람자입니다. 데모에서는 전환해 볼 수 있습니다.")
        if viewer != prev_viewer:
            hv["open"] = None   # 열람자를 바꾸면 이전 열람자의 근거 내용이 남지 않도록 패널을 비웁니다.
        hv["viewer"] = viewer

        links = hv.get("links", [])
        if links:
            for i, ln in enumerate(links, 1):
                if st.button(f"근거 {i} 보기", key="hv_ev_" + ln["evidence_id"], help=f"근거 라벨 {ln.get('label')}"):
                    with st.spinner("근거를 불러오는 중입니다…"):
                        try:
                            rr = api_get(f"/handover/{hv['handover_id']}/evidence/{ln['evidence_id']}",
                                         params={"viewer": viewer})
                            body = rr.json() if rr.headers.get("content-type", "").startswith("application/json") else {}
                            hv["open"] = {"status": rr.status_code, "body": body, "n": i}
                        except Exception as e:
                            hv["open"] = {"status": -1, "error": str(e), "body": {}, "n": i}
                    rerun()
        else:
            st.info("표시할 근거가 없습니다.")
        for inv in hv.get("invalid", []):
            st.write(f"• 근거 {inv} — 근거를 확인할 수 없습니다.")

        # ---- 근거 확인 패널: 서버의 세 가지 결과 + 로딩/인증/오류/확인불가 구분(아이콘+문구) ----
        op = hv.get("open")
        if op is not None:
            st.markdown("---")
            st.markdown(f"#### 근거 확인 — 근거 {op.get('n', '')}")
            status = op.get("status", -1)
            if status == 401:
                st.error("🔑 인증 실패 — 자격 증명을 확인하세요.")
            elif status < 0 or status >= 500:
                st.error("⚠️ 요청 실패 — 잠시 후 다시 시도하세요.")
                with st.expander("진단 정보"):
                    st.code(f"status={status} {op.get('error', '')}")
            elif status != 200:
                st.warning("❔ 근거를 확인할 수 없습니다.")
            else:
                b = op.get("body", {})
                outcome = b.get("outcome")
                reason = b.get("reason", "")
                if outcome == "original":
                    st.success("✅ 원문 근거 위치")
                    meta = f"출처: **{b.get('title')}**"
                    if b.get("page"):
                        meta += f" · {b.get('page')}쪽"
                    if b.get("document_version"):
                        meta += f" · 버전 {b.get('document_version')}"
                    st.write(meta)
                    st.caption("마스킹된 근거")
                    st.text(b.get("excerpt", ""))
                elif outcome == "excerpt":
                    st.info("📄 허용된 발췌")
                    if b.get("title"):
                        st.write(f"출처: **{b.get('title')}**")
                    st.text(b.get("excerpt", ""))
                elif reason in ("unknown_evidence", "unknown_handover", "evidence_unavailable"):
                    st.warning("❔ 근거를 확인할 수 없습니다.")
                    st.write("이 근거를 찾을 수 없거나 더 이상 사용할 수 없습니다.")
                else:
                    # 정책상 열람 제한. 서버가 '취소/만료'를 확정해 주지 않으므로 그 사유는 단정하지 않습니다.
                    st.warning("🔒 근거 열람 제한")
                    st.write("이 열람자는 현재 이 근거를 볼 수 있는 권한이 없습니다. 작성자나 관리자에게 권한을 요청하세요.")
                    # 제한 시 제목·쪽·미리보기·본문은 표시하지 않습니다.
            if st.button("요약으로 돌아가기"):
                hv["open"] = None; rerun()

        st.markdown("---")
        if st.button("새 인수인계 만들기"):
            st.session_state["hvflow"] = {"screen": "request"}; rerun()

        # ---- 보호된 데모·진단 영역 (권한 변경은 여기서만; 일반 열람자 화면과 분리) ----
        with st.expander("데모·진단 (관리자 전용)"):
            st.caption("권한 변경은 보호된 관리자 경로로만 수행합니다. 일반 열람자 화면에는 노출하지 마세요.")
            dv = st.selectbox("대상 열람자", hv_users, format_func=_nm, key="hv_grant_viewer")
            g1, g2 = st.columns(2)
            if g1.button("권한 부여") and hv.get("handover_id"):
                rr = api_post(f"/handover/{hv['handover_id']}/grant", params={"viewer": dv, "action": "grant"})
                st.write(f"권한 부여 → {rr.status_code}")
            if g2.button("권한 종료") and hv.get("handover_id"):
                rr = api_post(f"/handover/{hv['handover_id']}/grant", params={"viewer": dv, "action": "revoke"})
                st.write(f"권한 종료 → {rr.status_code}")
            st.caption("같은 근거를 같은 열람자로 다시 열어 상태 변화를 확인하세요. 대조: 권한이 그대로인 열람자와 "
                       "원본 열람 권한이 있는 리뷰어는 영향을 받지 않아야 합니다.")
            st.markdown("**기술 정보**")
            st.code(f"handover_id={hv.get('handover_id')}\nrequester={hv.get('requester')}\nviewer={hv.get('viewer')}")
