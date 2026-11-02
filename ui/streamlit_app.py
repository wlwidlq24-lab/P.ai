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

tab_query, tab_upload, tab_models, tab_exp = st.tabs(["Single query", "Upload document", "Models", "Experiments"])

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
                "normalization": {"detect_on_normalized": detect_norm, "generate_from_normalized": gen_norm}}
        try:
            r = api_post("/query", json=body)
            if r.status_code != 200:
                st.error(f"{r.status_code}: {r.text}")
            else:
                d = r.json()
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
