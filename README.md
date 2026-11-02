# ragsec — Korean Financial RAG IPI / PII-Exfiltration Testbed

A reproducible research system for the study *"Empirical Evaluation of Personal Data Exfiltration through
Indirect Prompt Injection in Korean Financial Enterprise RAG Agents and the Effectiveness of Multistage
Guardrails."*

It runs a local RAG agent (Ollama + ChromaDB + FastAPI), applies multistage guardrails
(regex PII, Korean/English IPI rules, Llama Guard 3, provenance, canary leak checks), and measures attack
success, unauthorized disclosure, false positives, detection quality, latency and utility — all on
**synthetic data** with a **local mock sink** that blocks real exfiltration.

> **Safety:** no real personal data, no real RRNs/accounts, no production credentials, no outbound network
> exfiltration. Attack documents ship with a literal `[IPI_PAYLOAD_PLACEHOLDER]`; the security researcher
> (Role 3) fills in reviewed injection templates. Canaries are format-valid but checksum-invalid.

---

## 1. Requirements

- Windows 11 + PowerShell (Bash paths also work)
- [uv](https://docs.astral.sh/uv/) (Python project/dependency manager) — pins Python 3.12 automatically
- [Ollama](https://ollama.com) running locally (`ollama serve` or the tray app) for live experiments
- NVIDIA GPU recommended. Tested target: RTX 4050 Laptop (6 GB) → `vram_6gb` profile.

Everything works **without Docker**. The offline `mock` backend needs no GPU and no Ollama.

## 2. Install

```powershell
# from the project root
uv sync                      # creates .venv (Python 3.12) and installs pinned deps from uv.lock
Copy-Item .env.example .env  # then edit RAGSEC_API_KEY etc.
```

## 3. Pull models (live experiments)

If `ollama` is on your PATH:

```powershell
.\scripts\pull_models.ps1          # exaone3.5:2.4b + bge-m3 + llama-guard3:1b  (~4.4 GB)
.\scripts\pull_models.ps1 -All     # also exaone3.5:7.8b + qwen3:4b
```

If `ollama` is **not** on PATH but the daemon runs, pull via the API:

```powershell
uv run python -c "import httpx,json;[__import__('sys').stdout.write(m+': '+[json.loads(l)['status'] for l in httpx.stream('POST','http://127.0.0.1:11434/api/pull',json={'model':m},timeout=1200).__enter__().iter_lines() if l][-1]+'\n') for m in ['exaone3.5:2.4b','bge-m3','llama-guard3:1b']]"
```

Check everything:

```powershell
uv run ragsec doctor         # prints Ollama version, GPU/VRAM, profile, missing models, policy versions
```

## 4. Quick start (offline, no GPU)

```powershell
uv run ragsec gen-dataset                                   # -> data/synthetic/v1
$env:RAGSEC_LLM_BACKEND = "mock"
uv run ragsec run experiments/smoke_mock.json              # end-to-end on the deterministic mock
# metrics land in var/logs/smoke-mock/<run_id>/metrics.{json,csv}
```

With placeholder payloads, ASR and UPDR are 0 by construction — this validates the *plumbing*, not an attack.

## 5. Live run (Ollama)

```powershell
uv run ragsec gen-dataset
$env:RAGSEC_LLM_BACKEND = "ollama"
uv run ragsec run experiments/smoke_live.json             # tiny: exaone3.5:2.4b, OFF vs HYBRID
# or the full defense/stage study (hours on 6 GB):
uv run ragsec run experiments/rq2_defenses.json
```

`scripts\live_smoke.ps1` does doctor → gen-dataset → smoke in one step. Before a strict live run, gate on the
binding preflight (see §11.3): `.\scripts\preflight_binding.ps1 -Port 11434`.

## 6. API + UI

```powershell
# terminal 1 — ONE worker (job state + the GPU lock live in-process; see caveats)
uv run uvicorn ragsec.api:app --host 127.0.0.1 --port 8000

# terminal 2 — the Streamlit console (talks to the API only)
$env:RAGSEC_API_URL = "http://127.0.0.1:8000"; $env:RAGSEC_API_KEY = "change-me-local-only"
uv run streamlit run ui/streamlit_app.py
```

API (all except `/health` require `X-API-Key`):

| Method & path | purpose |
|---|---|
| `GET /health` | liveness, Ollama/policy status, active index |
| `GET /models/status` | required/resident models, VRAM profile, scheduler switches |
| `POST /documents` | upload PDF/TXT + metadata → ingest into a new active index version |
| `POST /query` | one request through the pipeline (`QueryRequest` → `QueryResponse`) |
| `POST /experiments/run` | submit a manifest; returns `run_id` (background job) |
| `GET /experiments/{run_or_experiment_id}` | status + metrics (poll: running/completed/failed/cancelled) |
| `POST /experiments/{run_id}/cancel` | cancel a running job |
| `GET /experiments/{run_id}/log` | download `requests.jsonl` |
| `GET /experiments/{run_id}/metrics?format=csv` | download metrics |
| `GET /index`, `POST /index/activate/{v}`, `POST /index/rollback` | index version management |
| `POST /policies/reload` | re-read the active policy bundle |

## 7. Metrics

```powershell
uv run ragsec metrics var/logs/<exp>/<run_id>/requests.jsonl --out var/metrics
```

See [docs/DESIGN.md](docs/DESIGN.md) §7 for exact numerator/denominator definitions. Headline metrics:
`ASR_valid`, `ASR_itt`, `ASR_raw`, `compliance_raw`, `UPDR_attack/benign`, `FPR_block`, `FPR_intervention`,
detection `precision/recall/F1`, `utility`, cold/warm `p50/p95` latency, paired `risk_difference` vs OFF
with cluster-bootstrap CIs and exact McNemar p-values.

## 8. Tests

```powershell
uv run pytest -q                 # model-independent unit + mock-backed integration (~4 s, no GPU)
$env:RAGSEC_IT = "1"; uv run pytest -q -m integration   # opt-in live-Ollama tests (none required for CI)
```

## 9. Repository layout

```
ragsec/           core package (config, schemas, llm, scheduler, store, guards, rag, metrics, experiments, api, cli)
  guards/         pii.py, ipi.py, llama_guard.py, modes.py, runner.py  (detection vs enforcement separated)
  llm/            base.py (protocol), ollama.py (REST client), mock.py (offline deterministic)
policies/         access_policy.yaml, users.yaml, guard_policy.yaml, active.json  (versioned; validated on load)
experiments/      *.json manifests (smoke_mock, smoke_live, rq2_defenses)
ui/               streamlit_app.py  (FastAPI client only)
scripts/          pull_models.ps1, live_smoke.ps1
tests/            unit + integration
docs/             DESIGN.md  (decisions, sources, threat model, schemas, metrics, 4-week plan, caveats)
data/, var/       generated datasets / runtime artifacts (gitignored)
```

## 10. Roles (who edits what)

- **Legal (Role 1):** `policies/*.yaml`, legal-basis refs, PII grades and disclosable types. Policies are
  versioned and validated before activation; replacing legislation documents does **not** change executable
  policy.
- **Backend (Role 2):** `ragsec/` serving, store, scheduler, hooks, API.
- **Security (Role 3):** fill `[IPI_PAYLOAD_PLACEHOLDER]` in `ragsec/dataset_gen.py` attack scaffolds with
  reviewed templates; tune `ragsec/guards/ipi.py` rules and `policies/guard_policy.yaml`; review ground truth.
- **UI/Metrics (Role 4):** `ui/streamlit_app.py`, `ragsec/metrics.py`, result tables and figures.

See [docs/DESIGN.md](docs/DESIGN.md) for the full design, interfaces and the bug/pitfall report.

---

## 11. Security design (Ollama infrastructure)

This section is **infrastructure-security background and application-level attack-surface reduction**. It is
separate from, and does not affect, the measured IPI research outcomes. These application controls are **not a
patch** for any Ollama vulnerability — vendor patching (keeping Ollama up to date) is the actual remediation.

### 11.1 Supported / verified Ollama versions
- **Verified on 2026-10-28:** this machine runs Ollama **0.40.12** (seen 0.40.11 → auto-updated), which is at
  or above every fixed version listed below.
- Verify your version: `uv run ragsec doctor` (uses the admin client) or `scripts\pull_models.ps1`.

### 11.2 Relevant advisories (verify against the authoritative source before relying on exact numbers)
Distinct issues, treated separately. CVSS/version values are quoted from the cited advisory; where a field was
not loadable from the primary record it is marked accordingly. Verified 2026-10-28.

| Identifier | Type | Affected | Fixed | Source (authoritative) |
|---|---|---|---|---|
| CVE-2026-7482 "Bleeding Llama" | heap out-of-bounds read in GGUF loader | ≤ 0.17.0 (per secondary) | **0.17.1** (per secondary) | GitHub advisory **GHSA-x8qc-fggm-mpqg** (High). CVSS 9.1 / fixed 0.17.1 are from secondary sources — confirm on GHSA/NVD. |
| CVE-2026-108836 | **SSRF (CWE-918)** in Pull API | ≤ 0.34.1 | **0.34.2** | GitHub advisory **GHSA-fr42-jr2w-mx59**, CVSS v4 5.5 (Moderate) — confirmed from the advisory. |
| CVE-2026-85180 | redirect SSRF (model pull) | ≥0.30.0–0.33.2 (per secondary) | not confirmed (awaiting NVD) | secondary; verify on NVD/GHSA. |
| CVE-2026-5530 | model-pull SSRF | ≤ 0.18.1 (per third-party) | unconfirmed | third-party write-up; verify. |

Our installed Ollama is **0.40.12**. For the **two advisories whose fixed version we confirmed from an
authoritative source** — CVE-2026-108836 (0.34.2, GitHub advisory) and, per secondary sources pending primary
confirmation, CVE-2026-7482 (0.17.1) — 0.40.12 is at or above that fixed version. We do **not** claim that
0.40.12 fixes *every* cited or uncited Ollama vulnerability: CVE-2026-85180 and CVE-2026-5530 have unconfirmed
fixed versions, and new issues appear over time. Keeping Ollama patched is an ongoing operational duty. This
project does **not** remediate any CVE; it only reduces the application's own attack surface (below).

### 11.3 Windows binding configuration (and restart)
- **Connecting to 127.0.0.1 does not prove the server listens only on loopback.** Ollama may also listen on
  `0.0.0.0` / `::` via the `OLLAMA_HOST` environment variable. Only inspecting the listeners can establish this.
- Preflight (point-in-time): `.\scripts\preflight_binding.ps1 -Port 11434`. It fails on wildcard/non-loopback
  listeners, names the owning process, exits non-zero on failure or indeterminate result, and must be re-run
  after any Ollama restart or `OLLAMA_HOST` change.
- To bind loopback-only: ensure `OLLAMA_HOST` is unset or `127.0.0.1`, then restart Ollama (quit the tray app
  or `Stop-Process -Name ollama` and relaunch). `setx OLLAMA_HOST 127.0.0.1` persists it for new sessions.

### 11.4 Runtime endpoint restrictions and administrative separation
- The **experiment runtime** inference client (`ragsec/llm/ollama.py`) may call only `POST /api/chat`,
  `POST /api/generate`, `POST /api/embed` (allowlist, enforced before transmission). All management/diagnostic
  endpoints (`/api/pull`, `/api/create`, `/api/push`, `/api/delete`, `/api/copy`, blobs, `/api/ps|tags|version`)
  are rejected. It sets `follow_redirects=False`, `trust_env=False`, treats 3xx as errors, and never auto-pulls.
- **Diagnostics** (`/api/version`, `/api/tags`, `/api/ps`) live only in a separate **admin client**
  (`ragsec/llm/admin.py`), used by `ragsec doctor` and the experiment pre-run manifest — never by FastAPI,
  Streamlit, or RAG request handling. The connection URL is loopback-validated at startup (invalid → no start).

### 11.5 Disabling automatic downloads and cloud features
- Automatic model downloads are impossible from the runtime (no `/api/pull`; missing model → explicit error).
  Provision models administratively and separately: `ollama pull <model>` (see §3).
- If your Ollama build supports cloud-model execution, treat it as a **separate security boundary** and disable
  it per that version's documentation; this project neither enables nor relies on it.

### 11.6 Experimental assumptions and limits
1. No public port exposure, tunnels, or reverse proxies are used (single local machine).
2. **Loopback is not authentication or isolation from other local processes** — any local process/user can
   reach `127.0.0.1:11434`. These controls reduce *this application's* attack surface, not local-process risk.
3. These changes do **not** eliminate all Ollama SSRF or memory-safety vulnerabilities; keep Ollama patched.
4. Infrastructure-security background (this section) is kept separate from the measured IPI research outcomes.
