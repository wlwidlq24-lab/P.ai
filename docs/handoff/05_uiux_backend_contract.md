# 05. UI/UX 백엔드 계약 (UI/UX·Metrics / Role 4)

기준일: 2026-11-01 · 기준 구현: [api.py](../../ragsec/api.py), [schemas.py](../../ragsec/schemas.py). 현재 참고 UI: [ui/streamlit_app.py](../../ui/streamlit_app.py)

> **2026-11-02 구현 업데이트**: `QueryResponse`에 **구조화 인용**이 추가되었습니다 — `citations[]`(label·document_id·
> version·chunk_id·display_title·article_label/title·char_start/end·provenance_url), `invalid_citations[]`(제공되지
> 않은 근거를 인용한 경우), `uncited_evidence_labels[]`, `citation_policy`. 모델에는 `[E1]` 형식 라벨만 인용하도록
> 지시하며 백엔드가 검증합니다(존재하지 않는 라벨 인용 → invalid로 보고; 기본 정책 annotate, `block` 선택 가능).
> 또한 **인증이 2모드**가 되었습니다: `legacy`(공유 키, 기본) / `multiuser`(사용자별 토큰 → 신원·tenant·role 매핑).
> `/documents`·`/index/activate`·`/index/rollback`·`/policies/reload`·`/experiments/run`·`cancel`·`log`·`metrics`는
> **관리자 권한** 필요(multiuser에서 비관리자 → 403). `/query`는 요청 `user_id`가 인증 주체와 일치해야 함(스푸핑 → 403).
>
> 이 문서로 프런트를 **독립 설계**할 수 있습니다. 여기 적힌 엔드포인트·필드는 모두 **현재 구현된 것**이며, 아직 없는 것은 "🟨 제안"으로 표시했습니다. mock 응답을 "동작하는 엔드포인트"로 오해하지 마세요.
> 백엔드 구현 주장은 [api.py](../../ragsec/api.py)로 검증 가능하고, mock 기준으로 [tests/test_api.py](../../tests/test_api.py)가 통과합니다. 라이브(Ollama) 기동은 이번 리뷰에서 실행하지 않았습니다.

## 1. 인증·공통 규약

- `GET /health`를 제외한 **모든 요청에 `X-API-Key` 헤더** 필요. 불일치 시 인증 오류. 근거: [api.py](../../ragsec/api.py) `auth`.
- 단일 워커로 실행: `uv run uvicorn ragsec.api:app --host 127.0.0.1 --port 8000` (잡 상태·GPU 락이 in-process).
- **인증 한계(디자인에 반영할 것)**: 키는 1개 공유이고, 요청의 `user_id`는 신뢰 입력입니다. 즉 UI의 "사용자 선택"은 **운영 로그인이 아니라 역할 시뮬레이션**입니다(연구 테스트베드). 다중 사용자 실로그인은 🟨 제안.

### 두 가지 오류 응답 형태 (구분 필수)
1. **사전검증(pre-flight) 오류** → `RagSecError` JSON. 예: 잘못된 API 키, 알 수 없는 `user_id`, 허용목록 외 모델.
   ```json
   { "code": "UNKNOWN_USER", "message": "unknown user_id 'u_x'", "detail": {} }
   ```
2. **파이프라인 내부 오류/차단** → `QueryResponse` 본문 유지, HTTP 상태만 바뀜. 예: 타임아웃(504), 권한 필터 누락(403), 내부 오류(500). 본문의 `status`/`error_code`로 판별. 근거: [api.py](../../ragsec/api.py) `_HTTP_STATUS_FOR`.

## 2. 지원 워크플로 (일반 사용자 vs 연구자 분리)

| 구분 | 워크플로 | 엔드포인트 |
|---|---|---|
| **개인정보 담당자(일반)** | 질문→답변+근거 보기, (선택)문서 업로드 | `POST /query`, `POST /documents` |
| **연구자(실험 전용)** | A/B/C/D 실험 제출·모니터·지표/로그 다운로드, 인덱스/정책 관리, 모델 상태 | `POST /experiments/run`, `GET /experiments/{id}`, `.../log`, `.../metrics`, `POST /experiments/{id}/cancel`, `GET/POST /index*`, `POST /policies/reload`, `GET /models/status`, `GET /cases`, `GET /users` |

UI는 이 둘을 **화면/권한으로 분리**하세요(일반 담당자에게 실험·정책 관리 노출 금지).

## 3. 엔드포인트 계약 + JSON 예시

### 3.1 `GET /health` (인증 불필요)
로컬 상태만 보고(Ollama 도달성/버전은 여기서 확인하지 않음 — 관리 분리).
```json
{ "status": "ok", "backend": "mock", "ollama_url": "http://127.0.0.1:11434",
  "active_index": "v20261101...-ab", "policy_versions": {"access_policy": "kr-fin-access@1.0.0", "...": "..."},
  "vram_profile": "vram_6gb",
  "note": "Ollama reachability/version are checked administratively (ragsec doctor), not here." }
```
- `status`가 `"degraded"`면 정책 로드 실패 등 → 배너 경고.

### 3.2 `POST /query` → `QueryResponse`
요청 바디(`QueryRequest`, [schemas.py](../../ragsec/schemas.py)):
```json
{ "user_id": "u_comp_a", "query": "고객 문의 이메일을 요약해 주세요.",
  "subject_id": null, "guard_mode": "HYBRID",
  "stages": ["INGESTION", "PRE_GENERATION", "POST_GENERATION"],
  "target_model": "exaone3.5:2.4b", "access_control_mode": "ENFORCED",
  "normalization": {"detect_on_normalized": true, "generate_from_normalized": false} }
```
응답(핵심 필드):
```json
{ "request_id": "req-20261101...-a1b2",
  "answer": "고객 문의는 ... 입니다.",
  "blocked": false, "final_blocking_stage": null, "block_reasons": [],
  "retrieved": [
    { "chunk_id": "doc_x::v1::c0::ab12cd34", "document_id": "doc_x", "document_version": 1,
      "source_trust_level": "medium", "distance": 0.31, "decision": "ALLOW",
      "preview_masked": "고객명 [REDACTED:name] 문의 ..." }
  ],
  "actions": [],
  "enforcement": [ { "stage": "PRE_GENERATION", "artifact_id": "doc_x::v1::c0::...",
                     "decision": "ALLOW", "reasons": [], "plugins": ["pii_regex","ipi_rules"],
                     "transformations": [] } ],
  "timings": { "embedding_ms": 12.3, "retrieval_ms": 4.1, "inspection_pre_ms": 30.2,
               "generation_ms": 820.5, "inspection_post_ms": 25.0, "total_ms": 900.0 },
  "target_model": "exaone3.5:2.4b", "guard_mode": "HYBRID", "access_control_mode": "ENFORCED",
  "status": "ok", "error_code": null }
```
UI 표시 규칙:
- **답변**: `answer`. **근거**: `retrieved[]`의 `preview_masked`만 노출(원문·비마스킹 PII 금지). `decision`/`distance`/`source_trust_level`은 배지로.
- **액션**: `actions[]`는 시뮬레이션. `executed`/`reason`(예: `EGRESS_NOT_ALLOWLISTED`) 표시. 실제 전송 아님을 명시.
- **타이밍**: `null`이 아닌 키만 표시.

### 3.3 `POST /documents` (multipart)
`file`(.pdf/.txt) + `metadata`(JSON 문자열, `DocumentMetadataIn`) + `auto_activate`(기본 true). 응답:
```json
{ "ingestion_run_id": "ing-...", "index_version": "v...", "activated": true,
  "documents": [{"document_id":"doc_x","document_version":1,"chunks":5,"...":"..."}],
  "skipped_duplicates": [], "validation_errors": [], "file_type": "txt", "safe_filename": "doc_x.txt" }
```
메타데이터 형식은 [03_legal_data_submission.md](03_legal_data_submission.md) §5. 검증 실패 시 `MetadataValidationError`(사전검증 오류 형태).

### 3.4 연구자 엔드포인트
- `GET /models/status` →
  ```json
  { "profile": {"name":"vram_6gb","...":"..."}, "ollama_version": "0.40.12", "snapshot_present": true,
    "models": {"exaone3.5:2.4b": {"available": true, "digest": "...", "parameter_size": "2.4B"}},
    "scheduler_tracked_resident": ["exaone3.5:2.4b"], "scheduler_switches": 3,
    "note": "Live residency/VRAM is not queried at runtime. Run `ragsec doctor` for live diagnostics." }
  ```
  (⚠️ 과거 UI가 읽던 `resident`/`ps_error` 키는 **없음**. `scheduler_tracked_resident` 사용.)
- `GET /users` → `[{user_id, display_name, role, tenant_id, synthetic}]`
- `GET /cases?dataset_dir=synthetic/v1` → `[{case_id, case_type, attack_family, language, unicode_transform, split, user_id, subject_id, query}]`
- `POST /experiments/run` (바디 `ExperimentManifest`) → `{run_id, experiment_id, status, ...}`
- `GET /experiments/{run_or_experiment_id}` → `{status, done, total, errors, ...}` + 완료 시 `metrics`(집계 JSON) 포함
- `POST /experiments/{run_id}/cancel` → 잡 상태
- `GET /experiments/{run_id}/log` → `requests.jsonl` 파일 다운로드
- `GET /experiments/{run_id}/metrics?format=csv|json` → 지표 파일 다운로드
- `GET /index`, `POST /index/activate/{version}`, `POST /index/rollback`, `POST /policies/reload`

실험 모니터링: `done`/`total`/`errors`로 진행바. `status ∈ {running, completed, failed, cancelled}`. 완료 시 `metrics.groups`를 조건별 표로(예: condition, n, ASR_valid.rate, UPDR_attack.rate, FPR_block.rate, detection.f1, latency_warm.p50_ms). 참고 렌더링: [ui/streamlit_app.py](../../ui/streamlit_app.py) 실험 탭.

## 4. 상태(state) 처리 — UI가 반드시 구분할 것

| 상태 | 판별 | UI 처리 |
|---|---|---|
| 로딩 | 요청 진행 중 | 스피너. `/query`는 수 초~수십 초 가능(비스트리밍) |
| 정상 답변 | `status=="ok"`, `blocked==false`, `answer != 근거없음 문구` | 답변+근거 표시 |
| 근거 없음 | `status=="ok"`, `answer=="권한 범위 내에서 관련 근거 문서를 찾을 수 없어..."` | "권한 내 근거 없음" 안내(권한 부족과 구분) |
| 차단됨 | HTTP 200, `blocked==true` | "보안 정책에 따라 차단" + `block_reasons`(코드) 표시, **원문 미노출** |
| 권한 거부 | HTTP 403, `error_code=="AUTHZ_FILTER_MISSING"` | "권한이 없어 처리할 수 없음" (문서 내용/메타데이터 노출 금지) |
| 빈 상태 | `retrieved==[]` | "표시할 근거 없음" |
| 실패 | `status∈{error,timeout}` 또는 사전검증 오류 JSON | 사용자 친화 메시지 + `error_code`(예: `MODEL_TIMEOUT`). 스택/상세 노출 금지 |

**정보 비노출 원칙**: 근거 부족·권한 없음·가드 차단을 알릴 때 제한 문서의 내용이나 불필요한 메타데이터(원문, 비마스킹 PII, 내부 경로)를 **드러내지 마세요**. 노출 가능한 것은 `block_reasons`/`error_code` 같은 코드와 `preview_masked`뿐입니다.

## 5. 스트리밍·출처 표시 현황

- **스트리밍 미구현(🟨 제안)**: 생성은 비스트리밍이고, **POST 검사 완료 전에는 토큰을 반환하지 않는다**는 설계라 SSE/토큰 스트리밍 엔드포인트가 없습니다. UI는 "완료 후 한 번에 표시" 전제로 설계하세요(진행 표시는 스피너).
- **출처 표시**: 현재는 `retrieved[]`(근거 청크 목록)만 제공. 답변 본문 내 인라인 각주/조문 번호는 🟨 제안(미구현) — [02_backend_architecture.md](02_backend_architecture.md) §7.

## 6. UI 동작에 영향 주는 백엔드 한계 (요약)

- 단일 GPU 직렬화 → 동시 `/query`는 큐잉됨(동시성 1). 라이브에서 응답이 느릴 수 있음.
- 비스트리밍 → 긴 대기. 타임아웃은 504.
- 실험 잡 상태는 in-process → 서버 재시작 시 진행 중 잡 소실(단일 워커 전제).
- 라이브 모델 미기동/미pull 시 `/query`가 `MODEL_UNAVAILABLE`/`MODEL_NOT_FOUND`(503) 반환 → UI는 "모델 준비 필요(ragsec doctor)" 안내.
- `/models/status`·`ollama_version`은 **캐시된 관리 스냅샷**(마지막 `ragsec doctor`/실험 pre-run 기준)이며 실시간 조회가 아님 → "최신 아님" 가능성을 문구로.

> 백엔드는 계약·상태·예시를 제공합니다. **최종 비주얼 디자인/프런트 구현은 UI/UX 몫**입니다.
