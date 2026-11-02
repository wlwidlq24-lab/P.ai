# 01. 프로젝트 진행 상태 (근거 기반)

기준일: 2026-11-01 · 작성자: 백엔드 엔지니어

## 상태 표기 규칙

| 표기 | 의미 |
|---|---|
| ✅ 검증 | 이번 리뷰에서 실제로 실행/테스트해 확인함 |
| 🟦 구현됨(미실행) | 코드는 있으나 이번 리뷰에서 (라이브로) 실행하지는 않음 |
| 🟨 부분 구현 | 핵심은 되지만 일부가 빠졌거나 실데이터 미투입 |
| ⬜ 계획/미구현 | 아직 없음 |
| ❔ 불명 | 근거 부족으로 판단 불가 |

> "검증"은 **라이브 Ollama end-to-end**를 뜻하지 않습니다. 테스트 스위트는 `mock` 백엔드로 돌아가며(151개 통과, GPU 불필요), 라이브 모델 경로는 이번 리뷰에서 실행하지 않았습니다.

## 진행 상태표

| 요구사항 | 상태 | 근거(파일/함수) | 지금 되는 것 | 남은 일 | 담당 |
|---|---|---|---|---|---|
| 로컬 모델 실행 | 🟦 구현됨(미실행) | [llm/ollama.py](../../ragsec/llm/ollama.py) `OllamaClient`, [llm/mock.py](../../ragsec/llm/mock.py) | mock 백엔드는 ✅ 결정론적 실행. Ollama 클라이언트는 allowlist(POST chat/generate/embed)·loopback 검증 구현 | 라이브 1회 실행으로 모델 응답/지연 확인(`ragsec doctor` + 작은 run) | Backend |
| 문서 수집·파싱(PDF/TXT) | ✅ 검증 | [parsing.py](../../ragsec/parsing.py) `parse_document`, [tests/test_parsing.py](../../tests/test_parsing.py) | 크기·확장자·매직바이트·인코딩(UTF-8/16/CP949) 검증, 암호화/스캔 PDF 거부 | 실제 법령 PDF로 추출 품질 점검(코퍼스 투입 후) | Backend/Legal |
| 청크 분할·임베딩 | 🟨 부분 구현 | [ingestion.py](../../ragsec/ingestion.py) `embed_batched`, [textproc.py](../../ragsec/textproc.py) `chunk_text` | 문자 기준 청크·배치 임베딩·차원 일관성 검사. mock 임베딩 ✅ | 실제 `bge-m3` 임베딩 품질/차원(1024) 라이브 확인; 조문 인지형 청킹은 미지원 | Backend |
| 벡터 DB 색인·검색 | ✅ 검증 | [store.py](../../ragsec/store.py) `ChromaRepository`, [tests/test_authz_and_store.py](../../tests/test_authz_and_store.py) | 버전형 컬렉션·스테이징→검증→활성화→롤백·cosine 검색 | 대규모 코퍼스에서 top-k·max_distance 튜닝 | Backend |
| 검색 기반 답변 생성 | 🟦 구현됨(미실행) | [rag.py](../../ragsec/rag.py) `RagService._answer` | mock 경로 ✅ end-to-end. 비스트리밍 생성, POST 검사 전엔 토큰 미반환 | 라이브 생성 1회 확인 | Backend |
| 출처 표시(citation) | 🟨 부분 구현 | [schemas.py](../../ragsec/schemas.py) `QueryResponse.retrieved`(RetrievedChunkView) | 검색된 근거 청크 목록(doc_id·trust·거리·마스킹 미리보기) 반환 ✅ | **답변 본문 내 인라인 각주/출처 번호는 미구현** | Backend/UI |
| 법령·지침·내부정책 검색 | 🟨 부분 구현 | 검색 파이프라인은 [rag.py](../../ragsec/rag.py); 분류는 `document_kind`([schemas.py](../../ragsec/schemas.py)) | 유사도+권한 기반 검색은 동작 | **실제 법령 코퍼스 미투입**; `document_kind`별로 범위를 좁히는 전용 검색은 미구현 | Legal→Backend |
| 업무 문서 검토 | 🟨 부분 구현 | 동일 파이프라인 | 합성 업무 문서로 동작 | 실제(합성) 업무 문서 세트 설계·투입 | Legal→Backend |
| 사용자 식별·접근통제 | 🟨 부분 구현 | [store.py](../../ragsec/store.py) `build_where`/`assert_authz_filter`/`is_authorized`, [policy.py](../../ragsec/policy.py) | tenant/role/pii-grade/유효일자 필터, **fail-closed**. ✅ 테스트됨 | **인증은 공유 `X-API-Key` 1개뿐**; 요청의 `user_id`는 "신뢰된 입력"으로 받음(개인 로그인 아님) — 신뢰 경계 주의(02 문서) | Backend |
| 합성 제한 PII 데이터 | ✅ 검증 | [dataset_gen.py](../../ragsec/dataset_gen.py), [data/synthetic/v1/](../../data/synthetic/v1/) | 포맷 유효·체크섬 무효 canary, grade/role/tenant 라벨 | 데이터 다양성 확대(선택) | Backend/Legal |
| 공격 문서 수집·검색 | 🟨 부분 구현 | 공격 문서 [data/synthetic/v1/documents/doc_attack_*](../../data/synthetic/v1/documents/) | 수집/검색 배선 ✅ (plumbing) | **모든 공격 문서가 `[IPI_PAYLOAD_PLACEHOLDER]`** → 활성 공격 아님 | Security |
| 가드레일 통합 지점 | ✅ 검증 | [guards/](../../ragsec/guards/) `base.py`/`runner.py`/`modes.py` | INGESTION/PRE/POST 3단계 훅 + 검출↔집행 분리 + 5개 플러그인 연결 | 각 플러그인의 검출 로직/임계값 고도화는 Security 몫 | Security |
| A/B/C/D 조건 지원 | 🟦 구현됨(미실행) | [schemas.py](../../ragsec/schemas.py) `GuardMode`/`ExperimentManifest.guard_modes` | 조건 조합을 manifest 그리드로 구성 가능(배선 ✅) | 검토된 공격으로 실제 A/B/C/D 1회 실행 | Security/Backend |
| 로깅·평가 데이터 | ✅ 검증 | [schemas.py](../../ragsec/schemas.py) `RequestRecord`, [logstore.py](../../ragsec/logstore.py), [metrics.py](../../ragsec/metrics.py) | 요청당 JSONL 1줄(원문 PII·완전 프롬프트 미포함), 지표 집계 | — | Backend/Metrics |
| 백엔드 API 준비 | 🟦 구현됨(미실행) | [api.py](../../ragsec/api.py), [tests/test_api.py](../../tests/test_api.py) | 11개 엔드포인트, mock 기준 ✅ 테스트 | 라이브 서버 기동 1회 점검 | Backend |
| 엔드투엔드 프로토타입 | 🟨 부분 구현 | [experiments/smoke_mock.json](../../experiments/smoke_mock.json), [experiments/smoke_live.json](../../experiments/smoke_live.json) | mock end-to-end ✅ | 라이브 데모 = 모델 pull + `smoke_live` 1회 | Backend |
| 비교 실험 분석 준비 | 🟨 부분 구현 | [metrics.py](../../ragsec/metrics.py) `paired_comparison`/`aggregate` | 틀(쌍대 비교·McNemar·클러스터 부트스트랩 CI) 완비 | **적격 공격 케이스 0개 → ASR/UPDR이 N/A**. 검토된 payload 필요 | Security→Metrics |

## 평이한 한국어 설명

### 지금 시스템이 할 수 있는 일
합성 금융 문서를 벡터 DB에 넣고, 사용자의 역할/소속/열람등급/유효일자에 맞는 문서만 꺼내 LLM에게 넘겨 한국어로 답하게 합니다. 꺼내는 순간·답하기 전·답한 뒤 세 지점에서 검사 훅이 돌고, "밖으로 보내기" 동작은 실제 네트워크가 아니라 **로컬 가짜 싱크(mock sink)** 로만 흘러가 실제 유출이 불가능합니다. 이 전 과정이 `mock` 백엔드에서 실제로 돌아가며 테스트 151개가 통과합니다.

### 신뢰할 만한 데모에 필요한 것
(1) `ollama pull`로 모델 3종 내려받기 → (2) `ragsec doctor`로 환경 확인 → (3) `experiments/smoke_live.json` 1회 실행. 이러면 "라이브로 돈다"를 눈으로 보여줄 수 있습니다. (현재는 mock 데모만 즉시 가능.)

### 재현 가능한 보안 실험에 필요한 것
Security 팀원이 `[IPI_PAYLOAD_PLACEHOLDER]` 자리에 **검토·승인된** 공격 템플릿을 채우고, 그 케이스를 `review.status="reviewed"`로 승인해야 합니다. 그래야 스키마 게이트가 열려 실험이 실행되고 ASR/UPDR이 숫자로 나옵니다. 그 전까지 모든 공격 지표는 정직하게 **N/A**로 보고됩니다(0%가 아니라 "측정 대상 없음").

### 아직 근거로 주장할 수 없는 것
- 가드레일이 공격을 "몇 % 막는다"는 수치 — 활성 공격이 없어서 측정 불가.
- 라이브 모델의 실제 응답 품질/지연 — 이번 리뷰에서 라이브 미실행.
- 실제 한국 법령 검색 정확도 — 실제 코퍼스 미투입.
