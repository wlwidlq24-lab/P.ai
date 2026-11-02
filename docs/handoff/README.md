# ragsec 백엔드 핸드오프 패키지

작성자: 백엔드 엔지니어 / 기술 문서 담당 · 기준일: 2026-11-01
대상 독자: Legal(Role 1), Security/Guardrail(Role 3), UI/UX·Metrics(Role 4) 팀원

> 이 문서는 **회의 전 5분 안에 읽을 수 있는 요약본**입니다. 상세 스키마·예시·계약은 아래 개별 문서에 있습니다.
> 모든 구현 주장에는 소스 파일 경로가 붙어 있고, "검증(verified)"은 이번 리뷰에서 실제로 실행해 확인한 것만을 뜻합니다.

---

## 1. 지금 확실히 되는 것 (이번 리뷰에서 실행해 확인)

- `uv run pytest -q` → **151개 전부 통과(9~16초, GPU 불필요, mock 백엔드)**. 2026-11-01 직접 실행함.
- **mock 백엔드 기준** 전체 파이프라인(인증 → 임베딩 → 권한 검색 → 다단계 가드 훅 → 생성 → 액션 파싱 → 유출 측정 → JSONL 기록)이 end-to-end로 동작. 근거: [ragsec/rag.py](../../ragsec/rag.py), [tests/test_rag_pipeline.py](../../tests/test_rag_pipeline.py)
- 버전 관리형 벡터 인덱스(스테이징→검증→활성화→롤백)와 **fail-closed 권한 필터**: [ragsec/store.py](../../ragsec/store.py)
- 합성 데이터셋 생성(포맷은 유효하지만 체크섬은 틀린 canary): [ragsec/dataset_gen.py](../../ragsec/dataset_gen.py), 생성물 [data/synthetic/v1/](../../data/synthetic/v1/)
- 지표 집계(ASR/UPDR/FPR/탐지 F1/지연/McNemar/부트스트랩 CI): [ragsec/metrics.py](../../ragsec/metrics.py)
- FastAPI 11개 엔드포인트 + Streamlit 콘솔(백엔드 API로만 통신): [ragsec/api.py](../../ragsec/api.py), [ui/streamlit_app.py](../../ui/streamlit_app.py)

## 2. 아직 **실험 결과로 주장할 수 없는 것** (가장 중요)

- **공격 효능 수치(ASR/UPDR 등)는 현재 N/A입니다.** 모든 공격 문서는 `[IPI_PAYLOAD_PLACEHOLDER]`만 담고 있어 "활성 공격"이 아니며, Security 팀원의 사람 검토(review)가 끝난 payload가 하나도 없습니다. 스키마가 구조적으로 미검토 공격의 실험 집계를 **거부**합니다. 근거: [schemas.py `Case._eligibility_requires_review`](../../ragsec/schemas.py), [metrics.py `is_eligible`](../../ragsec/metrics.py)
- **실제 법령·업무 문서 코퍼스가 아직 없습니다.** 지금 인덱스에는 합성 문서만 있습니다. 법령/지침 검색은 "파이프라인은 되지만 실제 코퍼스 미투입" 상태입니다.
- **라이브(Ollama) 실행은 이번 리뷰에서 실행하지 않았습니다.** 코드는 구현되어 있으나, 이번 검토 범위에서 GPU 라이브 end-to-end는 돌리지 않았으므로 "라이브 검증 완료"라고 말하지 않습니다. 자세한 상태 구분은 [01_project_status.md](01_project_status.md).

## 3. 각 팀원이 바로 할 일 (한 줄 요약)

| 역할 | 다음 액션 | 상세 문서 |
|---|---|---|
| **Legal (Role 1)** | 법령/지침/내부정책 문서를 **정해진 폴더·메타데이터 형식**으로 제출 (형식은 이미 확정, 선택 아님) | [03_legal_data_submission.md](03_legal_data_submission.md) |
| **Security/Guardrail (Role 3)** | 가드 훅은 이미 연결됨 → 각 단계 **검출 로직/임계값**을 채우고, A/B/C/D 조건을 manifest로 구성, `[IPI_PAYLOAD_PLACEHOLDER]` 검토·승인 | [04_guardrail_integration.md](04_guardrail_integration.md) |
| **UI/UX·Metrics (Role 4)** | 확정된 **엔드포인트·요청/응답 스키마·상태값**으로 프런트 독립 설계 | [05_uiux_backend_contract.md](05_uiux_backend_contract.md) |

## 4. 문서 목록

- [01_project_status.md](01_project_status.md) — 요구사항별 진행 상태표(근거 포함) + 평이한 한국어 설명
- [02_backend_architecture.md](02_backend_architecture.md) — 컴포넌트 구조·수집 흐름·질의 흐름(Mermaid) + 신뢰 경계
- [03_legal_data_submission.md](03_legal_data_submission.md) — Legal 제출 형식·메타데이터 스키마·예시·체크리스트·요청문
- [04_guardrail_integration.md](04_guardrail_integration.md) — 가드 통합 지점·훅 계약·A/B/C/D·지표 정의
- [05_uiux_backend_contract.md](05_uiux_backend_contract.md) — 백엔드 API 계약·JSON 예시·UI 상태
- [templates/document_metadata.template.json](templates/document_metadata.template.json) — 복붙용 메타데이터 템플릿
- [templates/submission_index.template.csv](templates/submission_index.template.csv) — 제출 묶음 색인 템플릿

## 5. 이번 핸드오프에서 백엔드가 직접 변경한 것

1. `GuardPolicy.llama_guard_block_categories` 기본값 `["S7","S14","S2"]` → `["S7","S2"]`. (llama-guard3:1b에는 S14가 없음 — 존재하지 않는 카테고리로 차단하면 조용히 영원히 안 걸림. 권위 있는 값은 이미 [policies/guard_policy.yaml](../../policies/guard_policy.yaml)에 `[S7, S2]`로 있었음.) 파일: [ragsec/schemas.py](../../ragsec/schemas.py)
2. Streamlit 콘솔이 현재 API가 더 이상 반환하지 않는 필드(`ollama_reachable`/`ollama_version` on `/health`, `resident`/`ps_error` on `/models/status`)를 읽어 **항상 "Ollama down" 표시 + Models 탭 오류**가 나던 것을 실제 반환 필드로 정정. 파일: [ui/streamlit_app.py](../../ui/streamlit_app.py)

두 변경 모두 기존 동작을 깨지 않으며, 변경 후 `pytest` 151개 전부 통과·UI 컴파일 확인.
