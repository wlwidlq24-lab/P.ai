# 메타데이터 템플릿 필드 설명 (document_metadata.template.json)

> JSON 본문은 그대로 유효한 `DocumentMetadataIn`(doc-meta/1.1) 레코드입니다. 설명은 payload를 깨지 않도록 이 파일로 분리했습니다. `CHANGE_ME_id`와 값들을 실제 값으로 교체하세요.

## 필수
- `document_id` — 영숫자/`._-`, 2~121자. 파일명 base와 일치.
- `document_version` — 정수 ≥1. 내용이 바뀌면 올림.
- `source_name` — 문서 제목(1~200자).
- `source_type` — `statute_db` | `internal_wiki` | `crm_record` | `customer_email` | `uploaded_file` | `partner_feed`
- `source_trust_level` — `high` | `medium` | `low` | `untrusted` (법령/승인정책=high)
- `document_kind` — `legislation` | `internal_policy` | `business_document` | `experimental_document`
- `pii_grade` — `none` | `general` | `credit` | `unique_id` | `sensitive` (`none`이면 `pii_types`=[])
- `tenant_id` — tenant 레지스트리에 존재하는 값(기본 `bank_a`/`bank_b`)
- `allowed_roles` — access_policy에 존재하는 역할(≥1): `teller` | `credit_officer` | `compliance` | `general_staff`
- `law_or_policy_id` — `legislation`/`internal_policy`는 필수(비-null)

## 선택 (doc-meta/1.1에서 추가)
- `issuing_organization` — 발행기관명(≤200자). 없으면 `null`.
- `source_url` — 출처 URL. **http(s)만 허용**, **provenance 전용 — 백엔드가 절대 가져오지(fetch) 않음**. 없으면 `null`.
- `publication_date` — 공표일(ISO8601). `effective_from`(효력 시작)과 **구분**. 없으면 `null`.
- `review_status` — `draft` | `submitted` | `in_review` | `approved` | `rejected` | `not_applicable`. **선언적 메타데이터**이며, 수집 성공이 승인을 의미하지 않음. 기본 `draft`.

## 선택 (공통)
- `jurisdiction`(기본 `KR`), `effective_from`/`effective_to`(ISO8601, 구간 `[from,to)`), `supersedes_document_id`, `pii_types`, `subject_id`.

## 네 가지 시간의 구분
`publication_date`(공표) ≠ `effective_from/to`(법적 효력) ≠ 수집시각(`created_at`, 백엔드 자동) ≠ 사람 검토 시각(별도 기록). 서로 섞지 마세요.
