# 03. 개인정보·법령 데이터 제출 규격 (Legal / Role 1)

기준일: 2026-11-01 (구현 업데이트 2026-11-02) · 기준 구현: [schemas.py `DocumentMetadataIn`](../../ragsec/schemas.py), [ingestion.py](../../ragsec/ingestion.py), [parsing.py](../../ragsec/parsing.py), [submission.py](../../ragsec/submission.py)

> **2026-11-02 구현 업데이트**: 이전에 "🟨 제안"이던 `issuing_organization`, `source_url`, `publication_date`,
> `review_status`가 **실제 스키마(doc-meta/1.1)에 구현**되었습니다(모두 선택, 하위호환). `source_url`은 **provenance
> 전용이며 백엔드가 절대 fetch하지 않습니다**(http/https만 허용). `review_status`는 **선언적 메타데이터**이며 수집
> 성공이 승인을 의미하지 않습니다. 또한 조문 인지형(article-aware) 세그멘테이션([legalseg.py](../../ragsec/legalseg.py))과
> 제출 처리 CLI(`ragsec submit --dry-run`, `ragsec validate-index`)가 추가되었습니다.
>
> **마이그레이션**: 기존 `doc-meta/1.0` 레코드·인덱스는 그대로 유효합니다(새 필드는 None/기본값으로 로드). 새 제출물은
> `doc-meta/1.1`을 사용하세요. 인덱스를 다시 빌드할 필요는 없습니다(점진적 적용). 조문 인지형 청킹은 기본 꺼짐이며
> `RAGSEC_ARTICLE_AWARE_CHUNKING=true`로 켭니다.
>
> **제출 처리 흐름(확정)**: `ragsec submit <dir> --dry-run`으로 먼저 검증(활성 인덱스 변경 없음) → 통과하면
> `ragsec submit <dir>`로 적재(중복 자동 스킵·멱등). `ragsec validate-index <csv>`는 서비스 없이 인덱스만 검증합니다.

> 이 규격은 **선택지 나열이 아니라 확정안**입니다. 현재 수집 구현(`DocumentMetadataIn` + `POST /documents`)에 맞춰 바로 제출하면 됩니다. 아직 확립되지 않은 부분은 **단순 기본값을 골라 "제안 계약(proposed contract)"으로 표시**했습니다.
>
> ⚠️ **법령 원문 주의**: 이 문서의 모든 법령/정책 예시는 **가상의 플레이스홀더**이며 Legal 검토가 필요합니다. 실제 조문·효력일·기관명은 Legal이 권위 있는 출처에서 확인해 채워야 합니다. 저는 실제 법 해석을 대신하지 않습니다.

## 1. 제출 문서 범주와 우선순위

| 우선순위 | 범주 | `document_kind` | 설명 |
|---|---|---|---|
| 1 (필수) | 공개 법령 | `legislation` | 개인정보 보호법, 신용정보법 등 공개 법률·시행령 |
| 2 (필수) | 공식 가이드라인 | `legislation` 또는 `internal_policy` | 감독기관 고시·해설서(공개면 legislation, 사내 해석이면 internal_policy) |
| 3 (필수) | 내부 정책 | `internal_policy` | 사내 개인정보 처리방침·보안지침(합성/가공) |
| 4 (권장) | 합성 업무 문서 | `business_document` | 개인정보 업무 맥락 재현용 합성 업무자료 |

> 실험용 공격 문서(`experimental_document`)는 Legal이 아니라 **Security(Role 3)** 소관입니다. 제출하지 마세요.

## 2. 허용 파일 형식

- `.txt`(UTF-8 권장; UTF-16 BOM·CP949도 허용) 또는 `.pdf`(텍스트 추출 가능한 것).
- **거부**: 암호화 PDF, 스캔/이미지 PDF(텍스트 없음 → OCR 미지원), 10MB 초과, 200쪽 초과, 추출 텍스트 50만 자 초과. 근거: [parsing.py](../../ragsec/parsing.py), [config.py](../../ragsec/config.py) 한도.
- **권장**: 가능하면 `.txt`로 제출. PDF는 레이아웃에 따라 추출 품질이 들쭉날쭉합니다.

## 3. 원본 vs 추출 텍스트 vs 구조화 레코드

- **제출물 = 원본 파일(.txt/.pdf) 1개 + 문서 레벨 메타데이터 JSON 1개(사이드카).**
- 추출 텍스트·청크·임베딩·PII 탐지 플래그·content hash·청크 메타데이터는 **백엔드가 자동 생성**합니다. Legal이 만들지 않습니다(§7).
- 조문/절 단위 구조화 레코드는 **현재 미지원**(제안 §6). 지금은 조문을 본문 안에 자연스러운 머리말(예: `제15조(개인정보의 수집·이용)`)로 남겨 주세요.

## 4. 폴더·파일명 규칙 (제안 계약)

현재 "법령 코퍼스 일괄 적재" 폴더 규약은 확립돼 있지 않으므로 아래 단순안을 **제안 계약**으로 확정합니다. 적재는 당장은 (a) Streamlit 업로드 탭 또는 (b) `POST /documents`로 파일별 1건씩 가능하며, 폴더 일괄 로더는 백엔드 보류 과제(§8)입니다.

```
data/legal_corpus/
  legislation/
    pipa_2024/
      pipa_2024.txt                 # 원본 텍스트
      pipa_2024.meta.json           # 문서 레벨 메타데이터(§5 스키마)
  internal_policy/
    privacy_policy_v3/
      privacy_policy_v3.pdf
      privacy_policy_v3.meta.json
  business_document/
    ...
submission_index.csv                # 제출 묶음 색인(templates/submission_index.template.csv)
```

- 파일명: `document_id`와 동일 base 사용. `document_id` 패턴은 `^[A-Za-z0-9][A-Za-z0-9._\-]{1,120}$`(영숫자/`._-`, 2~121자). 공백·한글 파일명 금지.
- 메타데이터 사이드카: `<document_id>.meta.json`, 내용은 `DocumentMetadataIn` 1건.

## 5. 메타데이터 스키마 (문서 레벨 — 제출 대상)

필드명·타입·허용값은 [schemas.py `DocumentMetadataIn`](../../ragsec/schemas.py) 그대로입니다. 복붙 템플릿: [templates/document_metadata.template.json](templates/document_metadata.template.json).

| 필드 | 필수? | 타입 / 허용값 | 설명 |
|---|---|---|---|
| `schema_version` | 자동 | `"doc-meta/1.0"` 고정 | 생략 시 기본값 |
| `document_id` | **필수** | 영숫자/`._-`, 2~121자 | 문서 고유 ID(파일명 base와 일치) |
| `document_version` | **필수** | 정수 ≥1 | 개정 시 +1 (내용이 바뀌면 반드시 올림) |
| `source_name` | **필수** | 1~200자 | 문서 제목(= 요청서의 `title`) |
| `source_type` | **필수** | `statute_db` / `internal_wiki` / `crm_record` / `customer_email` / `uploaded_file` / `partner_feed` | 출처 유형 |
| `source_trust_level` | **필수** | `high` / `medium` / `low` / `untrusted` | 신뢰도. 법령·승인 정책=`high` |
| `document_kind` | **필수** | `legislation` / `internal_policy` / `business_document` / `experimental_document` | 문서 분류(= `document_type`) |
| `jurisdiction` | 기본 `KR` | `^[A-Z]{2}$` | 관할 |
| `law_or_policy_id` | legislation·internal_policy는 **필수** | 문자열/`null` | 법령/정책 식별자(예: `PIPA`, `privacy-policy`) |
| `effective_from` | 선택 | ISO8601 datetime/`null` | 효력 시작(= `effective_date`). `null`=태초부터 |
| `effective_to` | 선택 | ISO8601 datetime/`null` | 효력 종료. `null`=무기한. 구간은 `[from, to)` |
| `supersedes_document_id` | 선택 | 문자열/`null` | 이 문서가 대체하는 구버전 `document_id` |
| `pii_grade` | **필수** | `none` / `general` / `credit` / `unique_id` / `sensitive` | 취급 등급(= `access_level`의 핵심 축) |
| `pii_types` | 선택 | `PiiType` 목록 | 포함 PII 유형. `pii_grade=none`이면 비어야 함 |
| `tenant_id` | **필수** | `^[A-Za-z0-9_\-]{2,64}$` | 소속. 현재 정책상 `bank_a`/`bank_b` |
| `allowed_roles` | **필수** | 역할 목록(≥1) | 열람 허용 역할. 정책에 존재하는 역할만 |
| `subject_id` | 선택 | 문자열/`null` | 특정 고객 전용 레코드면 그 고객 id, 일반 문서면 `null` |
| `experimental_label` | experimental만 | 객체/`null` | **Legal은 사용 안 함** |

허용 역할(현재 [access_policy.yaml](../../policies/access_policy.yaml)): `teller`, `credit_officer`, `compliance`, `general_staff`.
PII 유형(`pii_types`): `rrn`, `foreigner_rrn`, `passport`, `driver_license`, `account_number`, `card_number`, `phone`, `email`, `name`, `address`, `credit_info`.

### 요청서 희망 필드 ↔ 실제 스키마 매핑

| 요청서 필드 | 실제 처리 | 상태 |
|---|---|---|
| `title` | `source_name` | ✅ 이름만 다름 |
| `document_type` | `document_kind`(+`source_type`) | ✅ |
| `effective_date` | `effective_from` / `effective_to` | ✅ |
| `version` | `document_version` | ✅ |
| `access_level` | `pii_grade` + `allowed_roles` + `source_trust_level` 조합 | ✅ (분해 저장) |
| `contains_personal_data` | `pii_grade != none` + `pii_types` | ✅ (분해 저장) |
| `allowed_roles` | `allowed_roles` | ✅ |
| `issuing_organization` | 전용 필드 없음 → 당분간 `source_name`에 포함 | 🟨 제안 §6 |
| `source_url` | 전용 필드 없음 → `law_or_policy_id`로 식별 | 🟨 제안 §6 |
| `publication_date` | 전용 필드 없음 | 🟨 제안 §6 |
| `article_or_section` | 문서 레벨 `law_or_policy_id`만; 조문 필드 없음 | 🟨 제안 §6 |
| `is_synthetic` | 전용 필드 없음(`document_kind`/`experimental_label`로 암시) | 🟨 제안 §6 |
| `review_status` | 전용 필드 없음(정책에는 `status` 존재) | 🟨 제안 §6 |

## 6. 개정·효력일·중복·대체·구조 처리 규칙

- **개정**: 내용이 바뀌면 `document_version`을 올립니다. 같은 `document_id`+같은 `document_version`인데 내용 해시가 다르면 수집이 **거부**됩니다(버전 올리라는 오류). 근거: [ingestion.py](../../ragsec/ingestion.py).
- **효력일**: `effective_from/to`는 검색 시 `as_of` 기준으로 필터됩니다(만료/미발효 문서 자동 제외). 근거: [store.py](../../ragsec/store.py) `build_where`.
- **중복**: 동일 id·version·내용 해시는 자동 스킵(idempotent).
- **대체(supersede)**: 신문서에 `supersedes_document_id`를 적으면 색인에서 구문서가 제거됩니다.
- **공개법/고시/내부정책/합성업무 구분**: `document_kind`로 구분. legislation/internal_policy는 `law_or_policy_id` 필수.
- 🟨 **제안(미구현)**: `issuing_organization`, `source_url`, `publication_date`, `article_or_section`(조문 단위), `review_status` 전용 필드. 조문 단위 인용/검색이 연구에 필요하면 백엔드가 스키마 확장 + 조문 인지형 청킹을 추가해야 합니다(아키텍처 결정 필요 → 보류). 지금은 본문 머리말로 조문을 남겨 두면 추후 확장 시 활용 가능합니다.

## 7. 백엔드가 담당(= Legal이 안 해도 됨)

텍스트 추출·정규화·청크 분할·임베딩·PII 정규식 탐지 플래그·content hash·청크 메타데이터(`chunk_id`, `char_start/end`, `detected_pii_types`, 임베딩 차원 등) 전부 백엔드 자동 생성. 근거: [ingestion.py](../../ragsec/ingestion.py), [schemas.py `ChunkMetadata`](../../ragsec/schemas.py).

## 8. 접근 라벨은 누가 검증하나 (중요)

- 메타데이터의 `allowed_roles`/`pii_grade`/`tenant_id`는 **그 자체로 권한이 아닙니다.** 실행 가능한 권한은 승인된 [access_policy.yaml](../../policies/access_policy.yaml)이며, 검색 시 필터([store.py](../../ragsec/store.py))가 집행합니다.
- 수집 시 백엔드는 "그 역할/소속이 정책에 **존재하는가**"만 교차검증합니다. "이 법령이 grade X·role Y가 맞는가"라는 **의미적 타당성은 자동 검증되지 않습니다** → Legal+Security의 사람 검토가 권위입니다.
- 사용자 제출 메타데이터를 **권한 근거로 신뢰하지 않습니다.** (신뢰 경계: [02_backend_architecture.md](02_backend_architecture.md) §6)

## 9. 하나의 (가상) 예시 레코드

> ⚠️ 아래 조문/기관/내용은 **전부 가상 플레이스홀더**입니다. 실제 법령 텍스트가 아니며 Legal 검토 전 사용 금지.

`privacy_policy_v3.meta.json`:
```json
{
  "document_id": "privacy_policy_v3",
  "document_version": 3,
  "source_name": "[가상] 사내 개인정보 처리방침 v3",
  "source_type": "internal_wiki",
  "source_trust_level": "high",
  "document_kind": "internal_policy",
  "jurisdiction": "KR",
  "law_or_policy_id": "privacy-policy",
  "effective_from": "2026-01-01T00:00:00+09:00",
  "effective_to": null,
  "supersedes_document_id": "privacy_policy_v2",
  "pii_grade": "none",
  "pii_types": [],
  "tenant_id": "bank_a",
  "allowed_roles": ["teller", "credit_officer", "compliance", "general_staff"],
  "subject_id": null
}
```

## 10. 수용 체크리스트 (제출 전 자가점검)

- [ ] 파일 형식이 `.txt`/`.pdf`이고 암호화·스캔본이 아니다.
- [ ] `document_id`가 패턴(영숫자/`._-`, 2~121자)에 맞고 파일명 base와 같다.
- [ ] 내용이 바뀌었으면 `document_version`을 올렸다.
- [ ] legislation/internal_policy면 `law_or_policy_id`를 채웠다.
- [ ] `pii_grade=none`인데 `pii_types`가 비어 있다(충돌 금지).
- [ ] `allowed_roles`의 모든 역할이 access_policy에 존재한다.
- [ ] `tenant_id`가 `bank_a`/`bank_b` 중 하나다.
- [ ] 효력일이 있으면 `effective_to > effective_from`이다.
- [ ] 실제 법 해석/인용의 정확성은 Legal이 별도 확인했다(백엔드는 검증 안 함).
- [ ] `submission_index.csv`에 이 문서 한 줄을 추가했다.

## 11. Legal 팀원에게 보낼 요청문 (복붙용)

> **[요청] 법령·정책 문서 제출 (ragsec 백엔드 수집용)**
>
> 안녕하세요. 백엔드 수집기에 바로 넣을 수 있도록 아래 형식으로 문서를 제출해 주세요.
>
> 1. **무엇을**: ① 공개 법령(개인정보 보호법·신용정보법 등), ② 공식 가이드라인, ③ 사내 개인정보 정책(합성/가공) 순서로 우선 부탁드립니다. 실험용 공격 문서는 보내지 마세요(Security 소관).
> 2. **형식**: 문서마다 **원본 파일(.txt 권장, 또는 텍스트 추출 가능한 .pdf) 1개 + `<document_id>.meta.json` 1개**. 폴더 구조와 메타데이터 템플릿은 `docs/handoff/03_legal_data_submission.md` §4·§5와 `docs/handoff/templates/`를 그대로 따라 주세요.
> 3. **메타데이터 필수 항목**: `document_id`, `document_version`, `source_name`(제목), `source_type`, `source_trust_level`(법령=high), `document_kind`, `pii_grade`, `tenant_id`(bank_a/bank_b), `allowed_roles`. legislation/internal_policy는 `law_or_policy_id`도 필수입니다.
> 4. **조문**: 현재 조문 단위 필드는 없으니, 조문을 본문에 머리말(예: `제15조(…)`)로 남겨 주세요.
> 5. **검토**: 실제 조문·효력일·기관명·법 해석의 정확성은 Legal에서 확인 부탁드립니다. 백엔드는 형식만 검증하고 법적 타당성은 검증하지 않습니다. 각 파일은 `review_status`를 아직 쓸 수 없으니, `submission_index.csv`의 비고란에 "검토완료/검토중"을 적어 주세요.
> 6. **암호화/스캔 PDF, 10MB·200쪽·50만 자 초과**는 거부됩니다.
>
> 템플릿: `docs/handoff/templates/document_metadata.template.json`, `docs/handoff/templates/submission_index.template.csv`. 막히는 부분은 백엔드로 알려 주세요.
