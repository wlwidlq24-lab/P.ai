# 공개 규칙 제출 — 구조화 동반 형식 (companion to the Markdown template)

Legal은 의미만 적습니다(`disclosure_rule_submission.template.md` §1 표). Backend 매핑 도구(`ragsec rule-map`)에
**기계 판독 가능한 입력**을 주기 위해, 같은 내용을 아래 JSON/YAML 형식으로도 제출합니다. 예시:
[`disclosure_rule_submission.example.json`](disclosure_rule_submission.example.json).

> 이 형식은 **런타임 집행 규칙(`RolePolicy.disclosure_rules`)** 으로 매핑 가능한 필드만 모읍니다. 법적 근거·필요성·
> 의무·미결 질문은 **메타데이터로만** 보존되고 런타임 규칙에는 들어가지 않습니다(설계상 분리). 표현형이 original이
> 아니거나 미지원 술어를 쓰면 **허용 규칙을 발급하지 않고 '차이'로 보고**합니다(임의 허용/거부로 바꾸지 않음).

## 최상위 필드

| 필드 | 필수 | 의미 |
|---|---|---|
| `submission_id` | ✔ | 제출 묶음 ID(산출물 파일명·대조표 제목에 사용) |
| `source` | | 출처/제출자/템플릿 버전 등 provenance(문서화용) |
| `policy_mode` | | `strict_rules`(기본, 미커버→HOLD) 또는 `role_fallback`(미커버→DENY) |
| `rows[]` | ✔ | 규칙 행 목록(아래) |

## 규칙 행(`rows[]`) ↔ 템플릿 §1 매핑

| JSON 필드 | 템플릿 §1 열 | 런타임 매핑 | 비고 |
|---|---|---|---|
| `rule_id`, `version` | (행 식별) | 대조표에 그대로 인용 | source ID·버전을 생성 규칙 옆에 기록 |
| `role` | role | `AccessPolicy.roles[role]` | 역할별 `disclosure_rules`로 묶임 |
| `recipient` | recipient | `DisclosureRule.recipient` | `null`=모든 수신자 |
| `purpose` | purpose | `DisclosureRule.purpose` | `null`=모든 목적 |
| `channel` | channel | `DisclosureRule.channel` | `null`=모든 채널 |
| `allowed_pii_types` | allowed_pii_types | `DisclosureRule.allowed_pii_types` | 정규식 탐지 가능한 `PiiType`만 집행 |
| `validity_from`/`validity_to` | validity_from/to | `effective_from`/`effective_to` | 인가(권한) 창. 구간 `[from, to)` |
| `conditions` | conditions | `conditional_predicates` | **지원 술어만** 충족 가능(그 외 HOLD) |
| `decision` | decision_note | (ALLOW/CONDITIONAL만 허용 규칙 발급) | DENY=미발급, UNRESOLVED=보류, 둘은 구분 |
| `permitted_form` | (표현형) | original만 런타임 허용 규칙으로 | masked/summarized=미지원→차이 보고, omitted=비공개 |
| `legal_ground` | legal_ground | **런타임 밖** | 오라클/문서화용(필요성·의무와 구분) |
| `task_required` | (필요성) | **런타임 밖** | 업무 필수 ≠ 법적 근거 |
| `legal_obligation` | (의무) | **런타임 밖** | 법정 제공 의무(별도) |
| `unresolved_note` | unresolved | **런타임 밖** | UNRESOLVED일 때 미결 질문 |

## 결정값·표현형 처리 규칙 (요약)

- `ALLOW` + `original` → 런타임 허용 규칙 발급.
- `CONDITIONAL` + `original` → 허용 규칙 + `conditional_predicates`. 미지원 술어는 **차이로 표기**되고 런타임은 HOLD.
- `DENY` 또는 `permitted_form=omitted` → 허용 규칙 **미발급**(= 집행 시 거부/보류).
- `UNRESOLVED` → 허용 규칙 **미발급**, "미결(보류)"로 구분. `strict_rules`에서 HOLD, `role_fallback`에서는 DENY로 귀결(그래서 UNRESOLVED는 strict 권장).
- `permitted_form` ∈ {masked, summarized} 인데 ALLOW/CONDITIONAL → **표현형 미지원**: 허용 규칙을 발급하지 **않고** 차이로 보고(원문 공개로 넓히지 않음).

## 실행

```
ragsec rule-map docs/handoff/templates/examples/disclosure_rule_submission.example.json --out var/rule_mapping
```
→ `var/rule_mapping/<submission_id>.candidate.yaml`(**미승인** 후보), `.report.ko.md`(Legal 확인용 대조표),
`.result.json`(통합·검증용). **활성 정책은 건드리지 않습니다.** 종료코드: 0=깔끔, 3=수정/미결 있음, 2=도구 오류.
