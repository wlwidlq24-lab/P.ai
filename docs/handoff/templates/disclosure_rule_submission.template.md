# 공개 규칙 제출 양식 (Legal용) — disclosure_rule_submission

> **목적.** Legal은 **공개 규칙의 의미·법적 근거·조건·미결 질문**만 아래 표로 제출합니다. **YAML/코드를 작성하지
> 않습니다.** Backend가 이를 검증된 설정(`RolePolicy.disclosure_rules`)으로 매핑하고, 매핑 결과를 **사람이 읽을 수
> 있는 대조표**로 되돌려 Legal이 확인합니다. Backend가 법적 결론을 지어내거나 매핑을 자동 승인하지 않습니다.
>
> 모든 값은 **합성·가상 은행** 전제이며, 적법성 확정은 Legal 사람의 몫입니다. required(업무 필수)는 법적 공개 근거가
> 아니며, legal_obligation(법정 제공 의무)과 구분해 적습니다.

## 1. 규칙 행 (한 줄 = 한 (역할 × 수신자 × 목적 × 채널) 판단)

| 필드 | 설명 | 예시(합성) |
|---|---|---|
| role | 행위자 역할 | compliance |
| recipient | 공개 수신자 | internal_successor / external_partner |
| purpose | 처리·공개 목적 | handover / outsourced_processing |
| channel | 공개 경로 | response / internal://case-system |
| allowed_pii_types | 이 맥락에서 공개 **허용**되는 정보 유형 | account_number |
| validity_from / validity_to | 인가(권한) 유효 기간. 비우면 무기한 | 2026-01-01 / (비움) |
| conditions | 충족돼야 공개 가능한 조건(지원 술어만; §2) | recipient_verified |
| legal_ground | 적용 법령·조·항·시행일 + 사실 전제 | (Legal 기재) |
| decision_note | ALLOW/DENY/CONDITIONAL/UNRESOLVED 중 의도와 근거 | CONDITIONAL: 수신자 확인 시 |
| unresolved | 미결 법률 질문(있으면) | 국외 수신 시 추가 검토 |

> 규칙에 없는 (수신자·목적·채널) 조합은 기본적으로 **공개 불가(deny)**로 집행됩니다(strict 모드에서는 **보류/준비
> 오류**). "규칙을 넣지 않음" = "그 맥락은 허용되지 않음"임을 유의하세요.

## 2. 지원 조건(술어)과 각 술어가 요구하는 **서버측 증거**

조건은 아래 **지원 목록에서만** 선택합니다. 목록에 없는 조건을 쓰면 시스템은 공개를 **보류(HOLD)** 합니다(추론으로
허용하지 않음). **클라이언트(요청 본문)가 보낸 값은 조건 충족의 근거가 되지 않습니다** — 반드시 보호된 서버측 기록/
검증된 증거 참조에서 확인됩니다.

| 술어 ID | 의미 | 충족에 필요한 **서버측 증거(출처)** |
|---|---|---|
| `recipient_verified` | 수신자 신원·수신 권한이 확인됨 | 보호된 수신자 레지스트리/디렉터리의 검증 레코드 |
| `approval_on_file` | 해당 공개에 대한 승인이 기록됨 | 보호된 승인 저장소의 승인 레코드(요청자·범위·시각) |
| `within_retention_period` | 보유·이용 기간 내임 | 신뢰 설정의 보유기간 + 서버 시각 기준 판정 |

> 새 술어가 필요하면 **의미 + 어떤 서버측 증거로 검증할지**를 함께 제안하세요. 증거 검증 방법이 없으면 추가하지 않습니다.
> (현재 암호학적 서명 검증은 미구현 — 별도 요구 시 알고리즘·검증키·폐기 절차를 먼저 명세.)

## 3. Backend 되돌림(대조표) — Legal 확인용

Backend는 제출 행을 `DisclosureRule`로 매핑한 뒤 아래 형태로 **대조표**를 돌려드립니다. Legal은 의미가 보존됐는지만
확인합니다(코드 검토 아님).

| 제출 행(요약) | 매핑된 설정(요약) | 집행 결과(요약) | Legal 확인 |
|---|---|---|---|
| compliance→internal_successor/handover/response: account 허용, 조건 recipient_verified | role=compliance rule#1 | account: 수신자 확인 시 ALLOW, 아니면 HOLD | ☐ |

## 4. 주의
- `allowed_pii_types`는 **정규식 탐지 가능한 제한된 유형**에만 집행됩니다(의미적 DLP 아님). 미탐은 평가 한계입니다.
- 평가용 정답(오라클: allowed/prohibited/required/legal_obligation atom)과 **이 집행 규칙은 별개**입니다. 둘을 정합되게
  제출하되, 집행 규칙은 런타임 신뢰 정책, 오라클은 채점용입니다.
