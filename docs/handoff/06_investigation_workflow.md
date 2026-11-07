# 06. W-01 민원 조사 인수인계 워크플로 구현 (Backend)

기준일: 2026-11-07 · 합성 데모(mock)로 검증 · 효능 파일럿은 HOLD

연구 4종(업무 조사표·조사·데이터조사·답변 기록표)이 **W-01 민원 조사 인수인계**를 첫 후보로 선정했고, 그 업무를
`investigation request → authorized retrieval → structured findings → handover`로 구현했습니다. 기존 FastAPI·
Streamlit·권한·근거링크·감사로그를 재사용하고 최소 변경만 추가했습니다.

## 1. 선택한 조사 업무와 직무 매핑
- **업무:** 담당자 변경에 따른 민원 조사 인계. 조사 담당자가 사건 기록을 열람해 **확인 사실 / 확인 중 / 다음 조치**로
  구조화한 인계 결과를 만들고, 후임자에게 근거 링크와 함께 전달합니다(조사.pdf p.1 "기록 열람 → 요약 작성 →
  수신자별 전달").
- **역할:** 법정 CPO(총괄·책임)와 실무 Privacy 담당자를 구분(업무 조사표 p.1, INT-02 #1). 조사 개시 권한은 실무
  수준으로 두되, **조사 부서를 준법감시(compliance)로 둔 것은 실험용 설정**(업무 조사표 p.2 '직무 구분')이므로
  합성 데모 정책으로 명시합니다(`INVESTIGATOR_ROLES=("compliance",)`).

## 2. 출처 → 코드 표 (PDF 쪽 · 구현 필드 · 가정)
| 출처(첨부·쪽·위치) | 확인 | 구현(코드) |
|---|---|---|
| 업무 조사표 p.2 'W-01 … 첫 후보' | 후보 선정(해석) | 전체 워크플로 선택 |
| 조사 p.1 주요 처리행위 | 사실(INT-01 3번) | `/investigation` 흐름: 열람→findings→handover |
| 조사 p.5 §5 정보별 출력(사건식별자·쟁점·확인사실·처리상태·다음조치·기한) | 합성 설계 | `InvestigationFindings.{case_id,issue,status,confirmed_facts,next_actions}` |
| 조사 p.5 §5 '고객 이름·연락처 기본 제외' / 데이터조사 p.8 '계좌 마스킹·토큰, 원문 금지' | 합성 설계 | `withheld_categories` + 발췌 뷰 방어적 마스킹 |
| 업무 조사표 p.2 '확인 사실' vs p.8 '확인 중'/다음 조치 | 사실+합성 | `FactStatus.{confirmed,checking}` + `NextAction(due)` |
| 데이터조사 p.8 '제외: 비밀번호·주민등록번호' | 합성 설계 | 합성 메모에 RRN·비밀번호 없음 |
| 답변 기록표 INT-01 #1·#2 (마스킹 기본·마스킹 해제 별도 권한) | 사실 | 발췌(마스킹)=일반 수신자 / 원문(마스킹된 위치)=권한 리뷰어 |
| 답변 기록표 INT-01 #3 (권한 회수 지연·정기 점검) | 사실 | 권한 종료 후 동일 링크 재열람 → 열람 제한 |
| 조사 p.6 §5.2 P-01..P-06 | 기대 동작 | `w01_investigation_rules.example.json` → `ragsec rule-map` 후보(미승인) |

**가정(모두 합성·검토 필요):** 조사 역할=compliance(실험 설정); 기관명·식별자 전부 가상(`가상상호은행(합성)`,
`CUST-SYN-0007`); 후임자 원문 허용 여부·마스킹 계좌 형식·목적 외 이용 근거는 **미결로 남겨** 승인 런타임 정책에서 제외.

## 3. 아티팩트 분리 (워크플로 / 런타임 / 오라클)
- **워크플로 config** = `InvestigationCase`(사건별 구조화 결과 템플릿; 합성, 권한 아님, 오라클 아님).
- **런타임 정책** = access_policy의 disclosure_rules + 클릭마다 OpenEvidence 권한(변경 없음). `rule-map`으로 P-01..P-06을
  후보로 매핑했고 **미지원(마스킹 계좌)·미결(후임자 원문·마케팅 목적)** 은 승인 정책에 넣지 않습니다.
- **평가 오라클** = 채점용. 여기서 읽지 않으며 **열람/공개/근거 접근을 인가하지 않습니다.**
- 요청자의 **기록 열람 권한**과 수신자의 **결과·근거 열람 권한**을 분리: 조사 결과는 생성되지만, 수신자는 grant가 있어야
  근거를 열 수 있고 제목·쪽·버전·발췌·마스킹 원문은 기존 규칙대로 분리 처리됩니다.

## 4. 변경 파일 · 실행
- 신규: `ragsec/investigation.py`, `scripts/demo_investigation_seed.py`, `tests/test_investigation.py`,
  `docs/handoff/templates/examples/w01_investigation_rules.example.json`, `docs/.../ui_draft_screens/inv_1..6_*.png`.
- 수정: `ragsec/api.py`(`POST /investigation`), `ragsec/errors.py`(404), `ui/streamlit_app.py`(조사 요청→결과 화면),
  `scripts/demo_launch.ps1`(투자 케이스 시드).
```powershell
.\scripts\demo_launch.ps1            # mock API+Streamlit 기동, 합성 W-01 케이스 시드 -> http://127.0.0.1:8501
.\scripts\demo_launch.ps1 -Stop
# 정책 후보(미승인) 생성:
ragsec rule-map docs/handoff/templates/examples/w01_investigation_rules.example.json --out var/rule_mapping
```

## 5. 검증 결과 (실제 수행)
- 테스트: `tests/test_investigation.py` 5건 통과(구조화 findings·요청자/수신자 권한 분리·403·404·근거없음 노트·경로
  traversal 거부). 전체 회귀 **269 passed**.
- Chrome(mock, 합성): 조사 요청 → 구조화 결과(확인 사실 2·확인 중 1·다음 조치 2) → 발췌(허용) → 권한 종료 후 동일 링크
  재열람 → **열람 제한(이전 발췌 제거)** → 권한 리뷰어 원문(마스킹) → general_staff 조사 요청 **거절(권한 없음)**.
  캡처: `inv_1_request`~`inv_6_denied`.
- 남은 검증 공백: 실제 LLM(Ollama) 미기동; 라이브 생성/지연은 미측정. 구조화 결과는 합성 케이스 템플릿 기반(결정적)이며
  근거 링크·권한만 실제 경로.

## 6. 사람 검토가 필요한 결정
- **Legal:** (P-06) 정상 후임자에게 계좌·연락처 **원문 허용 여부**; (P-01) **마스킹 계좌 형식**; (P-04) 목적 외(마케팅)
  이용 근거; 필수 정보 목록의 법적 근거(업무 조사표 p.8 B·C 질문). → 결정 전까지 UNRESOLVED/미지원으로 보류.
- **Security:** 메모 내 악성 지시('이전 담당자에게 원문 전달') 공격 케이스와 대조(준호 오래된 기록)는 **D14 사람 검토 후**에만
  효능 대상. 현재 데모는 benign 합성만 적재. **효능 파일럿 HOLD 유지.**
