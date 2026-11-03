# ragsec 전체 시스템 구성도

> 편집 가능한 Mermaid 원본(아래) — GitHub에서 바로 렌더링됩니다. 인쇄/오프라인 공유용 PDF는 같은 폴더의
> `ragsec_시스템_구성도.pdf`. 모든 데이터는 합성이며 외부 전송은 로컬 모의 싱크로만 갑니다.

```mermaid
flowchart TB
  subgraph clients["① 클라이언트 / 행위자"]
    UI["개인정보 담당자·연구자<br/>Streamlit 콘솔 (API만 호출)"]
    CLI["관리자<br/>ragsec CLI"]
  end

  subgraph api["② API 계층 — FastAPI (ragsec/api.py)"]
    AUTH["인증·권한<br/>X-API-Key → Principal<br/>legacy | multiuser · can_act_as · tenant/admin"]
    EP["엔드포인트<br/>/query /documents /experiments<br/>/index /policies /models /cases /health"]
  end

  subgraph core["③ 핵심 서비스 (services.py)"]
    RAG["RagService<br/>질의 파이프라인"]
    ING["Ingestor<br/>문서 파이프라인(조문 인지형)"]
    JOB["JobManager<br/>실험 러너(유계·실행중 데드라인)"]
    SCH["ModelScheduler<br/>단일 GPU 직렬화 · keep_alive"]
  end

  subgraph guards["④ 가드레일 — 검출(detection) → 집행(enforcement) 분리"]
    PL["플러그인<br/>pii_regex · ipi_rules · provenance<br/>· llama_guard · context_leak"]
    ENF["Enforcer<br/>ALLOW / REDACT / QUARANTINE / BLOCK"]
  end

  subgraph stores["⑤ 저장소 · 정책"]
    CH["ChromaDB<br/>버전형 색인(스테이징→검증→활성→롤백)"]
    POL["정책 YAML<br/>access / users / guard (버전·검증)"]
    SINK["MockSink<br/>로컬 모의 전송 (네트워크 없음)"]
    LOG["JSONL 로그 + 지표<br/>(원문 PII·완전 프롬프트 미기록)"]
  end

  subgraph llm["⑥ 로컬 모델 — Ollama (loopback 전용)"]
    RT["런타임 클라이언트<br/>allowlist: /api/chat · generate · embed"]
    EX["EXAONE 3.5 2.4b<br/>생성"]
    BGE["bge-m3<br/>임베딩(CPU)"]
    LG["llama-guard3 1b<br/>안전 분류(IPI 전용 아님)"]
    ADM["admin 클라이언트<br/>version/tags/ps (진단 전용·분리)"]
  end

  UI -->|HTTP + X-API-Key| EP
  CLI --> ING
  CLI --> JOB
  CLI -.진단.-> ADM
  EP --> AUTH
  AUTH --> RAG
  AUTH --> ING
  AUTH --> JOB
  JOB --> RAG
  RAG --> SCH
  ING --> SCH
  SCH --> RT
  RT --> EX
  RT --> BGE
  RT --> LG
  RAG -->|PRE / POST 검사| PL
  PL --> ENF
  RAG <-->|권한 검색 fail-closed| CH
  ING --> CH
  RAG -->|허용된 액션만| SINK
  RAG --> LOG
  RAG -.정책 참조.-> POL
  ADM -.진단.-> RT

  UNTRUSTED["⚠ 검색된 문서 = 비신뢰 증거<br/>문서 속 지시를 명령으로 자동 신뢰하지 않음<br/>(분리 효과는 측정 대상)"]
  UNTRUSTED -.주입 위험.-> CH

  classDef warn fill:#fde2e1,stroke:#c0392b,color:#1b2733;
  classDef safe fill:#dff0e4,stroke:#2e7d4f,color:#1b2733;
  class UNTRUSTED warn;
  class SINK safe;
```

## 핵심 흐름 (한눈에)

- **질의:** 클라이언트 → FastAPI(인증·권한) → RagService → 권한 검색(ChromaDB, fail-closed) → PRE 검사 →
  컨텍스트 조립(근거 라벨 `[E#]`) → 생성(Ollama) → **액션 파싱(미실행) → 출력/인용 검사 → 액션 인가 →
  허용된 모의 액션만 실행** → 응답 + JSONL 로깅.
- **문서:** 제출 → 메타데이터 검증 → 파싱/정규화 → 수집 훅(플래그) → 청크/임베딩 → 스테이징 색인 → 검증 → 활성화.
- **실험:** 검토된 케이스 → 버전형 데이터셋 → manifest 검증 → freeze 검증 → 유계 쌍대 실행 → 기록 → 집계.

## 신뢰 경계 (요약)

- **신뢰:** `SYSTEM_PROMPT`·정책 YAML·`ollama_url`(loopback 검증) 등 서버 설정 / 인증된 주체 신원.
- **비신뢰:** 검색된 문서 내용·질의 텍스트. 문서 속 "지시"는 명령이 아니며, `<document>`로 감싸 분리합니다.
- **분리 축:** 가드 검출 ≠ 집행, egress 차단 ≠ LLM 방어, 출처 인용 ≠ 의미적 정확성, 루프백 ≠ 인증.

## 범례

- ①~⑥ = 계층. 실선 = 주 데이터/제어 흐름, 점선 = 진단/정책 참조/주입 위험.
- 초록(MockSink) = 안전 경계(실제 네트워크 없음), 빨강(비신뢰) = 공격 표면.
