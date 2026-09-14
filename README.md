# 🛡️ AI Security Guardrail Gateway for Home Shopping & CS AI

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Defense Rate](https://img.shields.io/badge/Defense%20Rate-99.1%25-success)](#-벤치마크-성능-평가)
[![Avg Latency](https://img.shields.io/badge/Avg%20Latency-0.33ms-blue)](#-벤치마크-성능-평가)

**AI Security Guardrail Gateway**는 홈쇼핑 및 고객상담(CS) AI 서비스 앞단에서 **프롬프트 인젝션, 시스템 프롬프트 탈취, 개인정보(PII) 유출 및 악성 셸 명령어를 실시간(0.13ms 초저지연)으로 방어**하는 프로덕션 레벨의 LLM 보안 게이트웨이입니다.

---

## 📌 핵심 주요 기능 (Key Features)

1. **초저지연 다계층 입력 가드레일 (Input Guardrail - 0.13ms)**
   - **기계적 우회 방어**: 비가시 유니코드(Zero-Width) 제거, 유니코드 NFKC 정규화, 키릴/혼동 문자(Confusables) 및 Leetspeak 복원, Base64/Hex/URL 디코딩
   - **OWASP Top 10 for LLM 방어**:
     - `OWASP_LLM01`: 프롬프트 인젝션, DAN(Do Anything Now) 모드, 가상 역할극 탈옥 차단
     - `OWASP_LLM02`: 고객 개인정보(주민번호/카드/계좌) 대량 덤프 시도 사전 차단
     - `OWASP_LLM06`: `DROP TABLE`, 리눅스 리버스 쉘(`bash -i`, `nc -e`), RCE 구문 차단
     - `OWASP_LLM07`: 시스템 프롬프트 전문 유출 및 관리자 마스터 키 질의 차단
   - **의미론적/페르소나 탈옥 방어**: 동아일보 ‘할머니 탈옥(Grandma Exploit)’, PayloadsAllTheThings 샌드박스 탈출 방어

2. **실시간 출력 가드레일 및 비식별화 (Output Guardrail - 0.08ms)**
   - **Zero-Leakage 강제 파기**: 치명적 사내 기밀 대량 덤프나 Reverse Shell 코드 감지 시 응답 전체 즉시 파기
   - **PII 실시간 마스킹**: 주민등록번호(`[REDACTED_RRN]`), 휴대전화번호(`[REDACTED_PHONE]`), 주소(`[REDACTED_ADDRESS]`), 임시 비밀번호 및 마스터 키(`[REDACTED_SECRET]`), 신용카드/계좌번호 자동 비식별화
   - **XSS 스크립트 정화**: 클라이언트 브라우저 내 악성 자바스크립트 실행 방지 (HTML Entity 치환)

3. **표준 OpenAI 호환 API & AnythingLLM 연동**
   - 표준 OpenAI 규격(`POST /v1/chat/completions`, `GET /v1/models`)을 지원하여 **AnythingLLM 데스크톱 앱 및 전사 RAG 시스템과 100% 무수정 연동**
   - SSE(Server-Sent Events) 실시간 스트리밍 지원

4. **프로덕션 Fail-Closed 보안 아키텍처**
   - 운영 환경(`APP_ENV=production`)에서는 가드레일 우회 옵션(`ALLOW_DEMO_BYPASS`) 및 비인증 접근을 원천 차단
   - 관리 API(`toggle`, `stats`, `logs`)에 `X-Admin-Key` 상수 시간 인증 강제
   - 감사 로그의 개인정보 원문 저장을 기본 비활성화하여 규정 준수(Compliance) 확보

---

## 🏗️ 시스템 아키텍처 (System Architecture)

```mermaid
flowchart LR
    subgraph Clients["Clients"]
        AL["🖥️ AnythingLLM (RAG)"]
        ST["🌐 Streamlit 관제 UI"]
    end

    subgraph Gateway["FastAPI AI Security Gateway"]
        direction TB
        EP["/v1/chat/completions<br/>/api/v1/chat/completions"]
        IG["🛡️ Input Guardrail Engine<br/>(0.13ms 초저지연 검사)"]
        OG["🔒 Output Guardrail Engine<br/>(0.08ms 비식별화 & 마스킹)"]
        SLM["🧠 SLM Service Adapter<br/>(Ollama Qwen 2.5 / Llama 3)"]
    end

    subgraph Storage["Persistence"]
        DB[("💾 SQLite / PostgreSQL<br/>Security Audit Log")]
    end

    AL -->|OpenAI 규격| EP
    ST -->|관제 규격| EP
    EP --> IG
    IG -->|Early Block (0.2ms)| DB
    IG -->|Approved Path| SLM
    SLM --> OG
    OG --> DB
    OG --> EP
```

---

## 📊 벤치마크 성능 평가 (Benchmark Results)

200건의 E2E 실전 데이터셋([`datasets/`](datasets/))을 바탕으로 검증된 실제 성능 지표입니다:

| 평가 항목 | 목표치 | 검증 결과 | 상태 |
|:---|:---:|:---:|:---:|
| **악성 공격 차단율 (Defense Rate)** | ≥ 95.0% | **99.1%** (112건 중 111건 차단) | ✅ Pass |
| **정상 업무 오탐율 (False Positive Rate)** | ≤ 5.0% | **0.0%** (100건 중 0건 오탐) | ✅ Pass |
| **가드레일 검사 평균 지연시간 (Latency)** | ≤ 10.0ms | **0.329ms** (초저지연) | ✅ Pass |
| **입력 가드레일 단독 소요 시간** | ≤ 2.0ms | **0.130ms** | ✅ Pass |
| **출력 가드레일 단독 소요 시간** | ≤ 1.0ms | **0.080ms** | ✅ Pass |

---

## 🚀 빠른 시작 (Quickstart)

### 1. 로컬 환경 실행

Python 3.10 ~ 3.12 환경을 권장합니다.

```powershell
# 1. 환경 설정 파일 복사
Copy-Item .env.example .env

# 2. 가상환경 생성 및 활성화
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. 필수 의존성 패키지 설치
pip install -r requirements.txt
```

**백엔드 API 서버 및 프론트엔드 관제 UI 실행:**

```powershell
# 터미널 1: FastAPI 백엔드 (Port 8000)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload

# 터미널 2: Streamlit 웹 대시보드 (Port 8501)
streamlit run frontend/app.py --server.port 8501
```

- 🛡️ **웹 관제 대시보드**: `http://localhost:8501`
- 🔌 **Swagger API 문서**: `http://localhost:8000/docs`
- 🩺 **헬스체크**: `http://localhost:8000/api/v1/health`

---

### 2. Docker Compose 원클릭 실행

```powershell
# .env 파일 생성 및 관리자 키 설정
Copy-Item .env.example .env

# 컨테이너 빌드 및 백그라운드 실행
docker compose up --build -d

# 실시간 로그 확인
docker compose logs -f
```

---

## ⚙️ 환경 변수 설정 (.env)

| 변수명 | 기본값 | 설명 | 운영 권장값 |
|:---|:---|:---|:---|
| `APP_ENV` | `development` | 애플리케이션 실행 환경 (`development`, `test`, `production`) | `production` |
| `CORS_ORIGINS` | `http://localhost:8501` | 브라우저 허용 Origin 목록 (쉼표 구분) | 실제 서비스 도메인만 명시 |
| `ADMIN_API_KEY` | - | 관리 API 인증용 비밀 키 (`X-Admin-Key`) | 32자 이상 난수 |
| `ALLOW_DEMO_BYPASS` | `false` | 데모용 가드레일 해제 허용 여부 (`production`에서는 강제 비활성화) | `false` |
| `AUDIT_LOG_RAW_CONTENT`| `false` | 감사 로그에 사용자 입력 원문 저장 여부 | `false` (PII 유출 방지) |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama 추론 서버 엔드포인트 URL | 사설망 내부 주소 |

---

## 🧪 벤치마크 테스트 실행

200건 E2E 데이터셋을 활용하여 가드레일 성능과 오탐률을 즉시 측정할 수 있습니다:

```powershell
python tests/benchmark_test.py
```

---

## 📚 상세 기술 문서

- 📖 [운영 배포 가이드 (PRODUCTION.md)](docs/PRODUCTION.md)
- 🔒 [보안 취약점 감사 보고서 (SECURITY_AUDIT.md)](docs/SECURITY_AUDIT.md)
- 🧭 [엔드투엔드 유저 흐름도 및 아키텍처 명세서 (USER_FLOW_ARCHITECTURE.md)](docs/USER_FLOW_ARCHITECTURE.md)
- 📋 [개발 및 보안 가이드라인 (guidelines/README.md)](guidelines/README.md)
- 🛡️ [보안 정책 (SECURITY.md)](SECURITY.md)

---

## 📄 라이선스 (License)

본 프로젝트는 [MIT License](LICENSE)를 따릅니다.
