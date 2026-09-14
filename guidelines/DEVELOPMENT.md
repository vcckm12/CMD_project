# Development Guidelines

## 프로젝트 구조

- `backend/guardrails`: 입력·출력 정책 검사만 담당합니다.
- `backend/services`: LLM 공급자 연동과 비즈니스 로직을 담당합니다.
- `backend/database`: 감사 이벤트 저장·조회만 담당합니다.
- `backend/models`: API 요청·응답 스키마를 담당합니다.
- `frontend`: 내부 데모 관제 UI입니다.

라우터에서 직접 DB나 외부 모델을 호출하지 않습니다. 새 기능은 스키마 → 서비스 → 라우터 → 테스트 순으로 추가합니다.

## 코드 기준

- 모든 외부 입력은 Pydantic 스키마로 길이·형식·범위를 제한합니다.
- 예외 메시지, 비밀값, 내부 URL을 HTTP 응답에 노출하지 않습니다.
- 모델·DB·네트워크 호출에는 명시적인 timeout을 설정합니다.
- 새 환경 변수는 `.env.example`과 `README.md`에 함께 추가합니다.
- 실제 PII·토큰·비밀번호를 코드·테스트 픽스처·커밋 메시지에 넣지 않습니다.

## 테스트 기준

변경 전후에 다음을 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m compileall -q backend frontend
.\.venv\Scripts\python.exe tests\benchmark_test.py
```

새 가드레일 규칙은 최소 하나의 공격 사례와 하나의 정상 사례를 데이터셋에 추가해 오탐률도 확인합니다.
