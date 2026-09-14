# Security Analysis Report

## Executive Summary

- **Target**: FastAPI guardrail gateway, Streamlit demo UI, SQLite audit store
- **Initial risk**: Critical
- **Summary**: 가드레일 해제와 감사 로그 읽기·삭제가 무인증이었고, CORS와 우회 경로가 운영에도 열려 있었습니다. 운영 모드를 fail-closed로 변경했습니다.

## Findings

| ID | Title | Severity | Location | Status |
| --- | --- | --- | --- | --- |
| VULN-01 | 무인증 가드레일 해제 | Critical | `backend/main.py` | Fixed |
| VULN-02 | 무인증 감사 로그 조회·삭제 | High | `backend/main.py` | Fixed |
| VULN-03 | 와일드카드 CORS 구성 | High | `backend/main.py` | Fixed |
| VULN-04 | 운영 환경의 우회 모델·접두사 | Critical | `backend/main.py` | Fixed |
| VULN-05 | 감사 로그 원문 PII 저장 | High | `backend/database/audit_logger.py` | Mitigated |
| VULN-06 | 요청·페이지네이션 미검증 | Medium | `schemas.py`, `main.py` | Fixed |

## Remediation

프로덕션에서 `X-Admin-Key`의 상수 시간 비교를 적용하고 키 없는 기동을 거부합니다. CORS는 명시된 Origin만 허용하며, 우회 모델·접두사·요청별 보안 해제는 데모 모드 외에서 불가능합니다. 감사 이벤트는 원문 대신 메타데이터만 보존합니다.

## Residual risk

정규식 기반 가드레일만으로 모든 다국어·의미 기반 공격을 막을 수 없습니다. 정책 평가, 분류 모델, 지속적인 레드팀 테스트가 필요합니다. SQLite와 Streamlit은 다중 테넌트 운영용이 아닙니다.
