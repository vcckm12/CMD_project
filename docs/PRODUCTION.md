# Production Deployment Guide

## 배포 전 필수 조건

1. `APP_ENV=production`, `ALLOW_DEMO_BYPASS=false`를 설정합니다.
2. 32바이트 이상 난수의 `ADMIN_API_KEY`를 Secret Manager에서 주입합니다.
3. `CORS_ORIGINS`에는 실제 UI Origin만 지정하며 `*`는 사용하지 않습니다.
4. API와 Ollama는 사설망에 배치하고 외부 공개는 TLS 종료 프록시/API Gateway 하나로 제한합니다.
5. Streamlit은 내부 데모 UI입니다. 외부 운영 콘솔은 OIDC와 RBAC를 적용한 별도 UI로 교체합니다.

## 권장 인프라

```text
Internet → WAF / API Gateway → Guardrail API → LLM provider
                                  ├→ PostgreSQL (audit/policy)
                                  ├→ Redis (rate limit/cache)
                                  └→ OpenTelemetry collector
```

현재 Compose 구성은 단일 노드용입니다. 수만 명 규모에서는 PostgreSQL, Redis, 객체 스토리지, 중앙 로그, OIDC를 관리형 서비스로 분리하고 API를 무상태로 만드세요.

## 운영 점검

- 사용자·테넌트·API Key별 Rate Limit를 Redis로 적용합니다.
- 감사 로그 보존기간·삭제·접근권한을 문서화합니다.
- 차단율·오탐률·P95 지연·모델 오류율·비용을 모니터링합니다.
- 배포마다 공격/정상 평가셋을 CI에서 실행하고 기준 미달 시 배포를 막습니다.
