# Deployment Guidelines

## 환경 분리

| 환경 | 가드레일 우회 | 감사 원문 | 접근 |
| --- | --- | --- | --- |
| Development | 필요한 경우만 허용 | 기본 비저장 | 로컬 개발자 |
| Staging | 금지 | 기본 비저장 | 내부 담당자 |
| Production | 금지 | 기본 비저장 | 인증된 서비스 계정 |

## Docker 실행 전 점검

1. Docker Desktop을 실행하고 `docker info`가 성공하는지 확인합니다.
2. `.env`에 `ADMIN_API_KEY`를 장기·무작위 값으로 지정합니다.
3. `APP_ENV=production`, `ALLOW_DEMO_BYPASS=false`인지 확인합니다.
4. `CORS_ORIGINS`에 실제 UI 도메인만 입력합니다.

```powershell
docker compose up --build -d
docker compose ps
docker compose logs -f backend
```

운영 환경에서는 API 포트를 인터넷에 직접 공개하지 않습니다. TLS 종료, WAF, API Gateway, 비밀관리, 모니터링은 별도 인프라에서 제공합니다.
