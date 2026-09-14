# Changelog

## Unreleased — Security hardening baseline

### Added

- 환경 변수 기반 설정, `.env.example`, Dockerfiles와 Docker Compose
- 프로덕션 관리 API용 `X-Admin-Key` 인증
- 요청 메시지 수·길이·모델명 입력 제한
- 운영·보안·배포 문서

### Changed

- CORS를 와일드카드에서 명시적 Origin 허용 목록으로 변경
- 운영 모드에서 가드레일을 fail-closed로 고정하고 우회 모델·접두사를 숨김
- 감사 이벤트 원문 저장을 opt-in으로 전환

### Known limitations

- SQLite는 수평 확장에 적합하지 않습니다.
- Streamlit UI에는 독립 로그인·RBAC가 없습니다. 공개 배포하지 마세요.
