"""Runtime configuration with production-safe defaults."""

import os
from dataclasses import dataclass


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    app_env: str
    cors_origins: tuple[str, ...]
    admin_api_key: str | None
    allow_demo_bypass: bool
    audit_log_raw_content: bool

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def load_settings() -> Settings:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    if app_env not in {"development", "test", "production"}:
        raise RuntimeError("APP_ENV must be development, test, or production")

    allow_demo_bypass = os.getenv("ALLOW_DEMO_BYPASS", "false").lower() == "true"
    if app_env == "production" and allow_demo_bypass:
        raise RuntimeError("ALLOW_DEMO_BYPASS must be false in production")
    if app_env == "production" and not os.getenv("ADMIN_API_KEY"):
        raise RuntimeError("ADMIN_API_KEY is required in production")

    return Settings(
        app_env=app_env,
        cors_origins=_csv(os.getenv("CORS_ORIGINS", "http://localhost:8501")),
        admin_api_key=os.getenv("ADMIN_API_KEY") or None,
        allow_demo_bypass=allow_demo_bypass,
        audit_log_raw_content=os.getenv("AUDIT_LOG_RAW_CONTENT", "false").lower() == "true",
    )


settings = load_settings()
