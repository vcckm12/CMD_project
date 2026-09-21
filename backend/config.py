# -*- coding: utf-8 -*-
"""Runtime configuration with production-safe defaults."""

import os
from dataclasses import dataclass
from pathlib import Path


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    app_env: str
    cors_origins: tuple[str, ...]
    admin_api_key: str | None
    allow_demo_bypass: bool
    audit_log_raw_content: bool

    # 모델 및 AI 서비스 설정
    ollama_url: str
    default_model: str
    fallback_model: str
    default_temperature: float
    default_max_tokens: int

    # 파일 및 DB 경로 설정
    base_dir: Path
    database_dir: Path
    audit_db_path: Path
    threat_db_path: Path
    shop_db_path: Path
    datasets_dir: Path
    attack_payloads_path: Path

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

    # 기본 경로 산출 (backend 상위 디렉토리를 루트로 설정)
    current_file = Path(__file__).resolve()
    base_dir = current_file.parent.parent
    database_dir = base_dir / "backend" / "database"
    datasets_dir = base_dir / "datasets"

    ollama_url = os.getenv("OLLAMA_HOST_URL", os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
    default_model = os.getenv("DEFAULT_MODEL", "qwen2.5:7b-instruct")
    fallback_model = os.getenv("FALLBACK_MODEL", "llama3:latest")

    return Settings(
        app_env=app_env,
        cors_origins=_csv(os.getenv("CORS_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501")),
        admin_api_key=os.getenv("ADMIN_API_KEY") or None,
        allow_demo_bypass=allow_demo_bypass,
        audit_log_raw_content=os.getenv("AUDIT_LOG_RAW_CONTENT", "false").lower() == "true",
        ollama_url=ollama_url,
        default_model=default_model,
        fallback_model=fallback_model,
        default_temperature=float(os.getenv("DEFAULT_TEMPERATURE", "0.7")),
        default_max_tokens=int(os.getenv("DEFAULT_MAX_TOKENS", "500")),
        base_dir=base_dir,
        database_dir=database_dir,
        audit_db_path=database_dir / "audit.db",
        threat_db_path=database_dir / "threat_intel.db",
        shop_db_path=database_dir / "shop.db",
        datasets_dir=datasets_dir,
        attack_payloads_path=datasets_dir / "attack_payloads_100.jsonl",
    )


settings = load_settings()
