"""Configuração do backend, lida de variáveis de ambiente (prefixo VIBECHECK_)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} deve ser um inteiro, recebido: {raw!r}") from exc
    if value <= 0:
        raise RuntimeError(f"{name} deve ser maior que zero.")
    return value


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "sim", "on"}


def _str_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _origins_env() -> list[str]:
    raw = os.environ.get(
        "VIBECHECK_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    )
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@dataclass(frozen=True)
class Settings:
    db_path: Path = field(
        default_factory=lambda: Path(_str_env("VIBECHECK_DB_PATH", "data/vibecheck.db"))
    )
    cors_origins: list[str] = field(default_factory=_origins_env)

    # --- Banco de dados ---
    db_engine: str = field(default_factory=lambda: _str_env("VIBECHECK_DB_ENGINE", "sqlite").lower())
    db_host: str = field(default_factory=lambda: _str_env("VIBECHECK_DB_HOST", "127.0.0.1"))
    db_port: int = field(default_factory=lambda: _int_env("VIBECHECK_DB_PORT", 3306))
    db_name: str = field(default_factory=lambda: _str_env("VIBECHECK_DB_NAME", "vibecheck"))
    db_user: str = field(default_factory=lambda: _str_env("VIBECHECK_DB_USER", "vibecheck_user"))
    db_password: str = field(default_factory=lambda: _str_env("VIBECHECK_DB_PASSWORD", ""))

    # --- Análise (mesmos limites do frontend) ---
    max_source_bytes: int = field(
        default_factory=lambda: _int_env("VIBECHECK_MAX_SOURCE_BYTES", 1_000_000)
    )
    max_history: int = field(default_factory=lambda: _int_env("VIBECHECK_MAX_HISTORY", 20))
    # Linhas maiores que isso são truncadas antes de aplicar as regex. Protege
    # contra regex lentas (ReDoS) em arquivos minificados de uma linha só.
    max_line_chars: int = field(
        default_factory=lambda: _int_env("VIBECHECK_MAX_LINE_CHARS", 1000)
    )
    # Orçamento de tempo por análise; ao estourar, a requisição falha com 422.
    scan_timeout_seconds: int = field(
        default_factory=lambda: _int_env("VIBECHECK_SCAN_TIMEOUT_SECONDS", 10)
    )

    # --- Contas e sessões ---
    session_ttl_hours: int = field(
        default_factory=lambda: _int_env("VIBECHECK_SESSION_TTL_HOURS", 24 * 7)
    )
    reset_ttl_minutes: int = field(
        default_factory=lambda: _int_env("VIBECHECK_RESET_TTL_MINUTES", 30)
    )
    # Cria demo@vibecheck.dev / vibecheck2026 (credencial pública, só para demo!).
    seed_demo_user: bool = field(
        default_factory=lambda: _bool_env("VIBECHECK_SEED_DEMO_USER", False)
    )

    # --- Limites de taxa (por processo) ---
    rate_limit_enabled: bool = field(
        default_factory=lambda: _bool_env("VIBECHECK_RATE_LIMIT", True)
    )

    # --- Recuperação de senha por e-mail ---
    frontend_url: str = field(
        default_factory=lambda: _str_env("VIBECHECK_FRONTEND_URL", "http://localhost:5173")
    )
    smtp_host: str = field(default_factory=lambda: _str_env("VIBECHECK_SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: _int_env("VIBECHECK_SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: _str_env("VIBECHECK_SMTP_USER"))
    smtp_password: str = field(default_factory=lambda: _str_env("VIBECHECK_SMTP_PASSWORD"))
    smtp_from: str = field(
        default_factory=lambda: _str_env("VIBECHECK_SMTP_FROM", "VibeCheck <no-reply@localhost>")
    )
    smtp_starttls: bool = field(
        default_factory=lambda: _bool_env("VIBECHECK_SMTP_STARTTLS", True)
    )


def get_settings() -> Settings:
    return Settings()
