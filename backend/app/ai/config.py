"""Configuração exclusiva por variáveis de ambiente da camada de IA."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlsplit


class AIConfigurationError(ValueError):
    """Configuração opcional de IA ausente ou inválida."""


def validate_base_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").lower()
        parsed.port
    except ValueError:
        raise AIConfigurationError("AI_BASE_URL inválida.") from None
    local_http = parsed.scheme == "http" and hostname in {"localhost", "127.0.0.1"}
    if (
        (parsed.scheme != "https" and not local_http)
        or not parsed.netloc
        or not hostname
        or any(character.isspace() for character in hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AIConfigurationError(
            "AI_BASE_URL deve usar HTTPS; HTTP só é permitido para localhost ou 127.0.0.1."
        )
    return value.rstrip("/")


def _positive_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise AIConfigurationError(f"{name} deve ser numérico.") from exc
    if value <= 0:
        raise AIConfigurationError(f"{name} deve ser maior que zero.")
    return value


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise AIConfigurationError(f"{name} deve ser inteiro.") from exc
    if value <= 0:
        raise AIConfigurationError(f"{name} deve ser maior que zero.")
    return value


def _optional_bounded_positive_int(name: str, maximum: int) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise AIConfigurationError(f"{name} deve ser inteiro.") from exc
    if value <= 0:
        raise AIConfigurationError(f"{name} deve ser maior que zero.")
    if value > maximum:
        raise AIConfigurationError(f"{name} não pode ser maior que {maximum}.")
    return value


def _boolean(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "sim", "on"}:
        return True
    if normalized in {"0", "false", "no", "não", "nao", "off"}:
        return False
    raise AIConfigurationError(f"{name} deve ser booleano.")


def _optional_reasoning_effort() -> str | None:
    raw = os.environ.get("AI_REASONING_EFFORT")
    if raw is None or not raw.strip():
        return None
    value = raw.strip().lower()
    if value not in {"none", "minimal", "low", "medium", "high"}:
        raise AIConfigurationError(
            "AI_REASONING_EFFORT deve ser none, minimal, low, medium ou high."
        )
    return value


@dataclass(frozen=True)
class AISettings:
    enabled: bool = False
    base_url: str = ""
    api_key: str = field(default="", repr=False)
    model: str = ""
    timeout_seconds: float = 20
    max_calls_per_scan: int = 10
    concurrency: int = 2
    discovery: bool = False
    max_completion_tokens: int | None = None
    reasoning_effort: str | None = None
    total_timeout_seconds: float = 60

    @classmethod
    def from_env(cls) -> AISettings:
        enabled = _boolean("AI_ENABLED", False)
        if not enabled:
            return cls()
        settings = cls(
            enabled=True,
            base_url=os.environ.get("AI_BASE_URL", "").strip(),
            api_key=os.environ.get("AI_API_KEY", "").strip(),
            model=os.environ.get("AI_MODEL", "").strip(),
            timeout_seconds=_positive_float("AI_TIMEOUT_SECONDS", 20),
            max_calls_per_scan=_positive_int("AI_MAX_CALLS_PER_SCAN", 10),
            concurrency=_positive_int("AI_CONCURRENCY", 2),
            discovery=_boolean("AI_DISCOVERY", False),
            max_completion_tokens=_optional_bounded_positive_int(
                "AI_MAX_COMPLETION_TOKENS", 8192
            ),
            reasoning_effort=_optional_reasoning_effort(),
            total_timeout_seconds=_positive_float("AI_TOTAL_TIMEOUT_SECONDS", 60),
        )
        if not settings.base_url or not settings.api_key or not settings.model:
            raise AIConfigurationError(
                "AI_BASE_URL, AI_API_KEY e AI_MODEL são necessários quando AI_ENABLED=true."
            )
        validate_base_url(settings.base_url)
        return settings
