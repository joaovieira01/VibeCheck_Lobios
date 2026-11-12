"""Orquestra uma análise: valida a entrada, executa o scanner e monta o resultado."""

from __future__ import annotations

import logging
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .ai.config import AIConfigurationError, AISettings
from .ai.discovery import discover_risky_functions
from .ai.provider import OpenAICompatibleClient
from .ai.triage import AIAnalyzer, AIProvider, triage_findings
from .errors import ApiError
from .scanner import ScanTimeout, scan_source

_MAX_AI_FINDINGS = 20
_CREDENTIAL_URL = re.compile(r"(?i)https?://[^\s/@:]+:[^\s/@]+@")
_LOGGER = logging.getLogger("vibecheck.ai")


_LANGUAGES = {
    "py": "Python",
    "js": "JavaScript",
    "jsx": "JavaScript / React",
    "ts": "TypeScript",
    "tsx": "TypeScript / React",
    "json": "JSON",
    "txt": "Texto / dependências",
    "php": "PHP",
    "java": "Java",
    "go": "Go",
    "rb": "Ruby",
    "cs": "C#",
    "c": "C",
    "cpp": "C++",
}


def detect_language(filename: str) -> str:
    # Igual ao frontend: sem ponto, a "extensão" é o próprio nome do arquivo.
    extension = filename.split(".")[-1].lower() if filename else ""
    if not extension:
        return "Texto"
    return _LANGUAGES.get(extension, extension.upper())


def _iso_now() -> str:
    # Mesmo formato de Date.toISOString(): 2026-10-20T12:34:56.789Z
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _safe_ai_text(value: str, api_key: str, limit: int) -> str:
    value = value.replace(api_key, "[REDACTED]") if api_key else value
    value = _CREDENTIAL_URL.sub("[URL REDACTED]", value)
    return value.replace("\r", " ").replace("\n", " ")[:limit]


def run_analysis(
    filename: str,
    source: str,
    *,
    max_source_bytes: int,
    max_line_chars: int,
    scan_timeout_seconds: float | None = None,
    ai_settings: AISettings | None = None,
    ai_provider: AIProvider | None = None,
) -> dict[str, Any]:
    """Retorna um dict no formato ``Analysis`` do frontend (camelCase)."""
    try:
        size = len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:  # surrogates soltos vindos de JSON malformado
        raise ApiError(422, "O código contém caracteres inválidos.") from exc
    if size > max_source_bytes:
        raise ApiError(413, "O código excede o limite de 1 MB.")
    if not source.strip():
        raise ApiError(
            422, "Envie um arquivo ou cole um trecho de código para analisar."
        )

    start = time.perf_counter()
    try:
        result = scan_source(
            source,
            filename,
            max_line_chars=max_line_chars,
            time_budget_seconds=scan_timeout_seconds,
        )
    except ScanTimeout as exc:
        raise ApiError(
            422,
            "A análise excedeu o tempo limite. Envie um arquivo menor ou com linhas mais curtas.",
        ) from exc
    duration_ms = round((time.perf_counter() - start) * 1000)

    analysis = {
        "id": str(uuid.uuid4()),
        "filename": filename,
        "language": detect_language(filename),
        "linesAnalyzed": len(re.split(r"\r?\n", source)),
        "createdAt": _iso_now(),
        "durationMs": duration_ms,
        "findings": [finding.to_dict() for finding in result.findings],
        "rulesRun": result.rules_run,
    }

    try:
        ai_settings = ai_settings or AISettings.from_env()
    except AIConfigurationError:
        analysis["aiSummary"] = {"status": "indisponivel", "calls": 0}
        return analysis
    if not ai_settings.enabled:
        return analysis

    analyzer: AIAnalyzer | None = None
    try:
        provider = ai_provider or OpenAICompatibleClient(
            ai_settings.base_url,
            ai_settings.api_key,
            ai_settings.timeout_seconds,
        )
        analyzer = AIAnalyzer(ai_settings, provider)
        rule_findings = analysis["findings"]
        annotations = triage_findings(
            rule_findings, source, filename, analyzer
        )
        for finding in rule_findings:
            annotation = annotations.get(finding["id"])
            if annotation is None:
                continue
            finding["aiVerdict"] = annotation["verdict"]
            finding["aiConfidence"] = annotation["confidence"]
            finding["aiReason"] = _safe_ai_text(
                annotation["reason"], ai_settings.api_key, 200
            )

        if ai_settings.discovery:
            suggestions = discover_risky_functions(
                source, filename, rule_findings, analyzer
            )
            analysis["aiFindings"] = [
                {
                    **suggestion,
                    "reason": _safe_ai_text(
                        suggestion["reason"], ai_settings.api_key, 200
                    ),
                }
                for suggestion in suggestions[:_MAX_AI_FINDINGS]
            ]

        model = _safe_ai_text(ai_settings.model, ai_settings.api_key, 100)
        if "://" in model:
            model = ""
        analysis["aiSummary"] = {
            "status": "indisponivel" if analyzer.status == "indisponivel" else "ativa",
            "calls": analyzer.calls,
            **({"model": model} if model else {}),
        }
    except Exception:
        _LOGGER.warning("A camada de IA falhou; mantendo o resultado das regras.")
        analysis["aiSummary"] = {
            "status": "indisponivel",
            "calls": analyzer.calls if analyzer is not None else 0,
            **(
                {"model": _safe_ai_text(ai_settings.model, ai_settings.api_key, 100)}
                if ai_settings.model and "://" not in ai_settings.model
                else {}
            ),
        }
    return analysis
