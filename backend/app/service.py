"""Orquestra uma análise: valida a entrada, executa o scanner e monta o resultado."""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .errors import ApiError
from .scanner import ScanTimeout, scan_source


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


def run_analysis(
    filename: str,
    source: str,
    *,
    max_source_bytes: int,
    max_line_chars: int,
    scan_timeout_seconds: float | None = None,
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

    return {
        "id": str(uuid.uuid4()),
        "filename": filename,
        "language": detect_language(filename),
        "linesAnalyzed": len(re.split(r"\r?\n", source)),
        "createdAt": _iso_now(),
        "durationMs": duration_ms,
        "findings": [finding.to_dict() for finding in result.findings],
        "rulesRun": result.rules_run,
    }
