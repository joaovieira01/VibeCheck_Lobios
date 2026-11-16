"""Orquestra uma análise: valida a entrada, executa o scanner e monta o resultado."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .ai.config import AIConfigurationError, AISettings
from .ai.discovery import discover_risky_functions
from .ai.provider import (
    AIProviderError,
    OpenAICompatibleClient,
    normalize_ai_error_code,
)
from .ai.triage import AIAnalyzer, AIProvider, triage_findings
from .deps import check_dependencies, online_dependencies_enabled
from .errors import ApiError
from .repo_scan import RepositoryScanError, scan_repository
from .scanner import ScanTimeout, scan_source

_MAX_AI_FINDINGS = 20
_MAX_REPOSITORY_FINDINGS_PER_FILE = 20
_MAX_REPOSITORY_FINDINGS_TOTAL = 1000
_MAX_REPOSITORY_OCCURRENCES_PER_FINDING = 20
_MAX_REPOSITORY_PAYLOAD_BYTES = 8_000_000
_MAX_REPOSITORY_PATH_CHARS = 512
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
    online_deps: bool | None = None,
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
    check_online_dependencies = (
        online_dependencies_enabled() if online_deps is None else online_deps
    )
    if check_online_dependencies:
        dependency_check = check_dependencies(source, filename)
        analysis["findings"].extend(
            finding.to_dict() for finding in dependency_check.findings
        )
        analysis["onlineDependencyCheck"] = dependency_check.to_dict()

    try:
        ai_settings = ai_settings or AISettings.from_env()
    except AIConfigurationError:
        analysis["aiSummary"] = {
            "status": "indisponivel",
            "calls": 0,
            "errorCode": "configuracao_invalida",
        }
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
        unavailable = analyzer.status == "indisponivel"
        analysis["aiSummary"] = {
            "status": "indisponivel" if unavailable else "ativa",
            "calls": analyzer.calls,
            **({"model": model} if model else {}),
            **(
                {
                    "errorCode": normalize_ai_error_code(
                        analyzer.error_code or "network_error"
                    )
                }
                if unavailable
                else {}
            ),
        }
    except AIProviderError as exc:
        analysis["aiSummary"] = {
            "status": "indisponivel",
            "calls": analyzer.calls if analyzer is not None else 0,
            "errorCode": normalize_ai_error_code(str(exc)),
        }
    except Exception:
        _LOGGER.warning("A camada de IA falhou; mantendo o resultado das regras.")
        analysis["aiSummary"] = {
            "status": "indisponivel",
            "calls": analyzer.calls if analyzer is not None else 0,
            "errorCode": "network_error",
            **(
                {"model": _safe_ai_text(ai_settings.model, ai_settings.api_key, 100)}
                if ai_settings.model and "://" not in ai_settings.model
                else {}
            ),
        }
    return analysis


def _repository_display_path(path: str) -> tuple[str, bool]:
    if len(path) <= _MAX_REPOSITORY_PATH_CHARS:
        return path, False
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()[:16]
    return f"{path[:_MAX_REPOSITORY_PATH_CHARS - 18]}…{digest}", True


def _compact_size(payload: dict[str, Any]) -> int:
    return len(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def run_repository_analysis(
    filename: str,
    archive_base64: str,
    *,
    max_archive_bytes: int,
) -> dict[str, Any]:
    """Decodifica, analisa e limita o histórico de uma varredura de repositório."""
    safe_filename = PurePosixPath(filename.replace("\\", "/")).name
    if not safe_filename.casefold().endswith(".zip"):
        raise ApiError(400, "Envie um arquivo ZIP válido.")

    max_encoded_length = ((max_archive_bytes + 2) // 3) * 4
    if len(archive_base64) > max_encoded_length:
        raise ApiError(413, "O arquivo ZIP excede o limite configurado.")
    try:
        archive_bytes = base64.b64decode(archive_base64, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(400, "O conteúdo enviado não é um arquivo ZIP válido.") from None
    if len(archive_bytes) > max_archive_bytes:
        raise ApiError(413, "O arquivo ZIP excede o limite configurado.")

    try:
        with tempfile.TemporaryDirectory(prefix="vibecheck-upload-") as temporary:
            archive_path = Path(temporary) / "repository.zip"
            archive_path.write_bytes(archive_bytes)
            result = scan_repository(archive_path)
    except RepositoryScanError:
        raise ApiError(
            400, "O ZIP é inválido ou excede os limites de segurança."
        ) from None

    display_paths: dict[str, str] = {}
    paths_truncated = False

    def display(path: str) -> str:
        nonlocal paths_truncated
        if path not in display_paths:
            display_paths[path], was_truncated = _repository_display_path(path)
            paths_truncated = paths_truncated or was_truncated
        return display_paths[path]

    analysis: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "analysisType": "repository",
        "filename": safe_filename,
        "createdAt": _iso_now(),
        "findingsByFile": {},
        "countsBySeverity": result["countsBySeverity"],
        "countsByOwasp": result["countsByOwasp"],
        "filesAnalyzed": [display(path) for path in result["filesAnalyzed"]],
        "ignoredFiles": [
            {"path": display(item["path"]), "reason": item["reason"]}
            for item in result["ignoredFiles"]
        ],
        "filesNotAnalyzed": [display(path) for path in result["filesNotAnalyzed"]],
        "partial": result["partial"],
        "durationSeconds": result["durationSeconds"],
        "findingsTruncated": False,
        "truncatedFindingsCount": 0,
        "truncatedOccurrencesCount": 0,
        "pathsTruncated": False,
    }

    current_size = _compact_size(analysis)
    total_findings = 0
    for path, findings in result["findingsByFile"].items():
        display_path = display(path)
        stored_for_file: list[dict[str, Any]] = []
        for finding in findings:
            locations = finding.get("locations", [])
            if (
                len(stored_for_file) >= _MAX_REPOSITORY_FINDINGS_PER_FILE
                or total_findings >= _MAX_REPOSITORY_FINDINGS_TOTAL
            ):
                analysis["truncatedFindingsCount"] += 1
                analysis["truncatedOccurrencesCount"] += len(locations)
                continue

            stored = dict(finding)
            kept_locations = locations[:_MAX_REPOSITORY_OCCURRENCES_PER_FINDING]
            stored["locations"] = kept_locations
            stored["evidence"] = finding.get("evidence", [])[: len(kept_locations)]
            if isinstance(finding.get("suggestedFix"), list):
                stored["suggestedFix"] = finding["suggestedFix"][: len(kept_locations)]
            omitted_occurrences = len(locations) - len(kept_locations)
            encoded_item = json.dumps(
                stored, ensure_ascii=False, separators=(",", ":")
            )
            item_size = len(encoded_item.encode("utf-8"))
            if not stored_for_file and display_path not in analysis["findingsByFile"]:
                encoded_key = json.dumps(display_path, ensure_ascii=False)
                delta = len(encoded_key.encode("utf-8")) + item_size + (
                    3 if not analysis["findingsByFile"] else 4
                )
            else:
                delta = item_size + 1
            if current_size + delta + 64 > _MAX_REPOSITORY_PAYLOAD_BYTES:
                analysis["truncatedFindingsCount"] += 1
                analysis["truncatedOccurrencesCount"] += len(locations)
                continue

            stored_for_file.append(stored)
            analysis["truncatedOccurrencesCount"] += omitted_occurrences
            total_findings += 1
            current_size += delta

        if stored_for_file:
            analysis["findingsByFile"][display_path] = stored_for_file

    analysis["findingsTruncated"] = bool(
        analysis["truncatedFindingsCount"]
        or analysis["truncatedOccurrencesCount"]
    )
    analysis["pathsTruncated"] = paths_truncated
    if _compact_size(analysis) > _MAX_REPOSITORY_PAYLOAD_BYTES:
        raise ApiError(
            413,
            "O resultado é grande demais para ser salvo no histórico. Reduza o tamanho do repositório.",
        )
    return analysis
