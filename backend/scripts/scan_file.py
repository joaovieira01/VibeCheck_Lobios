"""Executa o scanner local em um arquivo, com triagem IA opcional."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.ai.config import AIConfigurationError, AISettings
from app.ai.provider import OpenAICompatibleClient
from app.ai.triage import AIProvider
from app.scanner import DEFAULT_MAX_LINE_CHARS
from app.service import run_analysis


def _load_root_env() -> None:
    load_dotenv(dotenv_path=ROOT / ".env", override=False)


class _TimedProvider:
    def __init__(self, provider: AIProvider):
        self.provider = provider
        self.elapsed_seconds = 0.0

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float = 0,
    ) -> str:
        started = time.perf_counter()
        try:
            return self.provider.complete(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
            )
        finally:
            self.elapsed_seconds += time.perf_counter() - started


def _ai_configuration(requested: bool) -> tuple[AISettings, str | None]:
    if not requested:
        return AISettings(), None
    try:
        settings = AISettings.from_env()
    except AIConfigurationError as exc:
        return AISettings(), f"Configuração de IA inválida ({exc})."
    if not settings.enabled:
        return AISettings(), "AI_ENABLED não está true."
    return settings, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="arquivo fonte a analisar")
    parser.add_argument(
        "--ai",
        action="store_true",
        help="triagem opcional usando AI_ENABLED=true e variáveis AI_*",
    )
    args = parser.parse_args(argv)
    try:
        source = args.file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Erro ao ler arquivo: {exc}", file=sys.stderr)
        return 2

    if args.ai:
        _load_root_env()
    settings, warning = _ai_configuration(args.ai)
    if warning:
        print(
            f"Aviso: {warning} Continuando somente com as regras.",
            file=sys.stderr,
        )

    timed_provider: _TimedProvider | None = None
    if settings.enabled:
        timed_provider = _TimedProvider(
            OpenAICompatibleClient(
                settings.base_url, settings.api_key, settings.timeout_seconds
            )
        )

    analysis = run_analysis(
        args.file.name,
        source,
        max_source_bytes=1_000_000,
        max_line_chars=DEFAULT_MAX_LINE_CHARS,
        scan_timeout_seconds=10,
        ai_settings=settings,
        ai_provider=timed_provider,
    )
    ai_summary = analysis.get("aiSummary")
    if ai_summary is None:
        ai_summary = {
            "status": "indisponivel" if warning else "desativada",
            "calls": 0,
        }
    output: dict[str, Any] = {
        "file": args.file.name,
        "findings": analysis["findings"],
        "aiFindings": analysis.get("aiFindings", []),
        "ai": {
            **ai_summary,
            "latencySeconds": round(
                timed_provider.elapsed_seconds if timed_provider else 0, 6
            ),
        },
    }
    if ai_summary["status"] == "indisponivel" and settings.enabled:
        print(
            "Aviso: provedor de IA indisponível; exibindo os achados das regras.",
            file=sys.stderr,
        )
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
