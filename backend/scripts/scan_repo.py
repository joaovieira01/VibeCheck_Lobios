"""Analisa um diretório ou ZIP e apresenta achados em texto, JSON ou SARIF."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.repo_scan import RepositoryScanError, scan_repository
from app.scanner import SEVERITY_ORDER


class PortugueseArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._positionals.title = "argumentos"
        self._optionals.title = "opções"

    def format_usage(self) -> str:
        return super().format_usage().replace("usage:", "Uso:")

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "Uso:")
            .replace("positional arguments:", "argumentos:")
            .replace("options:", "opções:")
        )

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"Erro: argumentos inválidos. Consulte --help.\n")


def _sarif(report: dict[str, Any]) -> dict[str, Any]:
    rule_metadata: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    levels = {"Crítica": "error", "Alta": "error", "Média": "warning", "Baixa": "note"}

    for filename, findings in report["findingsByFile"].items():
        for finding in findings:
            rule_id = finding["id"]
            rule_metadata.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding["title"],
                    "shortDescription": {"text": finding["title"]},
                    "defaultConfiguration": {
                        "level": levels[finding["severity"]]
                    },
                },
            )
            for index, line in enumerate(finding["locations"]):
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": levels[finding["severity"]],
                        "message": {"text": finding["description"]},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": quote(filename, safe="/._-")
                                    },
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                        "partialFingerprints": {
                            "primaryLocationLineHash": (
                                f"{rule_id}:{filename}:{line}:{index}"
                            )
                        },
                    }
                )

    output: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VibeCheck",
                        "informationUri": "https://github.com/joaovieira01/VibeCheck_Lobios",
                        "rules": list(rule_metadata.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    if report["partial"]:
        output["runs"][0]["invocations"] = [
            {
                "executionSuccessful": False,
                "toolExecutionNotifications": [
                    {
                        "level": "warning",
                        "message": {
                            "text": (
                                "A análise parcial atingiu o limite de tempo; "
                                "alguns arquivos não foram analisados."
                            )
                        },
                    }
                ],
            }
        ]
    return output


def _text(report: dict[str, Any]) -> str:
    lines = [
        f"Arquivos analisados: {len(report['filesAnalyzed'])}",
        f"Achados: {sum(report['countsBySeverity'].values())}",
        f"Duração: {report['durationSeconds']:.3f}s",
    ]
    if report["countsBySeverity"]:
        lines.append("Por severidade:")
        lines.extend(
            f"  {severity}: {count}"
            for severity, count in sorted(
                report["countsBySeverity"].items(),
                key=lambda item: SEVERITY_ORDER[item[0]],
            )
        )
    for filename, findings in report["findingsByFile"].items():
        for finding in findings:
            for line_number in finding["locations"]:
                lines.append(
                    f"{filename}:{line_number}: {finding['severity']} — "
                    f"{finding['title']} ({finding['id']})"
                )
    if report["ignoredFiles"]:
        lines.append(f"Itens ignorados: {len(report['ignoredFiles'])}")
    if report["partial"]:
        lines.append(
            f"Análise parcial; sem análise: {len(report['filesNotAnalyzed'])} arquivo(s)."
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = PortugueseArgumentParser(
        description="Analisa arquivos de um diretório ou arquivo ZIP.",
        epilog="Exemplo: python scripts/scan_repo.py ./projeto --format sarif",
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", action="help", help="mostra esta ajuda e encerra"
    )
    parser.add_argument("source", type=Path, help="diretório ou arquivo ZIP")
    parser.add_argument(
        "--fail-on",
        choices=("Crítica", "Alta", "Média", "Baixa"),
        help="sai com código 1 se houver achado desta severidade ou mais grave",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="formato de saída (padrão: text)",
    )
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    args = parser.parse_args(argv)
    try:
        report = scan_repository(args.source)
    except (RepositoryScanError, OSError, ValueError):
        print(
            "Erro: não foi possível analisar a entrada. Verifique o diretório ou arquivo ZIP.",
            file=sys.stderr,
        )
        return 2

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.format == "sarif":
        print(json.dumps(_sarif(report), ensure_ascii=False, indent=2))
    else:
        print(_text(report))

    if args.fail_on is None:
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    has_matching_finding = any(
        SEVERITY_ORDER[finding["severity"]] <= threshold
        for findings in report["findingsByFile"].values()
        for finding in findings
    )
    return 1 if has_matching_finding else 0


if __name__ == "__main__":
    raise SystemExit(main())
