"""Analisa um diretório ou ZIP e apresenta achados em texto, JSON ou SARIF."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import unicodedata
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


def _report_has_matching_finding(
    report: Any, fail_on: str
) -> bool:
    if not isinstance(report, dict) or not isinstance(
        report.get("findingsByFile"), dict
    ):
        raise ValueError("Estrutura de relatório inválida.")

    has_matching_finding = False
    for findings in report["findingsByFile"].values():
        if not isinstance(findings, list):
            raise ValueError("Estrutura de relatório inválida.")
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError("Estrutura de relatório inválida.")
            severity = finding.get("severity")
            if not isinstance(severity, str) or severity not in SEVERITY_ORDER:
                raise ValueError("Severidade inválida no relatório.")
            if SEVERITY_ORDER[severity] <= SEVERITY_ORDER[fail_on]:
                has_matching_finding = True
    return has_matching_finding


def _valid_git_ref(reference: str) -> bool:
    return (
        bool(reference)
        and not reference.startswith("-")
        and not any(
            character.isspace()
            or unicodedata.category(character).startswith("C")
            for character in reference
        )
    )


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
        description="Analisa repositórios ou aplica uma política a um relatório JSON.",
        epilog=(
            "Exemplo: python scripts/scan_repo.py ./projeto --format sarif\n"
            "Política: python scripts/scan_repo.py --check-report relatorio.json "
            "--fail-on Alta"
        ),
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", action="help", help="mostra esta ajuda e encerra"
    )
    parser.add_argument(
        "source",
        nargs="?",
        type=Path,
        help="diretório ou arquivo ZIP",
    )
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
    parser.add_argument(
        "--changed-since",
        metavar="REF",
        help="analisa apenas arquivos alterados desde uma referência Git",
    )
    parser.add_argument(
        "--check-report",
        type=Path,
        metavar="ARQUIVO.json",
        help="aplica --fail-on a um relatório JSON já gerado",
    )
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    args = parser.parse_args(argv)

    if args.check_report is not None:
        if (
            args.source is not None
            or args.changed_since is not None
            or args.format != "text"
        ):
            parser.error("--check-report não pode ser combinado com a entrada do scanner.")
        if args.fail_on is None:
            parser.error("--check-report exige a opção --fail-on.")
        try:
            report = json.loads(args.check_report.read_text(encoding="utf-8"))
            has_matching_finding = _report_has_matching_finding(
                report, args.fail_on
            )
        except (OSError, UnicodeError, ValueError):
            print(
                "Erro: não foi possível ler um relatório JSON válido do VibeCheck.",
                file=sys.stderr,
            )
            return 2
        if has_matching_finding:
            print(
                "Política reprovada: há achados na severidade configurada ou superior."
            )
            return 1
        print("Política aprovada: nenhum achado atingiu a severidade configurada.")
        return 0

    if args.source is None:
        parser.error("informe um diretório ou arquivo ZIP para analisar.")
    if args.changed_since is not None and not _valid_git_ref(args.changed_since):
        print(
            "Erro: referência Git inválida. Não use hífen inicial, espaços "
            "ou caracteres de controle.",
            file=sys.stderr,
        )
        return 2

    try:
        if args.changed_since is None:
            report = scan_repository(args.source)
        else:
            if not args.source.is_dir():
                raise RepositoryScanError(
                    "A seleção de arquivos alterados só pode ser usada com um diretório."
                )
            diff = subprocess.run(
                [
                    "git",
                    "diff",
                    "--name-only",
                    "-z",
                    args.changed_since,
                    "--",
                ],
                cwd=args.source,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=True,
            )
            changed_files = {
                name.decode("utf-8", errors="replace").replace("\\", "/")
                for name in diff.stdout.split(b"\0")
                if name
            }
            report = scan_repository(args.source, only_files=changed_files)
    except subprocess.CalledProcessError:
        print(
            "Erro: não foi possível comparar a referência Git. Em clones rasos, "
            "busque o commit base com `git fetch origin <ref>` ou `git fetch --unshallow`.",
            file=sys.stderr,
        )
        return 2
    except FileNotFoundError:
        if args.changed_since is not None:
            print(
                "Erro: Git não está instalado ou a referência Git não está disponível. "
                "Em clones rasos, busque o commit base com `git fetch origin <ref>` "
                "ou `git fetch --unshallow`.",
                file=sys.stderr,
            )
        else:
            print(
                "Erro: não foi possível analisar a entrada. Verifique o diretório "
                "ou arquivo ZIP.",
                file=sys.stderr,
            )
        return 2
    except (RepositoryScanError, OSError, ValueError, subprocess.SubprocessError):
        print(
            "Erro: não foi possível analisar a entrada. Verifique o diretório, "
            "arquivo ZIP ou referência Git.",
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
