"""Mede o scanner num corpus independente pequeno, sem rede."""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

BACKEND = Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
BENCHMARK = BACKEND / "tests" / "benchmark"
LABELS_PATH = BENCHMARK / "labels.json"
REPORT_PATH = BENCHMARK / "report.json"
sys.path.insert(0, str(BACKEND))

from app.scanner import scan_source


def _read_labels() -> dict[str, Any]:
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    vulnerable = labels["vulnerable"]
    safe_files = labels["safe_files"]
    if len(vulnerable) != 28 or len(safe_files) != 12:
        raise ValueError("O corpus deve conter 28 arquivos vulneráveis e 12 seguros.")
    if set(vulnerable).intersection(safe_files):
        raise ValueError("Um arquivo não pode ser vulnerável e seguro ao mesmo tempo.")
    return labels


def _safe_path(name: str) -> Path:
    path = (BENCHMARK / name).resolve()
    if path.parent != BENCHMARK.resolve() or not path.is_file():
        raise ValueError(f"Arquivo de benchmark ausente ou fora do diretório: {name}")
    return path


def collect_benchmark() -> dict[str, Any]:
    labels = _read_labels()
    vulnerable: dict[str, dict[str, Any]] = labels["vulnerable"]
    safe_files: list[str] = labels["safe_files"]
    filenames = sorted([*vulnerable, *safe_files])

    expected: dict[tuple[str, int], set[str]] = defaultdict(set)
    for filename, label in vulnerable.items():
        for line in label["lines"]:
            expected[(filename, line)].add(label["category"])

    total_started = time.perf_counter()
    file_results: list[dict[str, Any]] = []
    reported: list[dict[str, Any]] = []
    for filename in filenames:
        path = _safe_path(filename)
        source = path.read_text(encoding="utf-8")
        started = time.perf_counter()
        result = scan_source(source, filename)
        elapsed = time.perf_counter() - started

        occurrences = []
        for finding in result.findings:
            for index, line in enumerate(finding.locations):
                occurrence = {
                    "file": filename,
                    "line": line,
                    "ruleId": finding.id,
                    "category": finding.owasp_id,
                    "title": finding.title,
                    "evidence": finding.evidence[index],
                    "labeled": finding.owasp_id in expected.get((filename, line), set()),
                }
                occurrences.append(occurrence)
                reported.append(occurrence)
        file_results.append(
            {
                "file": filename,
                "elapsedSeconds": elapsed,
                "findingCount": len(occurrences),
                "findings": occurrences,
            }
        )
    total_seconds = time.perf_counter() - total_started

    matched_labels = {
        (finding["file"], finding["line"], finding["category"])
        for finding in reported
        if finding["labeled"]
    }
    false_negatives = [
        {
            "file": filename,
            "line": line,
            "category": label["category"],
        }
        for filename, label in sorted(vulnerable.items())
        for line in label["lines"]
        if (filename, line, label["category"]) not in matched_labels
    ]
    false_positives = [finding for finding in reported if not finding["labeled"]]

    category_totals: dict[str, int] = defaultdict(int)
    category_hits: dict[str, int] = defaultdict(int)
    for filename, label in vulnerable.items():
        for line in label["lines"]:
            category_totals[label["category"]] += 1
            if (filename, line, label["category"]) in matched_labels:
                category_hits[label["category"]] += 1

    total_labels = sum(len(item["lines"]) for item in vulnerable.values())
    matched_count = total_labels - len(false_negatives)
    finding_count = len(reported)
    metrics = {
        "files": len(filenames),
        "vulnerableFiles": len(vulnerable),
        "safeFiles": len(safe_files),
        "expectedVulnerabilities": total_labels,
        "matchedVulnerabilities": matched_count,
        "recall": matched_count / total_labels if total_labels else None,
        "findings": finding_count,
        "truePositiveFindings": sum(finding["labeled"] for finding in reported),
        "falsePositiveFindings": len(false_positives),
        "precision": (
            sum(finding["labeled"] for finding in reported) / finding_count
            if finding_count
            else None
        ),
        "falsePositiveRate": len(false_positives) / finding_count if finding_count else 0.0,
        "totalScanSeconds": total_seconds,
        "underTwoMinutes": total_seconds < 120,
        "recallByCategory": {
            category: {
                "matched": category_hits[category],
                "expected": total,
                "recall": category_hits[category] / total if total else None,
            }
            for category, total in sorted(category_totals.items())
        },
    }
    return {
        "method": "Uma detecção é correta quando coincide arquivo, linha e categoria OWASP.",
        "metrics": metrics,
        "files": file_results,
        "falseNegatives": false_negatives,
        "falsePositives": false_positives,
    }


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    report = collect_benchmark()
    REPORT_PATH.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    metrics = report["metrics"]
    print("Benchmark independente do scanner")
    print(
        f"Recall total: {metrics['matchedVulnerabilities']}/"
        f"{metrics['expectedVulnerabilities']} ({metrics['recall']:.1%})"
    )
    print("Recall por categoria OWASP:")
    for category, values in metrics["recallByCategory"].items():
        print(
            f"  {category}: {values['matched']}/{values['expected']} "
            f"({values['recall']:.1%})"
        )
    precision = metrics["precision"]
    print(
        f"Precisão: {precision:.1%}" if precision is not None else "Precisão: n/a (sem achados)"
    )
    print(
        f"Taxa de falsos positivos: {metrics['falsePositiveFindings']}/"
        f"{metrics['findings']} ({metrics['falsePositiveRate']:.1%})"
    )
    print(f"Tempo total do scanner: {metrics['totalScanSeconds']:.6f}s")
    print("Tempo por arquivo:")
    for item in report["files"]:
        print(f"  {item['file']}: {item['elapsedSeconds']:.6f}s")
    print("Falsos negativos:")
    for item in report["falseNegatives"]:
        print(f"  {item['file']}:{item['line']} ({item['category']})")
    if not report["falseNegatives"]:
        print("  nenhum")
    print("Falsos positivos:")
    for item in report["falsePositives"]:
        print(
            f"  {item['file']}:{item['line']} ({item['ruleId']}, "
            f"{item['category']})"
        )
    if not report["falsePositives"]:
        print("  nenhum")
    print(f"Relatório JSON: {REPORT_PATH.relative_to(REPOSITORY)}")


if __name__ == "__main__":
    main()
