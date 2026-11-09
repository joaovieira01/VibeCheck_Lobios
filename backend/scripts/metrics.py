"""Mede a linha de base do scanner nas amostras vulnerável e segura."""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.scanner import scan_source


SAMPLES = ROOT / "backend" / "tests" / "samples"
VULNERABLE_PATH = SAMPLES / "amostra_vulneravel.py"
SAFE_PATH = SAMPLES / "amostra_segura.py"
ANSWER_KEY_PATH = SAMPLES / "gabarito_amostra.json"


def _measure(path: Path) -> tuple[dict[str, Any], float]:
    source = path.read_text(encoding="utf-8")
    started = time.perf_counter()
    result = scan_source(source, path.name)
    elapsed = time.perf_counter() - started
    return (
        {
            "findings": [finding.to_dict() for finding in result.findings],
            "rulesRun": result.rules_run,
        },
        elapsed,
    )


def _recall(items: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    recalled = 0
    for item in items:
        expected_lines = set(item["lines"])
        if any(expected_lines.intersection(finding["locations"]) for finding in findings):
            recalled += 1
    return {
        "detected": recalled,
        "total": len(items),
        "recall": recalled / len(items) if items else None,
    }


def collect_metrics() -> dict[str, Any]:
    answer_key = json.loads(ANSWER_KEY_PATH.read_text(encoding="utf-8"))
    vulnerable, vulnerable_seconds = _measure(VULNERABLE_PATH)
    safe, safe_seconds = _measure(SAFE_PATH)
    items = answer_key["itens"]
    vulnerable_findings = vulnerable["findings"]
    categories: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        if item.get("owasp"):
            categories[item["owasp"]].append(item)

    expected_rules_by_line: dict[int, set[str]] = defaultdict(set)
    for item in items:
        if item["kind"] == "control":
            for line in item["lines"]:
                expected_rules_by_line[line].add(item["expectedRuleId"])
    unmatched_findings = []
    for finding in vulnerable_findings:
        unmatched_locations = [
            line
            for line in finding["locations"]
            if finding["id"] not in expected_rules_by_line.get(line, set())
        ]
        if unmatched_locations:
            unmatched_findings.append(
                {**finding, "unmatchedLocations": unmatched_locations}
            )

    return {
        "sample": answer_key["arquivo"],
        "rulesRun": vulnerable["rulesRun"],
        "recallTotal": _recall(items, vulnerable_findings),
        "recallByOwasp": {
            category: _recall(category_items, vulnerable_findings)
            for category, category_items in sorted(categories.items())
        },
        "findingsWithoutAnswerKeyMatch": unmatched_findings,
        "safeSampleFindings": safe["findings"],
        "analysisSeconds": {
            "vulnerable": vulnerable_seconds,
            "safe": safe_seconds,
            "total": vulnerable_seconds + safe_seconds,
        },
    }


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    metrics = collect_metrics()
    print("Métricas da linha de base")
    total = metrics["recallTotal"]
    print(
        f"Recall total: {total['detected']}/{total['total']} "
        f"({total['recall']:.1%})"
    )
    print("Recall por categoria OWASP:")
    for category, result in metrics["recallByOwasp"].items():
        print(f"  {category}: {result['detected']}/{result['total']} ({result['recall']:.1%})")
    print(
        "Achados sem correspondência no gabarito: "
        f"{len(metrics['findingsWithoutAnswerKeyMatch'])}"
    )
    print(f"Achados na amostra segura: {len(metrics['safeSampleFindings'])}")
    timings = metrics["analysisSeconds"]
    print(
        f"Tempo de análise: {timings['total']:.6f}s "
        f"(vulnerável {timings['vulnerable']:.6f}s; "
        f"segura {timings['safe']:.6f}s)"
    )
    print("JSON:")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
