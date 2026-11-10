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


def _strict_recall(
    items: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    correct: list[dict[str, Any]] = []
    wrong_rule: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for item in items:
        expected_lines = set(item["lines"])
        expected_rule = item["expectedRuleId"]
        correct_findings = [
            finding
            for finding in findings
            if finding["id"] == expected_rule
            and expected_lines.intersection(finding["locations"])
        ]
        if correct_findings:
            correct.append(item)
            continue
        other_rules = sorted(
            {
                finding["id"]
                for finding in findings
                if finding["id"] != expected_rule
                and expected_lines.intersection(finding["locations"])
            }
        )
        if other_rules:
            wrong_rule.append({**item, "foundRuleIds": other_rules})
        else:
            missing.append(item)
    return {
        "detectedByCorrectRule": len(correct),
        "detectedByWrongRule": len(wrong_rule),
        "notDetected": len(missing),
        "total": len(items),
        "recall": len(correct) / len(items) if items else None,
        "correctItems": correct,
        "wrongRuleItems": wrong_rule,
        "notDetectedItems": missing,
    }


def collect_metrics() -> dict[str, Any]:
    answer_key = json.loads(ANSWER_KEY_PATH.read_text(encoding="utf-8"))
    vulnerable, vulnerable_seconds = _measure(VULNERABLE_PATH)
    safe, safe_seconds = _measure(SAFE_PATH)
    items = answer_key["itens"]
    expected_findings = answer_key.get("expectedFindings", [])
    vulnerable_findings = vulnerable["findings"]
    expected_rules_by_line: dict[int, set[str]] = defaultdict(set)
    for item in [*items, *expected_findings]:
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

    categories = {
        category: _strict_recall(
            [item for item in items if item.get("owasp") == category],
            vulnerable_findings,
        )
        for category in sorted({item["owasp"] for item in items if item.get("owasp")})
    }
    return {
        "sample": answer_key["arquivo"],
        "rulesRun": vulnerable["rulesRun"],
        "recallTotal": _strict_recall(items, vulnerable_findings),
        "additionalExpectedFindings": _strict_recall(
            expected_findings, vulnerable_findings
        ),
        "recallByOwasp": categories,
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
        f"Recall pela regra correta: {total['detectedByCorrectRule']}/{total['total']} "
        f"({total['recall']:.1%})"
    )
    print(f"Detectado por regra errada na linha: {total['detectedByWrongRule']}")
    print(f"Não detectado: {total['notDetected']}")
    wrong_ids = ", ".join(
        f"{item['id']} ({', '.join(item['foundRuleIds'])})"
        for item in total["wrongRuleItems"]
    )
    missing_ids = ", ".join(item["id"] for item in total["notDetectedItems"])
    print(f"Itens detectados pela regra errada: {wrong_ids or 'nenhum'}")
    print(f"Itens não detectados: {missing_ids or 'nenhum'}")
    additional = metrics["additionalExpectedFindings"]
    print(
        "Achados adicionais esperados: "
        f"{additional['detectedByCorrectRule']}/{additional['total']} corretos; "
        f"{additional['detectedByWrongRule']} por regra errada; "
        f"{additional['notDetected']} não detectados"
    )
    print("Recall por categoria OWASP:")
    for category, result in metrics["recallByOwasp"].items():
        print(
            f"  {category}: {result['detectedByCorrectRule']}/{result['total']} "
            f"({result['recall']:.1%}); regra errada "
            f"{result['detectedByWrongRule']}; não detectado {result['notDetected']}"
        )
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
