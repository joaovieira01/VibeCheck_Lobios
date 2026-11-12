"""Mede a linha de base do scanner nas amostras vulnerável e segura."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.scanner import scan_source
from app.ai.config import AIConfigurationError, AISettings
from app.ai.provider import OpenAICompatibleClient
from app.ai.triage import AIProvider
from app.service import run_analysis


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


class _TimedProvider:
    def __init__(self, provider: AIProvider):
        self.provider = provider
        self.elapsed_seconds = 0.0

    def complete(self, **kwargs: Any) -> str:
        started = time.perf_counter()
        try:
            return self.provider.complete(**kwargs)
        finally:
            self.elapsed_seconds += time.perf_counter() - started


def _is_high_confidence_false_positive(finding: dict[str, Any]) -> bool:
    return (
        finding.get("aiVerdict") == "falso_positivo"
        and finding.get("aiConfidence", 0) >= 0.85
    )


def _collect_ai_metrics(
    *,
    answer_key: dict[str, Any],
    baseline: dict[str, Any],
    settings: AISettings,
    provider: AIProvider | None,
) -> dict[str, Any]:
    if not settings.enabled:
        return {
            "status": "desativada",
            "warning": "AI_ENABLED não está true; foram mantidas as métricas somente por regras.",
            "calls": 0,
            "latencySeconds": 0,
            "withoutAI": {
                "recall": baseline["recallTotal"]["recall"],
                "potentialFalsePositives": (
                    len(baseline["findingsWithoutAnswerKeyMatch"])
                    + len(baseline["safeSampleFindings"])
                ),
            },
        }

    timed_provider = _TimedProvider(
        provider
        or OpenAICompatibleClient(
            settings.base_url, settings.api_key, settings.timeout_seconds
        )
    )
    analyses: dict[str, dict[str, Any]] = {}
    for path in (VULNERABLE_PATH, SAFE_PATH):
        source = path.read_text(encoding="utf-8")
        analyses[path.name] = run_analysis(
            path.name,
            source,
            max_source_bytes=1_000_000,
            max_line_chars=1000,
            scan_timeout_seconds=10,
            ai_settings=settings,
            ai_provider=timed_provider,
        )

    vulnerable = analyses[VULNERABLE_PATH.name]
    safe = analyses[SAFE_PATH.name]
    expected_rules_by_line: dict[int, set[str]] = defaultdict(set)
    for item in [*answer_key["itens"], *answer_key.get("expectedFindings", [])]:
        for line in item["lines"]:
            expected_rules_by_line[line].add(item["expectedRuleId"])

    findings_with_ai = vulnerable["findings"]
    effective_findings = [
        finding
        for finding in findings_with_ai
        if not _is_high_confidence_false_positive(finding)
    ]
    flagged_false_positives = 0
    for finding in findings_with_ai:
        unmatched = any(
            finding["id"] not in expected_rules_by_line.get(line, set())
            for line in finding["locations"]
        )
        if unmatched and _is_high_confidence_false_positive(finding):
            flagged_false_positives += 1
    flagged_false_positives += sum(
        _is_high_confidence_false_positive(finding) for finding in safe["findings"]
    )

    potential_false_positives = (
        len(baseline["findingsWithoutAnswerKeyMatch"])
        + len(baseline["safeSampleFindings"])
    )
    summary_statuses = {
        analysis.get("aiSummary", {}).get("status", "indisponivel")
        for analysis in analyses.values()
    }
    status = "indisponivel" if "indisponivel" in summary_statuses else "ativa"
    return {
        "status": status,
        "model": settings.model,
        "calls": sum(
            analysis.get("aiSummary", {}).get("calls", 0)
            for analysis in analyses.values()
        ),
        "latencySeconds": round(timed_provider.elapsed_seconds, 6),
        "withoutAI": {
            "recall": baseline["recallTotal"]["recall"],
            "potentialFalsePositives": potential_false_positives,
        },
        "withAI": {
            "recall": _strict_recall(
                answer_key["itens"], effective_findings
            )["recall"],
            "potentialFalsePositives": max(
                0, potential_false_positives - flagged_false_positives
            ),
            "flaggedFalsePositives": flagged_false_positives,
        },
        "note": (
            "Estimativa de triagem: os achados continuam presentes; somente "
            "falsos positivos com confiança >= 0,85 são descontados destas métricas."
        ),
    }


def collect_metrics(
    *,
    ai: bool = False,
    ai_settings: AISettings | None = None,
    ai_provider: AIProvider | None = None,
) -> dict[str, Any]:
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
    metrics = {
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
    if ai:
        try:
            settings = ai_settings or AISettings.from_env()
            metrics["aiMetrics"] = _collect_ai_metrics(
                answer_key=answer_key,
                baseline=metrics,
                settings=settings,
                provider=ai_provider,
            )
        except AIConfigurationError as exc:
            metrics["aiMetrics"] = {
                "status": "indisponivel",
                "warning": (
                    f"Configuração de IA inválida ({exc}); foram mantidas as "
                    "métricas somente por regras."
                ),
                "calls": 0,
                "latencySeconds": 0,
                "withoutAI": {
                    "recall": metrics["recallTotal"]["recall"],
                    "potentialFalsePositives": (
                        len(metrics["findingsWithoutAnswerKeyMatch"])
                        + len(metrics["safeSampleFindings"])
                    ),
                },
            }
    return metrics


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ai",
        action="store_true",
        help="triagem opcional dos achados usando a configuração AI_*",
    )
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8")
    metrics = collect_metrics(ai=args.ai)
    if args.ai and metrics["aiMetrics"].get("warning"):
        print(f"Aviso: {metrics['aiMetrics']['warning']}", file=sys.stderr)
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
    if args.ai:
        ai_metrics = metrics["aiMetrics"]
        print(
            "Triagem IA: "
            f"status={ai_metrics['status']}; chamadas={ai_metrics['calls']}; "
            f"latência={ai_metrics['latencySeconds']:.6f}s"
        )
        if "withAI" in ai_metrics:
            print(
                "Recall sem/com IA: "
                f"{ai_metrics['withoutAI']['recall']:.1%}/"
                f"{ai_metrics['withAI']['recall']:.1%}; falsos positivos "
                "potenciais sem/com IA: "
                f"{ai_metrics['withoutAI']['potentialFalsePositives']}/"
                f"{ai_metrics['withAI']['potentialFalsePositives']}"
            )
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
