"""Testes offline para a integração opcional de IA na análise e no histórico."""

from __future__ import annotations

import json
import secrets
import unittest
from pathlib import Path
from unittest.mock import patch

from app.ai.config import AISettings
from app.ai.triage import _CACHE, _CACHE_LOCK
from app.schemas import AnalysisOut
from app.scanner import scan_source
from app.service import run_analysis

TESTS = Path(__file__).parent
GOLDEN = TESTS / "golden"
SAMPLES = TESTS / "samples"
ANALYSIS_LIMITS = {"max_source_bytes": 1_000_000, "max_line_chars": 1000}


class FakeProvider:
    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def complete(self, *, model, messages, max_tokens, temperature=0):
        self.calls.append(
            {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        )
        return self.respond(messages)


def enabled_settings(*, discovery=False, api_key="runtime-api-key-placeholder"):
    return AISettings(
        enabled=True,
        base_url="https://provider.invalid/v1",
        api_key=api_key,
        model="small-test-model",
        discovery=discovery,
    )


class AIAnalysisIntegrationTests(unittest.TestCase):
    def setUp(self):
        with _CACHE_LOCK:
            _CACHE.clear()
        socket_blocker = patch(
            "socket.socket",
            side_effect=AssertionError("tests must not create network sockets"),
        )
        socket_blocker.start()
        self.addCleanup(socket_blocker.stop)

    def test_disabled_ai_preserves_scanner_results_for_golden_and_samples(self):
        corpus = json.loads((GOLDEN / "corpus.json").read_text(encoding="utf-8"))
        cases = [
            (case["filename"], case["source"])
            for case in corpus
        ] + [
            (path.name, path.read_text(encoding="utf-8"))
            for path in sorted(SAMPLES.glob("*.py"))
        ]
        disabled = AISettings()

        for filename, source in cases:
            with self.subTest(filename=filename):
                if not source.strip():
                    continue
                result = run_analysis(
                    filename,
                    source,
                    ai_settings=disabled,
                    **ANALYSIS_LIMITS,
                )
                expected = scan_source(
                    source, filename, max_line_chars=ANALYSIS_LIMITS["max_line_chars"]
                )
                self.assertEqual(
                    result["findings"],
                    [finding.to_dict() for finding in expected.findings],
                )
                self.assertEqual(result["rulesRun"], expected.rules_run)
                self.assertEqual(
                    set(result),
                    {
                        "id", "filename", "language", "linesAnalyzed", "createdAt",
                        "durationMs", "findings", "rulesRun",
                    },
                )

    def test_ai_annotations_are_bounded_and_do_not_leak_key_or_credential_url(self):
        key = "runtime-" + secrets.token_urlsafe(36)
        credential_url = (
            "https://"
            + secrets.token_urlsafe(8)
            + ":"
            + secrets.token_urlsafe(16)
            + "@example.invalid/path"
        )

        def respond(messages):
            user = json.loads(messages[-1]["content"])
            finding_id = user["findings"][0]["id"]
            return json.dumps(
                {
                    "results": [
                        {
                            "id": finding_id,
                            "verdict": "confirmado",
                            "confidence": 0.91,
                            "reason": f"Texto {key} {credential_url}",
                        }
                    ]
                }
            )

        provider = FakeProvider(respond)
        analysis = run_analysis(
            "handler.py",
            "def evaluate(value):\n    return eval(value)\n",
            ai_settings=enabled_settings(api_key=key),
            ai_provider=provider,
            **ANALYSIS_LIMITS,
        )

        finding = next(item for item in analysis["findings"] if item["id"] == "dynamic-eval")
        self.assertEqual(finding["aiVerdict"], "confirmado")
        self.assertEqual(finding["aiConfidence"], 0.91)
        self.assertLessEqual(len(finding["aiReason"]), 200)
        self.assertEqual(analysis["aiSummary"]["status"], "ativa")
        self.assertEqual(analysis["aiSummary"]["calls"], 1)
        serialized = json.dumps(analysis, ensure_ascii=False)
        self.assertNotIn(key, serialized)
        self.assertNotIn(credential_url.split("@", 1)[0], serialized)
        self.assertNotIn("aiPrompt", serialized)
        self.assertNotIn("aiCode", serialized)

        validated = AnalysisOut.model_validate(analysis)
        output = validated.model_dump(by_alias=True, exclude_unset=True)
        self.assertEqual(output["findings"][0]["aiVerdict"], "confirmado")
        self.assertEqual(output["aiSummary"]["model"], "small-test-model")

    def test_discovery_results_are_separate_and_capped(self):
        source_lines = [
            '@app.post("/items")',
            "def update_items(req):",
            *[f"    value_{index} = {index}" for index in range(25)],
        ]
        source = "\n".join(source_lines)

        def respond(messages):
            request = json.loads(messages[-1]["content"])
            if "findings" in request:
                return json.dumps({"results": []})
            code = request["functions"][0]["code"]
            lines = [
                int(line.split(":", 1)[0])
                for line in code.splitlines()
                if line[:1].isdigit()
            ]
            return json.dumps(
                {
                    "findings": [
                        {
                            "function_id": "f0",
                            "line": line,
                            "category": "other",
                            "confidence": 0.8,
                            "reason": "Revisão manual sugerida.",
                        }
                        for line in lines[2:27]
                    ]
                }
            )

        provider = FakeProvider(respond)
        analysis = run_analysis(
            "routes.py",
            source,
            ai_settings=enabled_settings(discovery=True),
            ai_provider=provider,
            **ANALYSIS_LIMITS,
        )
        self.assertEqual(len(analysis["aiFindings"]), 20)
        self.assertTrue(all(item["origin"] == "ia" for item in analysis["aiFindings"]))
        self.assertFalse(any("origin" in item for item in analysis["findings"]))
        self.assertEqual(analysis["aiSummary"]["calls"], 2)
        self.assertLessEqual(
            max(len(item["reason"]) for item in analysis["aiFindings"]), 200
        )

    def test_provider_failure_returns_rules_and_unavailable_status(self):
        key = "runtime-failure-key-placeholder"

        class FailingProvider:
            def complete(self, **_kwargs):
                raise RuntimeError(key)

        analysis = run_analysis(
            "handler.py",
            "def evaluate(value):\n    return eval(value)\n",
            ai_settings=enabled_settings(api_key=key),
            ai_provider=FailingProvider(),
            **ANALYSIS_LIMITS,
        )
        self.assertIn("dynamic-eval", {item["id"] for item in analysis["findings"]})
        self.assertEqual(analysis["aiSummary"]["status"], "indisponivel")
        self.assertNotIn(key, json.dumps(analysis))

    def test_legacy_history_payload_validates_without_ai_fields(self):
        legacy = {
            "id": "legacy-id",
            "filename": "old.py",
            "language": "Python",
            "linesAnalyzed": 1,
            "createdAt": "2025-01-01T00:00:00.000Z",
            "durationMs": 1,
            "findings": [],
            "rulesRun": 41,
        }
        output = AnalysisOut.model_validate(legacy).model_dump(
            by_alias=True, exclude_unset=True
        )
        self.assertEqual(output, legacy)


if __name__ == "__main__":
    unittest.main()
