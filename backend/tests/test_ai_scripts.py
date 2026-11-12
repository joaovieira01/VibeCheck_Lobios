from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.ai.config import AISettings
from scripts.metrics import collect_metrics
from scripts.scan_file import main as scan_file_main


class FakeProvider:
    def __init__(self, verdict: str = "falso_positivo"):
        self.verdict = verdict
        self.calls = 0

    def complete(self, *, model, messages, max_tokens, temperature=0):
        self.calls += 1
        request = json.loads(messages[-1]["content"])
        return json.dumps(
            {
                "results": [
                    {
                        "id": item["id"],
                        "verdict": self.verdict,
                        "confidence": 0.96,
                        "reason": "Rótulo de teste offline.",
                    }
                    for item in request["findings"]
                ]
            }
        )


def enabled_settings() -> AISettings:
    return AISettings(
        enabled=True,
        base_url="https://provider.invalid/v1",
        api_key="runtime-test-placeholder",
        model="small-test-model",
    )


class AIScriptTests(unittest.TestCase):
    def setUp(self):
        socket_blocker = patch(
            "socket.socket",
            side_effect=AssertionError("tests must not create network sockets"),
        )
        socket_blocker.start()
        self.addCleanup(socket_blocker.stop)

    def test_rules_only_metrics_keep_the_28_of_28_baseline(self):
        metrics = collect_metrics()
        self.assertEqual(metrics["recallTotal"]["detectedByCorrectRule"], 28)
        self.assertEqual(metrics["recallTotal"]["total"], 28)
        self.assertNotIn("aiMetrics", metrics)

    def test_metrics_ai_reports_baseline_and_triage_estimate_offline(self):
        provider = FakeProvider()
        metrics = collect_metrics(
            ai=True,
            ai_settings=enabled_settings(),
            ai_provider=provider,
        )
        ai_metrics = metrics["aiMetrics"]

        self.assertEqual(metrics["recallTotal"]["detectedByCorrectRule"], 28)
        self.assertEqual(ai_metrics["status"], "ativa")
        self.assertGreater(ai_metrics["calls"], 0)
        self.assertEqual(ai_metrics["calls"], provider.calls)
        self.assertGreaterEqual(ai_metrics["latencySeconds"], 0)
        self.assertEqual(ai_metrics["withoutAI"]["recall"], 1.0)
        self.assertLessEqual(
            ai_metrics["withAI"]["potentialFalsePositives"],
            ai_metrics["withoutAI"]["potentialFalsePositives"],
        )

    def test_metrics_ai_without_configuration_keeps_rules_metrics(self):
        metrics = collect_metrics(ai=True, ai_settings=AISettings())
        self.assertEqual(metrics["recallTotal"]["detectedByCorrectRule"], 28)
        self.assertEqual(metrics["recallTotal"]["total"], 28)
        self.assertEqual(metrics["aiMetrics"]["status"], "desativada")
        self.assertEqual(metrics["aiMetrics"]["calls"], 0)

    def test_scan_file_ai_without_configuration_warns_and_scans_rules_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.py"
            path.write_text(
                "def evaluate(value):\n    return eval(value)\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch.dict(os.environ, {"AI_ENABLED": "false"}, clear=True):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                    stderr
                ):
                    status = scan_file_main([str(path), "--ai"])

        self.assertEqual(status, 0)
        self.assertIn("Continuando somente com as regras", stderr.getvalue())
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["ai"]["status"], "indisponivel")
        self.assertEqual(output["ai"]["calls"], 0)
        self.assertIn("dynamic-eval", {item["id"] for item in output["findings"]})


if __name__ == "__main__":
    unittest.main()
