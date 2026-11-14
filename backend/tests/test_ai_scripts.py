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
from scripts import metrics as metrics_script, scan_file as scan_file_script
from scripts.metrics import collect_metrics
from scripts.scan_file import main as scan_file_main


class FakeProvider:
    def __init__(self, verdict: str = "falso_positivo"):
        self.verdict = verdict
        self.calls = 0

    def complete(
        self,
        *,
        model,
        messages,
        max_tokens,
        temperature=0,
        timeout_seconds=None,
        reasoning_effort=None,
    ):
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
        self.assertIn("continuando somente com as regras", stderr.getvalue())
        self.assertIn("configuracao_invalida", stderr.getvalue())
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["ai"]["status"], "indisponivel")
        self.assertEqual(output["ai"]["calls"], 0)
        self.assertIn("dynamic-eval", {item["id"] for item in output["findings"]})

    def test_metrics_ai_loads_root_env_without_overriding_process_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "AI_ENABLED=true\n"
                "AI_BASE_URL=https://provider.invalid/v1\n"
                "AI_API_KEY=placeholder\n"
                "AI_MODEL=dotenv-model\n",
                encoding="utf-8",
            )
            with patch.object(metrics_script, "ROOT", root), patch.dict(
                os.environ, {"AI_MODEL": "environment-model"}, clear=True
            ):
                metrics = collect_metrics(ai=True, ai_provider=FakeProvider())

        self.assertEqual(metrics["aiMetrics"]["status"], "ativa")
        self.assertEqual(metrics["aiMetrics"]["model"], "environment-model")

    def test_scan_file_ai_loads_root_env_without_overriding_process_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text(
                "AI_ENABLED=true\n"
                "AI_BASE_URL=https://provider.invalid/v1\n"
                "AI_API_KEY=placeholder\n"
                "AI_MODEL=dotenv-model\n",
                encoding="utf-8",
            )
            source_path = root / "sample.py"
            source_path.write_text(
                "def evaluate(value):\n    return eval(value)\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with patch.object(scan_file_script, "ROOT", root), patch.object(
                scan_file_script,
                "OpenAICompatibleClient",
                lambda *_args, **_kwargs: FakeProvider(),
            ), patch.dict(
                os.environ, {"AI_MODEL": "environment-model"}, clear=True
            ), contextlib.redirect_stdout(stdout):
                status = scan_file_main([str(source_path), "--ai"])

        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(stdout.getvalue())["ai"]["model"], "environment-model"
        )

    def test_ai_scripts_work_when_root_env_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "sample.py"
            source_path.write_text("print('rules only')\n", encoding="utf-8")
            stdout = io.StringIO()
            with patch.object(scan_file_script, "ROOT", root), patch.dict(
                os.environ, {}, clear=True
            ), contextlib.redirect_stdout(stdout):
                status = scan_file_main([str(source_path), "--ai"])
            self.assertEqual(status, 0)
            self.assertEqual(
                json.loads(stdout.getvalue())["ai"]["status"], "indisponivel"
            )

            with patch.object(metrics_script, "ROOT", root), patch.dict(
                os.environ, {}, clear=True
            ):
                metrics = collect_metrics(ai=True)
        self.assertEqual(metrics["aiMetrics"]["status"], "desativada")

    def test_scan_file_prints_only_the_sanitized_error_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.py"
            path.write_text("print('rules only')\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            summary = {
                "status": "indisponivel",
                "calls": 1,
                "errorCode": "http_429",
            }
            env = {
                "AI_ENABLED": "true",
                "AI_BASE_URL": "https://provider.invalid/v1",
                "AI_API_KEY": "placeholder",
                "AI_MODEL": "small-model",
            }
            with patch.object(scan_file_script, "_load_root_env"), patch.object(
                scan_file_script,
                "OpenAICompatibleClient",
                lambda *_args, **_kwargs: FakeProvider(),
            ), patch.object(
                scan_file_script,
                "run_analysis",
                return_value={
                    "findings": [],
                    "aiFindings": [],
                    "aiSummary": summary,
                },
            ), patch.dict(
                os.environ, env, clear=True
            ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                stderr
            ):
                status = scan_file_main([str(path), "--ai"])

        self.assertEqual(status, 0)
        self.assertEqual(stderr.getvalue().strip(), "Aviso: IA indisponível (http_429); exibindo os achados das regras.")
        self.assertEqual(json.loads(stdout.getvalue())["ai"]["errorCode"], "http_429")


if __name__ == "__main__":
    unittest.main()
