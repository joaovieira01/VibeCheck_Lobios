import json
import unittest
from pathlib import Path

from app.scanner import scan_source

SAMPLES = Path(__file__).parent / "samples"


class SampleControlRecallTests(unittest.TestCase):
    def test_control_recall_is_100_percent(self):
        answer_key = json.loads((SAMPLES / "gabarito_amostra.json").read_text(encoding="utf-8"))
        sample = (SAMPLES / "amostra_vulneravel.py").read_text(encoding="utf-8")
        findings = scan_source(sample, "amostra_vulneravel.py").findings
        control_items = [item for item in answer_key["itens"] if item["kind"] == "control"]

        recalled = [
            item
            for item in control_items
            if any(
                finding.id == item["expectedRuleId"]
                and set(item["lines"]).intersection(finding.locations)
                for finding in findings
            )
        ]
        self.assertEqual(len(recalled), len(control_items), "Recall dos itens control deve ser 100%")

    def test_safe_sample_has_no_findings(self):
        sample = (SAMPLES / "amostra_segura.py").read_text(encoding="utf-8")
        self.assertEqual(scan_source(sample, "amostra_segura.py").findings, [])

    def test_additional_expected_server_rule_is_detected(self):
        answer_key = json.loads((SAMPLES / "gabarito_amostra.json").read_text(encoding="utf-8"))
        sample = (SAMPLES / "amostra_vulneravel.py").read_text(encoding="utf-8")
        findings = scan_source(sample, "amostra_vulneravel.py").findings
        expected = answer_key["expectedFindings"][0]
        self.assertTrue(
            any(
                finding.id == expected["expectedRuleId"]
                and set(finding.locations).intersection(expected["lines"])
                for finding in findings
            )
        )
