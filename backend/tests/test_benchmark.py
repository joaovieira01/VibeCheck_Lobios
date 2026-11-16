import unittest

from scripts.benchmark import _labels_for_file, collect_benchmark


class BenchmarkLabelTests(unittest.TestCase):
    def test_ssrf_and_tls_labels_match_for_the_same_line(self):
        report = collect_benchmark()
        file_result = next(
            item for item in report["files"] if item["file"] == "bench_py_14.py"
        )
        findings = {
            (finding["line"], finding["category"])
            for finding in file_result["findings"]
        }

        self.assertEqual(findings, {(6, "A01"), (6, "A04")})
        self.assertFalse(
            any(
                finding["file"] == "bench_py_14.py"
                for finding in report["falsePositives"]
            )
        )
        self.assertFalse(
            any(
                finding["file"] == "bench_py_12.py"
                for finding in report["falseNegatives"] + report["falsePositives"]
            )
        )
        self.assertEqual(report["metrics"]["expectedVulnerabilities"], 29)
        self.assertEqual(report["metrics"]["matchedVulnerabilities"], 29)

    def test_invalid_multiple_label_format_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "categoria e linhas"):
            _labels_for_file(
                {
                    "labels": [
                        {"category": "A01", "lines": "6"},
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()
