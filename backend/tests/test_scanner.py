import json
import time
import unittest
from pathlib import Path

from app.scanner import RULE_COUNT, ScanTimeout, scan_source

GOLDEN = Path(__file__).parent / "golden"


def ids(result):
    return [f.id for f in result.findings]


class ScannerPortTests(unittest.TestCase):
    """Porte dos testes de src/services/scanner.test.ts."""

    def test_detects_python_patterns_and_lines(self):
        result = scan_source(
            "\n".join(
                [
                    'SECRET_KEY = "fixed-secret"',
                    "DEBUG = True",
                    "hashlib.md5(password.encode()).hexdigest()",
                    'query = f"SELECT * FROM users WHERE id = {user_id}"',
                    "result = eval(expression)",
                    'subprocess.check_output("ping " + host, shell=True)',
                    "pickle.loads(request.data)",
                    "yaml.load(request.data)",
                    "requests.get(url, verify=False)",
                    'open(BASE_DIR + filename, "rb")',
                ]
            ),
            "example.py",
        )
        self.assertEqual(
            set(ids(result)),
            {
                "sql-injection", "hardcoded-secret", "dynamic-eval", "command-injection",
                "pickle", "debug-mode", "unsafe-yaml", "tls-disabled", "path-traversal",
                "weak-password-hash",
            },
        )
        self.assertEqual(len(result.findings), 10)
        sql = next(f for f in result.findings if f.id == "sql-injection")
        self.assertEqual(sql.locations, [4])
        self.assertTrue(all(f.evidence for f in result.findings))
        self.assertTrue(all(f.owasp_id.startswith("A") for f in result.findings))

    def test_javascript_findings_and_aggregation(self):
        result = scan_source(
            "\n".join(
                [
                    'const password = "demo-password";',
                    'const apiKey = "demo-api-key";',
                    'const query = "SELECT * FROM users WHERE id = " + req.params.id;',
                    "jwt.verify(token, secret);",
                    'const project = "SELECT * FROM projects WHERE id = ?" + projectId;',
                    "exec(`convert ${req.body.file} output.png`);",
                    "const resetToken = Math.random().toString(36);",
                    'res.cookie("session", token, { httpOnly: true });',
                    "results.innerHTML = new URLSearchParams(location.search).get('q');",
                ]
            ),
            "server.js",
        )
        secrets = next(f for f in result.findings if f.id == "hardcoded-secret")
        self.assertEqual(secrets.locations, [1, 2])
        for expected in ("jwt-algorithm", "idor-project", "xss-innerhtml", "weak-random-token"):
            self.assertIn(expected, ids(result))

    def test_safe_controls_not_flagged(self):
        result = scan_source(
            "\n".join(
                [
                    'db_secret = os.environ["APP_DB_SECRET"]',
                    'db.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                    "yaml.safe_load(raw)",
                    'subprocess.run(["ping", host], capture_output=True, check=True)',
                    "jwt.verify(token, secret, { algorithms: ['HS256'] });",
                    "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });",
                ]
            ),
            "safe.js",
        )
        self.assertEqual(result.findings, [])

    def test_unlocked_package_manifest(self):
        result = scan_source(
            json.dumps({"dependencies": {"express": "*", "react": "^19.0.0"}}), "package.json"
        )
        finding = next(f for f in result.findings if f.id == "unlocked-dependency")
        self.assertEqual(finding.owasp_id, "A03")
        self.assertIn('"express": "*"', finding.evidence)
        self.assertGreater(RULE_COUNT, 15)

    def test_requirements_pins(self):
        result = scan_source("fastapi\nuvicorn>=0.30\n# comment", "requirements.txt")
        finding = next(f for f in result.findings if f.id == "unlocked-dependency")
        self.assertEqual(finding.locations, [1])


class ParityTests(unittest.TestCase):
    """Compara com a saída do scanner TypeScript original (tests/golden/expected.json).

    Regenere com scripts/generate_golden.mjs se as regras do frontend mudarem.
    """

    def test_matches_typescript_scanner(self):
        corpus = json.loads((GOLDEN / "corpus.json").read_text(encoding="utf-8"))
        expected = json.loads((GOLDEN / "expected.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(corpus), 15)
        for case in corpus:
            with self.subTest(case=case["name"]):
                result = scan_source(case["source"], case["filename"])
                got = {"findings": [f.to_dict() for f in result.findings], "rulesRun": result.rules_run}
                self.assertEqual(got, expected[case["name"]])


class AddedRuleTests(unittest.TestCase):
    def test_each_added_rule_has_a_positive_and_negative_golden_case(self):
        corpus = json.loads((GOLDEN / "corpus.json").read_text(encoding="utf-8"))
        cases = [case for case in corpus if "ruleCheck" in case]
        self.assertEqual(len(cases), 21)
        for case in cases:
            check = case["ruleCheck"]
            with self.subTest(case=case["name"]):
                result = scan_source(case["source"], case["filename"])
                finding = next(
                    (item for item in result.findings if item.id == check["ruleId"]),
                    None,
                )
                self.assertIsNotNone(finding, f"positive case for {check['ruleId']}")
                self.assertIn(check["positiveLine"], finding.locations)
                self.assertNotIn(check["negativeLine"], finding.locations)

    def test_password_hash_rule_does_not_misclassify_token_hash(self):
        source = 'return {"token": hashlib.md5(email.encode()).hexdigest()}'
        result = scan_source(source, "auth.py")
        self.assertIn("weak-token-hash", ids(result))
        self.assertNotIn("weak-password-hash", ids(result))

    def test_rules_include_confidence_and_all_owasp_2025_categories(self):
        rules = json.loads((Path(__file__).parents[1] / "app" / "rules.json").read_text(encoding="utf-8"))
        self.assertTrue(all(rule["confidence"] in {"alta", "média", "baixa"} for rule in rules))
        self.assertEqual({rule["owaspId"] for rule in rules}, {f"A{number:02}" for number in range(1, 11)})
        self.assertEqual(
            {rule["id"] for rule in rules if rule["confidence"] == "baixa"},
            {"mass-assignment", "missing-authentication", "csrf-get-mutable", "toctou", "user-enumeration"},
        )


class HardeningTests(unittest.TestCase):
    def test_long_lines_are_truncated_for_matching(self):
        line = "x" * 2000 + " DEBUG = True"
        self.assertEqual(scan_source(line, "a.py", max_line_chars=1000).findings, [])
        self.assertEqual(ids(scan_source(line, "a.py", max_line_chars=5000)), ["debug-mode"])

    def test_time_budget_aborts_hostile_input(self):
        hostile = ("FROM projects WHERE " * 50 + "\n") * 2000
        with self.assertRaises(ScanTimeout):
            scan_source(hostile, "x.js", time_budget_seconds=0.2)

    def test_evidence_is_capped_at_500_chars(self):
        result = scan_source("DEBUG = True  #" + "x" * 900, "a.py")
        self.assertEqual(len(result.findings[0].evidence[0]), 500)

    def test_all_rules_handle_1000_character_near_match_lines(self):
        line = "re.match(r'^(a+)+$'," + "a" * 975
        line = line[:1000].ljust(1000, "x")
        started = time.perf_counter()
        scan_source(line, "long.py", max_line_chars=1000, time_budget_seconds=1.0)
        self.assertLess(time.perf_counter() - started, 1.0)


if __name__ == "__main__":
    unittest.main()
