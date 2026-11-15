"""Testes da camada HTTP. Exigem fastapi + httpx (pip install -r requirements-dev.txt)."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient

    from app.config import Settings, get_settings
    from app.main import create_app
    from app.main import app as exported_app

    HAVE_FASTAPI = True
except ImportError:  # pragma: no cover
    HAVE_FASTAPI = False

PASSWORD = "senha-forte-123"


class FakeMailer:
    def __init__(self):
        self.sent = []

    def send_password_reset(self, to_email, reset_url):
        self.sent.append((to_email, reset_url))


@unittest.skipUnless(HAVE_FASTAPI, "fastapi/httpx não instalados")
class ApiTestBase(unittest.TestCase):
    rate_limit = False

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.mailer = FakeMailer()
        settings = Settings(
            db_path=os.path.join(tmp.name, "api.db"),
            rate_limit_enabled=self.rate_limit,
            cors_origins=["http://localhost:5173"],
            frontend_url="http://localhost:5173",
        )
        self.client = TestClient(create_app(settings, mailer=self.mailer))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def register(self, email="ana@example.com", password=PASSWORD):
        response = self.client.post("/api/auth/register", json={"email": email, "password": password})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    @staticmethod
    def bearer(token):
        return {"Authorization": f"Bearer {token}"}


@unittest.skipUnless(HAVE_FASTAPI, "fastapi/httpx não instalados")
class ApiTests(ApiTestBase):
    def test_health_and_rules(self):
        self.assertEqual(self.client.get("/api/health").json(), {"status": "ok", "rules": 41})
        rules = self.client.get("/api/rules").json()
        self.assertEqual(len(rules), 41)
        self.assertEqual(
            set(rules[0]),
            {
                "id", "title", "severity", "cwe", "owaspId", "owaspName",
                "description", "recommendation", "impact", "prevention", "confidence",
            },
        )

    def test_health_returns_degraded_without_database_details(self):
        with patch.object(
            self.client.app.state.database,
            "connect",
            side_effect=RuntimeError("database password must not be exposed"),
        ):
            response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json(),
            {"status": "degraded", "rules": 41},
        )
        self.assertNotIn("database password", response.text)

    def test_import_with_unavailable_mysql_does_not_connect(self):
        env = os.environ.copy()
        env.update(
            {
                "VIBECHECK_ENV": "development",
                "VIBECHECK_DB_ENGINE": "mysql",
                "VIBECHECK_DB_HOST": "vibecheck-host-that-does-not-exist.invalid",
                "VIBECHECK_DB_PORT": "1",
                "VIBECHECK_DB_NAME": "vibecheck",
                "VIBECHECK_DB_USER": "vibecheck_test",
                "VIBECHECK_DB_PASSWORD": "test-only-password",
                "VIBECHECK_SEED_DEMO_USER": "false",
            }
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import app.main; assert app.main.app is not None",
            ],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNotNone(exported_app)

    def test_full_flow(self):
        auth = self.register()
        headers = self.bearer(auth["token"])
        self.assertEqual(self.client.get("/api/auth/me", headers=headers).json()["email"], "ana@example.com")

        created = self.client.post(
            "/api/analyses", headers=headers, json={"filename": "app.py", "source": "DEBUG = True\nx = eval(y)"}
        )
        self.assertEqual(created.status_code, 201, created.text)
        body = created.json()
        self.assertEqual(
            set(body),
            {"id", "filename", "language", "linesAnalyzed", "createdAt", "durationMs", "findings", "rulesRun"},
        )
        self.assertEqual({f["id"] for f in body["findings"]}, {"debug-mode", "dynamic-eval"})
        self.assertIn("owaspId", body["findings"][0])

        listed = self.client.get("/api/analyses", headers=headers).json()
        self.assertEqual([a["id"] for a in listed], [body["id"]])
        self.assertEqual(self.client.get(f"/api/analyses/{body['id']}", headers=headers).json()["id"], body["id"])

        self.assertEqual(self.client.delete("/api/analyses", headers=headers).status_code, 204)
        self.assertEqual(self.client.get("/api/analyses", headers=headers).json(), [])

    def test_ai_disabled_preserves_analysis_and_history_response_shape(self):
        auth = self.register()
        headers = self.bearer(auth["token"])
        with patch.dict(os.environ, {"AI_ENABLED": "false"}):
            created = self.client.post(
                "/api/analyses",
                headers=headers,
                json={"filename": "app.py", "source": "DEBUG = True"},
            )
            self.assertEqual(created.status_code, 201, created.text)
            body = created.json()
            self.assertEqual(
                set(body),
                {
                    "id", "filename", "language", "linesAnalyzed", "createdAt",
                    "durationMs", "findings", "rulesRun",
                },
            )
            self.assertEqual(
                self.client.get("/api/analyses", headers=headers).json(),
                [body],
            )
            self.assertEqual(
                self.client.get(
                    f"/api/analyses/{body['id']}", headers=headers
                ).json(),
                body,
            )

    def test_requires_authentication(self):
        for method, url in [("get", "/api/analyses"), ("get", "/api/auth/me"), ("delete", "/api/analyses")]:
            response = getattr(self.client, method)(url)
            self.assertEqual(response.status_code, 401, url)
            self.assertIn("detail", response.json())
        response = self.client.get("/api/analyses", headers=self.bearer("token-invalido"))
        self.assertEqual(response.status_code, 401)

    def test_users_cannot_see_each_others_history(self):
        a = self.register("a@example.com")
        b = self.register("b@example.com")
        created = self.client.post(
            "/api/analyses", headers=self.bearer(a["token"]), json={"filename": "a.py", "source": "DEBUG = True"}
        ).json()
        self.assertEqual(self.client.get("/api/analyses", headers=self.bearer(b["token"])).json(), [])
        response = self.client.get(f"/api/analyses/{created['id']}", headers=self.bearer(b["token"]))
        self.assertEqual(response.status_code, 404)

    def test_login_logout(self):
        self.register()
        bad = self.client.post("/api/auth/login", json={"email": "ana@example.com", "password": "errada-errada"})
        self.assertEqual(bad.status_code, 401)
        good = self.client.post("/api/auth/login", json={"email": "ANA@example.com", "password": PASSWORD})
        self.assertEqual(good.status_code, 200)
        token = good.json()["token"]
        self.assertEqual(self.client.post("/api/auth/logout", headers=self.bearer(token)).status_code, 204)
        self.assertEqual(self.client.get("/api/auth/me", headers=self.bearer(token)).status_code, 401)

    def test_duplicate_register_is_409(self):
        self.register()
        response = self.client.post("/api/auth/register", json={"email": "ana@example.com", "password": PASSWORD})
        self.assertEqual(response.status_code, 409)

    def test_analysis_validation_errors_are_plain_text_details(self):
        headers = self.bearer(self.register()["token"])
        empty = self.client.post("/api/analyses", headers=headers, json={"filename": "a.py", "source": "  "})
        self.assertEqual(empty.status_code, 422)
        self.assertIsInstance(empty.json()["detail"], str)
        malformed = self.client.post("/api/analyses", headers=headers, json={"filename": "a.py"})
        self.assertEqual(malformed.status_code, 422)
        self.assertIsInstance(malformed.json()["detail"], str)
        too_big = self.client.post(
            "/api/analyses", headers=headers, json={"filename": "a.py", "source": "x" * 1_000_001}
        )
        self.assertEqual(too_big.status_code, 413)

    def test_password_reset_flow(self):
        auth = self.register()
        # mesma resposta para e-mail existente e inexistente
        known = self.client.post("/api/auth/password-reset", json={"email": "ana@example.com"})
        unknown = self.client.post("/api/auth/password-reset", json={"email": "ninguem@example.com"})
        self.assertEqual(known.status_code, 202)
        self.assertEqual(known.json(), unknown.json())
        self.assertEqual(len(self.mailer.sent), 1)

        email, url = self.mailer.sent[0]
        self.assertEqual(email, "ana@example.com")
        self.assertIn("#reset_token=", url)
        token = url.split("#reset_token=")[1]

        weak = self.client.post("/api/auth/password-reset/confirm", json={"token": token, "newPassword": "curta"})
        self.assertEqual(weak.status_code, 422)
        done = self.client.post(
            "/api/auth/password-reset/confirm", json={"token": token, "newPassword": "senha-nova-456"}
        )
        self.assertEqual(done.status_code, 204)
        self.assertEqual(self.client.get("/api/auth/me", headers=self.bearer(auth["token"])).status_code, 401)
        login = self.client.post("/api/auth/login", json={"email": "ana@example.com", "password": "senha-nova-456"})
        self.assertEqual(login.status_code, 200)
        again = self.client.post(
            "/api/auth/password-reset/confirm", json={"token": token, "newPassword": "senha-nova-789"}
        )
        self.assertEqual(again.status_code, 400)

    def test_cors_preflight_and_error_headers(self):
        origin = {"Origin": "http://localhost:5173"}
        preflight = self.client.options(
            "/api/analyses",
            headers={**origin, "Access-Control-Request-Method": "POST",
                     "Access-Control-Request-Headers": "authorization,content-type"},
        )
        self.assertEqual(preflight.status_code, 200)
        self.assertEqual(preflight.headers["access-control-allow-origin"], "http://localhost:5173")
        # mesmo respostas de erro levam CORS (o navegador precisa ler a mensagem)
        error = self.client.get("/api/analyses", headers=origin)
        self.assertEqual(error.status_code, 401)
        self.assertEqual(error.headers["access-control-allow-origin"], "http://localhost:5173")
        blocked = self.client.get("/api/health", headers={"Origin": "http://evil.example"})
        self.assertNotIn("access-control-allow-origin", blocked.headers)

    def test_oversized_body_rejected_before_parsing(self):
        response = self.client.post(
            "/api/analyses", content=b"x" * 7_000_000, headers={"Content-Type": "application/json"}
        )
        self.assertEqual(response.status_code, 413)


@unittest.skipUnless(HAVE_FASTAPI, "fastapi/httpx não instalados")
class RateLimitApiTests(ApiTestBase):
    rate_limit = True

    def test_login_is_rate_limited(self):
        self.register()
        statuses = [
            self.client.post("/api/auth/login", json={"email": "ana@example.com", "password": "errada-errada"}).status_code
            for _ in range(7)
        ]
        self.assertEqual(statuses[:5], [401] * 5)
        self.assertEqual(statuses[5:], [429, 429])

    def test_login_limit_also_caps_distinct_emails_per_ip(self):
        from unittest.mock import patch

        with patch("app.auth.burn_password_check"):
            statuses = [
                self.client.post(
                    "/api/auth/login",
                    json={
                        "email": f"user-{index}@example.com",
                        "password": "senha-incorreta",
                    },
                ).status_code
                for index in range(21)
            ]

        self.assertEqual(statuses[:20], [401] * 20)
        self.assertEqual(statuses[20], 429)


@unittest.skipUnless(HAVE_FASTAPI, "fastapi/httpx não instalados")
class ProductionStartupTests(unittest.TestCase):
    def test_environment_defaults_to_development_and_normalizes(self):
        with patch.dict(os.environ, {"VIBECHECK_ENV": ""}):
            self.assertEqual(get_settings().environment, "development")
        with patch.dict(os.environ, {"VIBECHECK_ENV": "PRODUCTION"}):
            self.assertEqual(get_settings().environment, "production")

    def test_production_rejects_insecure_settings_before_startup(self):
        invalid_settings = (
            ({"seed_demo_user": True}, "VIBECHECK_SEED_DEMO_USER"),
            ({"cors_origins": ["https://*.example.com"]}, "VIBECHECK_CORS_ORIGINS"),
            (
                {"db_engine": "mysql", "db_password": "CHANGE_THIS_PASSWORD"},
                "senha de exemplo",
            ),
            ({"db_engine": "mysql", "db_password": ""}, "senha de exemplo"),
        )

        for overrides, expected_message in invalid_settings:
            with self.subTest(setting=expected_message):
                with tempfile.TemporaryDirectory() as directory:
                    values = {
                        "environment": "production",
                        "db_path": os.path.join(directory, "production.db"),
                        "db_engine": "sqlite",
                        "db_password": "safe-test-password",
                        "cors_origins": ["https://app.example.com"],
                        "seed_demo_user": False,
                    }
                    values.update(overrides)
                    settings = Settings(**values)
                    with patch(
                        "app.main.Database",
                        side_effect=AssertionError(
                            "o banco não deve ser aberto antes da validação"
                        ),
                    ):
                        with self.assertRaisesRegex(RuntimeError, expected_message):
                            with TestClient(create_app(settings, mailer=FakeMailer())):
                                pass

    def test_production_starts_with_explicitly_safe_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                environment="production",
                db_path=os.path.join(directory, "production.db"),
                db_engine="sqlite",
                db_password="safe-test-password",
                cors_origins=["https://app.example.com"],
                seed_demo_user=False,
            )
            with TestClient(create_app(settings, mailer=FakeMailer())) as client:
                self.assertEqual(client.get("/api/health").status_code, 200)

    def test_production_sqlite_does_not_require_database_password(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                environment="production",
                db_path=os.path.join(directory, "production.db"),
                db_engine="sqlite",
                db_password="",
                cors_origins=["https://app.example.com"],
                seed_demo_user=False,
            )
            with TestClient(create_app(settings, mailer=FakeMailer())) as client:
                self.assertEqual(client.get("/api/health").status_code, 200)

    def test_request_without_lifespan_initializes_application_state(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                db_path=os.path.join(directory, "serverless.db"),
                db_engine="sqlite",
                db_password="",
                seed_demo_user=False,
            )
            app = create_app(settings, mailer=FakeMailer())
            client = TestClient(app)
            try:
                response = client.get("/api/health")
                database = app.state.database
                second_response = client.get("/api/health")
            finally:
                client.close()

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["status"], "ok")
            self.assertEqual(second_response.status_code, 200)
            self.assertIs(app.state.database, database)

    def test_demo_user_is_seeded_when_application_starts_in_development(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                db_path=os.path.join(directory, "development.db"),
                seed_demo_user=True,
                rate_limit_enabled=False,
            )
            with TestClient(create_app(settings, mailer=FakeMailer())) as client:
                response = client.post(
                    "/api/auth/login",
                    json={
                        "email": "demo@vibecheck.dev",
                        "password": "vibecheck2026",
                    },
                )
            self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
