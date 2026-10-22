"""Testes da camada HTTP. Exigem fastapi + httpx (pip install -r requirements-dev.txt)."""

import os
import tempfile
import unittest

try:
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app

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
        self.assertEqual(self.client.get("/api/health").json(), {"status": "ok", "rules": 20})
        self.assertEqual(len(self.client.get("/api/rules").json()), 19)

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
            for _ in range(12)
        ]
        self.assertEqual(statuses[:10], [401] * 10)
        self.assertEqual(statuses[10:], [429, 429])


if __name__ == "__main__":
    unittest.main()
