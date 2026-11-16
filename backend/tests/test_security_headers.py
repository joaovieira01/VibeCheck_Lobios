"""Cabeçalhos de segurança HTTP da API."""

import os
import tempfile
import unittest

from tests.test_api import HAVE_FASTAPI, ApiTestBase

if HAVE_FASTAPI:
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app


class SecurityHeadersTests(ApiTestBase):
    def test_api_responses_carry_hardening_headers(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertNotIn("Strict-Transport-Security", response.headers)

    def test_error_responses_carry_headers_too(self):
        response = self.client.get("/api/auth/me")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_body_limit_rejection_carries_headers(self):
        response = self.client.post(
            "/api/auth/login", content=b"x", headers={"Content-Length": "999999999"}
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    @unittest.skipUnless(HAVE_FASTAPI, "fastapi/httpx não instalados")
    def test_hsts_only_in_production(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = Settings(
                db_path=os.path.join(tmp, "prod.db"),
                environment="production",
                rate_limit_enabled=False,
                seed_demo_user=False,
                cors_origins=["https://app.example.com"],
            )
            with TestClient(create_app(settings)) as client:
                response = client.get("/api/health")
        self.assertIn("max-age=", response.headers["Strict-Transport-Security"])


if __name__ == "__main__":
    unittest.main()
