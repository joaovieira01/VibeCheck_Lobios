"""Testes offline para configuração e cliente genérico de IA."""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import contextmanager
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request

from app.ai.config import AIConfigurationError, AISettings
from app.ai.provider import AIProviderError, OpenAICompatibleClient


AI_ENV_VARS = (
    "AI_ENABLED",
    "AI_BASE_URL",
    "AI_API_KEY",
    "AI_MODEL",
    "AI_TIMEOUT_SECONDS",
    "AI_MAX_CALLS_PER_SCAN",
    "AI_CONCURRENCY",
    "AI_DISCOVERY",
)


@contextmanager
def isolated_ai_env(**values: str):
    with patch.dict(os.environ, {}, clear=False):
        for name in AI_ENV_VARS:
            os.environ.pop(name, None)
        os.environ.update(values)
        yield


class FakeResponse:
    def __init__(self, value: object):
        self.body = json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


class FakeOpener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout):
        self.requests.append(request)
        self.timeouts.append(timeout)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)


class AIProviderConfigurationTests(unittest.TestCase):
    def test_defaults_leave_ai_disabled(self):
        with isolated_ai_env():
            settings = AISettings.from_env()
        self.assertFalse(settings.enabled)
        self.assertFalse(settings.discovery)
        self.assertEqual(settings.timeout_seconds, 20)
        self.assertEqual(settings.max_calls_per_scan, 10)
        self.assertEqual(settings.concurrency, 2)

    def test_enabled_configuration_uses_environment_and_defaults(self):
        with isolated_ai_env(
            AI_ENABLED="true",
            AI_BASE_URL="http://localhost:11434/v1",
            AI_API_KEY="placeholder",
            AI_MODEL="small-model",
        ):
            settings = AISettings.from_env()
        self.assertTrue(settings.enabled)
        self.assertEqual(settings.timeout_seconds, 20)
        self.assertEqual(settings.max_calls_per_scan, 10)
        self.assertEqual(settings.concurrency, 2)
        self.assertFalse(settings.discovery)
        self.assertNotIn("placeholder", repr(settings))

    def test_base_url_requires_https_except_exact_local_development_hosts(self):
        for value in (
            "http://localhost:11434/v1",
            "http://127.0.0.1:11434/v1",
            "https://provider.invalid/v1",
        ):
            with self.subTest(value=value):
                settings = AISettings(
                    enabled=True,
                    base_url=value,
                    api_key="placeholder",
                    model="small-model",
                )
                self.assertEqual(settings.base_url, value)
        for value in (
            "http://provider.invalid/v1",
            "http://localhost.example/v1",
            "http://[::1]:11434/v1",
            "https://user:pass@provider.invalid/v1",
            "https://provider.invalid/v1?redirect=elsewhere",
            "https://[malformed",
            "https://provider.invalid:99999/v1",
        ):
            with self.subTest(value=value):
                with self.assertRaises(AIConfigurationError):
                    from app.ai.config import validate_base_url

                    validate_base_url(value)

    def test_enabled_configuration_requires_url_key_and_model(self):
        with isolated_ai_env(AI_ENABLED="true"):
            with self.assertRaises(AIConfigurationError) as raised:
                AISettings.from_env()
        self.assertNotIn("placeholder", str(raised.exception))

    def test_invalid_boolean_and_limits_are_rejected(self):
        with isolated_ai_env(AI_ENABLED="sometimes"):
            with self.assertRaises(AIConfigurationError):
                AISettings.from_env()
        with isolated_ai_env(
            AI_ENABLED="true",
            AI_BASE_URL="http://localhost/v1",
            AI_API_KEY="placeholder",
            AI_MODEL="small-model",
            AI_MAX_CALLS_PER_SCAN="0",
        ):
            with self.assertRaises(AIConfigurationError):
                AISettings.from_env()
        with isolated_ai_env(
            AI_ENABLED="true",
            AI_BASE_URL="http://provider.invalid/v1",
            AI_API_KEY="placeholder",
            AI_MODEL="small-model",
        ):
            with self.assertRaises(AIConfigurationError):
                AISettings.from_env()


class OpenAICompatibleClientTests(unittest.TestCase):
    def test_posts_openai_compatible_chat_request_with_bounded_timeout(self):
        opener = FakeOpener(
            [{"choices": [{"message": {"content": '{"ok":true}'}}]}]
        )
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "placeholder",
            timeout_seconds=7,
            opener=opener,
        )
        response = client.complete(
            model="small-model",
            messages=[{"role": "user", "content": "check"}],
            max_tokens=120,
        )
        request = opener.requests[0]
        payload = json.loads(request.data)
        self.assertEqual(response, '{"ok":true}')
        self.assertEqual(request.full_url, "https://provider.invalid/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer placeholder")
        self.assertEqual(opener.timeouts, [7])
        self.assertEqual(payload["temperature"], 0)
        self.assertEqual(payload["max_tokens"], 120)
        self.assertEqual(payload["response_format"], {"type": "json_object"})

    def test_retries_rate_limit_then_returns_content(self):
        opener = FakeOpener(
            [
                HTTPError("https://provider.invalid", 429, "limited", {}, io.BytesIO(b"secret")),
                {"choices": [{"message": {"content": "{}"}}]},
            ]
        )
        delays = []
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "placeholder",
            opener=opener,
            sleep=delays.append,
        )
        content = client.complete(
            model="small-model", messages=[], max_tokens=20
        )
        self.assertEqual(content, "{}")
        self.assertEqual(client.request_count, 2)
        self.assertEqual(delays, [0.25])

    def test_http_errors_do_not_expose_provider_body_or_credentials(self):
        secret = "sensitive-placeholder"
        opener = FakeOpener(
            [
                HTTPError(
                    "https://provider.invalid",
                    401,
                    secret,
                    {},
                    io.BytesIO(secret.encode()),
                )
            ]
        )
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            secret,
            opener=opener,
            sleep=lambda _delay: None,
        )
        with self.assertRaises(AIProviderError) as raised:
            client.complete(model="small-model", messages=[], max_tokens=20)
        self.assertEqual(str(raised.exception), "http_401")
        self.assertNotIn(secret, str(raised.exception))

    def test_invalid_response_is_sanitized(self):
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "placeholder",
            opener=FakeOpener([{"unexpected": "shape"}]),
        )
        with self.assertRaises(AIProviderError) as raised:
            client.complete(model="small-model", messages=[], max_tokens=20)
        self.assertEqual(str(raised.exception), "invalid_response")

    def test_response_body_is_limited(self):
        class OversizedResponse(FakeResponse):
            def read(self, size=-1):
                return b"x" * (size + 1)

        class OversizedOpener:
            def open(self, _request, timeout):
                return OversizedResponse({})

        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "placeholder",
            opener=OversizedOpener(),
        )
        with self.assertRaises(AIProviderError) as raised:
            client.complete(model="small-model", messages=[], max_tokens=20)
        self.assertEqual(str(raised.exception), "response_too_large")

    def test_default_opener_refuses_redirects(self):
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "secret-placeholder",
        )
        redirect_handler = next(
            handler
            for handler in client._opener.handlers
            if isinstance(handler, HTTPRedirectHandler)
        )
        self.assertIsNone(
            redirect_handler.redirect_request(
                request=Request(
                    "https://provider.invalid/v1/chat/completions",
                    headers={"Authorization": "Bearer secret-placeholder"},
                ),
                response=object(),
                code=302,
                message="redirect",
                headers={},
                new_url="https://other.invalid",
            )
        )

    def test_client_repr_does_not_expose_api_key(self):
        key = "do-not-print-this-key"
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            key,
            opener=FakeOpener([]),
        )
        self.assertNotIn(key, repr(client))

    def test_rejects_non_http_or_credential_embedded_base_urls(self):
        for value in ("file:///tmp/provider", "https://user:pass@example.invalid/v1"):
            with self.subTest(value=value):
                with self.assertRaises(AIProviderError):
                    OpenAICompatibleClient(value, "placeholder")


if __name__ == "__main__":
    unittest.main()
