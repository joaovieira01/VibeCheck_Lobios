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
from app.ai.provider import (
    AIProviderError,
    OpenAICompatibleClient,
    normalize_ai_error_code,
)


AI_ENV_VARS = (
    "AI_ENABLED",
    "AI_BASE_URL",
    "AI_API_KEY",
    "AI_MODEL",
    "AI_TIMEOUT_SECONDS",
    "AI_MAX_CALLS_PER_SCAN",
    "AI_CONCURRENCY",
    "AI_DISCOVERY",
    "AI_MAX_COMPLETION_TOKENS",
    "AI_REASONING_EFFORT",
    "AI_TOTAL_TIMEOUT_SECONDS",
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
        self.assertIsNone(settings.max_completion_tokens)
        self.assertIsNone(settings.reasoning_effort)
        self.assertEqual(settings.total_timeout_seconds, 60)
        self.assertNotIn("placeholder", repr(settings))

    def test_new_ai_options_are_validated(self):
        with isolated_ai_env(
            AI_ENABLED="true",
            AI_BASE_URL="https://provider.invalid/v1",
            AI_API_KEY="placeholder",
            AI_MODEL="small-model",
            AI_MAX_COMPLETION_TOKENS="8192",
            AI_REASONING_EFFORT="high",
            AI_TOTAL_TIMEOUT_SECONDS="12",
        ):
            settings = AISettings.from_env()
        self.assertEqual(settings.max_completion_tokens, 8192)
        self.assertEqual(settings.reasoning_effort, "high")
        self.assertEqual(settings.total_timeout_seconds, 12)

        for name, value in (
            ("AI_MAX_COMPLETION_TOKENS", "0"),
            ("AI_MAX_COMPLETION_TOKENS", "8193"),
            ("AI_MAX_COMPLETION_TOKENS", "not-an-integer"),
            ("AI_REASONING_EFFORT", "secret-value"),
            ("AI_TOTAL_TIMEOUT_SECONDS", "inf"),
        ):
            with self.subTest(name=name, value=value):
                with isolated_ai_env(
                    AI_ENABLED="true",
                    AI_BASE_URL="https://provider.invalid/v1",
                    AI_API_KEY="placeholder",
                    AI_MODEL="small-model",
                    **{name: value},
                ):
                    with self.assertRaises(AIConfigurationError):
                        AISettings.from_env()

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
        self.assertEqual(
            payload,
            {
                "model": "small-model",
                "messages": [{"role": "user", "content": "check"}],
                "temperature": 0,
                "max_tokens": 120,
                "response_format": {"type": "json_object"},
            },
        )

    def test_legacy_triage_and_discovery_payloads_are_exact_without_new_options(self):
        messages = [{"role": "user", "content": "check"}]
        for legacy_limit in (700, 600):
            with self.subTest(max_tokens=legacy_limit):
                opener = FakeOpener(
                    [{"choices": [{"message": {"content": "{}"}}]}]
                )
                client = OpenAICompatibleClient(
                    "https://provider.invalid/v1",
                    "placeholder",
                    opener=opener,
                )
                client.complete(
                    model="small-model",
                    messages=messages,
                    max_tokens=legacy_limit,
                )
                self.assertEqual(
                    json.loads(opener.requests[0].data),
                    {
                        "model": "small-model",
                        "messages": messages,
                        "temperature": 0,
                        "max_tokens": legacy_limit,
                        "response_format": {"type": "json_object"},
                    },
                )

    def test_reasoning_effort_is_sent_only_when_set_and_timeout_is_bounded(self):
        opener = FakeOpener(
            [{"choices": [{"message": {"content": "{}"}}]}]
        )
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "placeholder",
            timeout_seconds=7,
            opener=opener,
        )
        client.complete(
            model="small-model",
            messages=[],
            max_tokens=80,
            reasoning_effort="minimal",
            timeout_seconds=3,
        )
        self.assertLessEqual(opener.timeouts[0], 3)
        self.assertGreater(opener.timeouts[0], 2.9)
        self.assertEqual(
            json.loads(opener.requests[0].data),
            {
                "model": "small-model",
                "messages": [],
                "temperature": 0,
                "max_tokens": 80,
                "response_format": {"type": "json_object"},
                "reasoning_effort": "minimal",
            },
        )

        slower_deadline_opener = FakeOpener(
            [{"choices": [{"message": {"content": "{}"}}]}]
        )
        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "placeholder",
            timeout_seconds=7,
            opener=slower_deadline_opener,
        )
        client.complete(
            model="small-model",
            messages=[],
            max_tokens=80,
            timeout_seconds=30,
        )
        self.assertEqual(slower_deadline_opener.timeouts, [7])

    def test_error_codes_are_normalized_to_the_fixed_set(self):
        self.assertEqual(normalize_ai_error_code("http_401"), "http_401")
        self.assertEqual(normalize_ai_error_code("http_403"), "http_403")
        self.assertEqual(normalize_ai_error_code("http_429"), "http_429")
        self.assertEqual(normalize_ai_error_code("http_503"), "http_5xx")
        self.assertEqual(normalize_ai_error_code("http_404"), "network_error")
        self.assertEqual(normalize_ai_error_code("untrusted text"), "network_error")

    def test_retry_wait_and_retries_stop_at_the_remaining_deadline(self):
        opener = FakeOpener(
            [
                HTTPError(
                    "https://provider.invalid",
                    429,
                    "limited",
                    {},
                    io.BytesIO(b""),
                )
            ]
        )
        current_time = [0.0]
        delays = []

        def sleep(delay):
            delays.append(delay)
            current_time[0] += delay

        client = OpenAICompatibleClient(
            "https://provider.invalid/v1",
            "placeholder",
            opener=opener,
            sleep=sleep,
        )
        with patch(
            "app.ai.provider.time.monotonic",
            side_effect=lambda: current_time[0],
        ):
            with self.assertRaises(AIProviderError) as raised:
                client.complete(
                    model="small-model",
                    messages=[],
                    max_tokens=20,
                    timeout_seconds=0.1,
                )
        self.assertEqual(str(raised.exception), "timeout_total")
        self.assertEqual(delays, [0.1])
        self.assertEqual(len(opener.requests), 1)

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
