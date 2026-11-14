"""Cliente mínimo para endpoints OpenAI-compatible de chat completions."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .config import AIConfigurationError, validate_base_url

MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024
AI_ERROR_CODES = frozenset(
    {
        "invalid_base_url",
        "network_error",
        "http_401",
        "http_403",
        "http_429",
        "http_5xx",
        "invalid_response",
        "response_too_large",
        "timeout_total",
        "calls_exhausted",
        "configuracao_invalida",
    }
)


def normalize_ai_error_code(value: str) -> str:
    if value in AI_ERROR_CODES:
        return value
    if value.startswith("http_"):
        try:
            if 500 <= int(value.removeprefix("http_")) <= 599:
                return "http_5xx"
        except ValueError:
            pass
    return "network_error"


class AIProviderError(RuntimeError):
    """Falha sanitizada do provedor; nunca contém corpo, URL ou credencial."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


class OpenAICompatibleClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 20,
        *,
        opener: Any | None = None,
        sleep: Any = time.sleep,
    ) -> None:
        try:
            normalized_url = validate_base_url(base_url)
        except AIConfigurationError:
            raise AIProviderError("invalid_base_url") from None
        self._endpoint = normalized_url
        if not self._endpoint.endswith("/chat/completions"):
            self._endpoint += "/chat/completions"
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds
        self._opener = opener or build_opener(_NoRedirect())
        self._sleep = sleep
        self.request_count = 0

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float = 0,
        timeout_seconds: float | None = None,
        reasoning_effort: str | None = None,
    ) -> str:
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }
        if reasoning_effort is not None:
            payload["reasoning_effort"] = reasoning_effort
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = Request(
            self._endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        deadline = (
            time.monotonic() + timeout_seconds
            if timeout_seconds is not None
            else None
        )
        for attempt in range(3):
            remaining = (
                deadline - time.monotonic() if deadline is not None else None
            )
            if remaining is not None and remaining <= 0:
                raise AIProviderError("timeout_total")
            request_timeout = self._timeout_seconds
            if remaining is not None:
                request_timeout = min(request_timeout, remaining)
            self.request_count += 1
            try:
                with self._opener.open(request, timeout=request_timeout) as response:
                    raw_response = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
                if len(raw_response) > MAX_PROVIDER_RESPONSE_BYTES:
                    raise AIProviderError("response_too_large")
                payload = json.loads(raw_response.decode("utf-8"))
                content = payload["choices"][0]["message"]["content"]
                if not isinstance(content, str):
                    raise AIProviderError("invalid_response")
                return content
            except HTTPError as exc:
                if exc.code == 429 or 500 <= exc.code <= 599:
                    if attempt < 2:
                        delay = 0.25 * (2**attempt)
                        if deadline is not None:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise AIProviderError("timeout_total") from None
                            delay = min(delay, remaining)
                        self._sleep(delay)
                        if deadline is not None and time.monotonic() >= deadline:
                            raise AIProviderError("timeout_total") from None
                        continue
                raise AIProviderError(f"http_{exc.code}") from None
            except (TimeoutError, OSError, URLError):
                raise AIProviderError("network_error") from None
            except (
                KeyError,
                IndexError,
                TypeError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ):
                raise AIProviderError("invalid_response") from None
        raise AIProviderError("retry_exhausted")
