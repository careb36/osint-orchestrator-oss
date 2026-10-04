"""
OpenAI-compatible LLM provider (optional extra).

Works with the official OpenAI API, Azure OpenAI, or any local server that
speaks the OpenAI chat-completions protocol (e.g. LM Studio, vLLM).

Install: pip install openai
Config:  OPENAI_API_KEY, optionally OPENAI_BASE_URL for compatible endpoints.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Literal

from orchestrator import metrics
from orchestrator.config import settings
from orchestrator.synthesizer.model_routing import resolve_model_for_route

logger = logging.getLogger(__name__)

try:
    import openai as _openai_sdk

    _HAS_OPENAI = True
except ImportError:
    _openai_sdk = None
    _HAS_OPENAI = False


_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_JITTER_RATIO = 0.25


def _usage_tokens(response: Any) -> tuple[int, int]:
    usage = getattr(response, "usage", None)
    in_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
    out_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
    return in_tokens, out_tokens


def _error_status_label(exc: Exception) -> str:
    status_code = getattr(exc, "status_code", None)
    if status_code == 429:
        return "http_429"
    if isinstance(status_code, int) and status_code >= 500:
        return "http_5xx"
    timeout_types = tuple(
        cls
        for cls in (
            getattr(_openai_sdk, "APITimeoutError", None),
            TimeoutError,
            asyncio.TimeoutError,
        )
        if cls is not None
    )
    if timeout_types and isinstance(exc, timeout_types):
        return "timeout"
    return "error"


def _is_retryable(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None)
    if status_code in _RETRYABLE_STATUS_CODES:
        return True
    retryable_types = tuple(
        cls
        for cls in (
            getattr(_openai_sdk, "RateLimitError", None),
            getattr(_openai_sdk, "APITimeoutError", None),
            getattr(_openai_sdk, "APIConnectionError", None),
            TimeoutError,
            asyncio.TimeoutError,
        )
        if cls is not None
    )
    return bool(retryable_types and isinstance(exc, retryable_types))


def _supports_json_schema_response(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None)
    if status_code != 400:
        return True
    message = str(exc).lower()
    has_response_format = "response_format" in message
    has_json_schema = "json_schema" in message or "json schema" in message
    return not (has_response_format and has_json_schema)


def _backoff_seconds(attempt_index: int) -> float:
    delay = min(_BACKOFF_BASE_SECONDS * (2**attempt_index), 30.0)
    jitter = delay * _BACKOFF_JITTER_RATIO
    return max(0.0, random.uniform(delay - jitter, delay + jitter))


class OpenAICompatClient:
    """Calls any OpenAI-compatible /v1/chat/completions endpoint."""

    def __init__(
        self,
        *,
        provider_name: str = "openai",
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self._provider_name = provider_name
        self._api_key = api_key if api_key is not None else settings.openai_api_key
        self._base_url = base_url if base_url is not None else (settings.openai_base_url or None)

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: Literal["reasoning", "fast"] = "reasoning",
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        """One /v1/chat/completions call (temperature 0); returns the raw text."""
        if not _HAS_OPENAI:
            raise RuntimeError("openai package is not installed; run: pip install openai")

        model = resolve_model_for_route(model_route)
        client = _openai_sdk.AsyncOpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=timeout,
            max_retries=0,
        )

        payload: dict[str, Any] = {
            "model": model,
            "temperature": 0,
            "max_tokens": settings.llm_max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if response_schema:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "finding",
                    "schema": response_schema,
                },
            }

        schema_downgraded = False
        for attempt in range(_MAX_ATTEMPTS):
            started = time.monotonic()
            try:
                response = await client.chat.completions.create(**payload)
                duration_ms = int((time.monotonic() - started) * 1000)
                in_tokens, out_tokens = _usage_tokens(response)
                logger.info(
                    "LLM request completed: provider=%s model=%s status=ok",
                    self._provider_name,
                    model,
                    extra={
                        "provider": self._provider_name,
                        "model": model,
                        "status": "ok",
                        "latency_ms": duration_ms,
                        "input_tokens": in_tokens,
                        "output_tokens": out_tokens,
                    },
                )
                metrics.llm_requests_total.labels(model, "ok").inc()
                metrics.llm_tokens_total.labels(model, "input").inc(in_tokens)
                metrics.llm_tokens_total.labels(model, "output").inc(out_tokens)
                return str(response.choices[0].message.content or "")
            except Exception as exc:  # noqa: BLE001
                if (
                    "response_format" in payload
                    and not schema_downgraded
                    and not _supports_json_schema_response(exc)
                ):
                    status = _error_status_label(exc)
                    metrics.llm_requests_total.labels(model, status).inc()
                    schema_downgraded = True
                    payload.pop("response_format", None)
                    logger.info(
                        "LLM provider does not support JSON schema response_format; retrying without it"
                    )
                    continue

                duration_ms = int((time.monotonic() - started) * 1000)
                status = _error_status_label(exc)
                logger.warning(
                    "LLM request failed: provider=%s model=%s status=%s attempt=%d/%d",
                    self._provider_name,
                    model,
                    status,
                    attempt + 1,
                    _MAX_ATTEMPTS,
                    extra={
                        "provider": self._provider_name,
                        "model": model,
                        "status": status,
                        "latency_ms": duration_ms,
                        "input_tokens": 0,
                        "output_tokens": 0,
                    },
                )
                metrics.llm_requests_total.labels(model, status).inc()
                if attempt == _MAX_ATTEMPTS - 1 or not _is_retryable(exc):
                    raise
                await asyncio.sleep(_backoff_seconds(attempt))

        raise RuntimeError("unreachable")
