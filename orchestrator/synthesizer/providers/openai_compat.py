"""
OpenAI-compatible LLM provider (optional extra).

Works with the official OpenAI API, Nebius Token Factory, Azure OpenAI, or any
local server that speaks the OpenAI chat-completions protocol (e.g. LM Studio,
vLLM).

Install: pip install openai
Config:  OPENAI_API_KEY, optionally OPENAI_BASE_URL for compatible endpoints;
         NEBIUS_API_KEY / NEBIUS_BASE_URL for the Nebius preset.

Retry policy
------------
The SDK's own retries are disabled (``max_retries=0``) and replaced by a loop
that the caller's ``timeout`` bounds as a whole: every attempt gets the
remaining budget, backoff waits are capped by it, and the call never outlives
``LLM_TIMEOUT_SECONDS``. Retries happen on 408, 409, 429, every 5xx and
transport errors, honouring ``Retry-After`` when the provider sends one. A
provider that rejects ``response_format`` (400/422) gets the same request once
more without it; that capability probe is counted as ``schema_downgrade`` and
does not consume an attempt.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Any, Literal

from orchestrator.config import settings
from orchestrator.synthesizer.model_routing import resolve_model_for_route
from orchestrator.synthesizer.providers._telemetry import (
    SCHEMA_REJECT_STATUS_CODES,
    is_retryable_status,
    record_request,
    status_label,
)

logger = logging.getLogger(__name__)

try:
    import openai as _openai_sdk

    _HAS_OPENAI = True
except ImportError:
    _openai_sdk = None
    _HAS_OPENAI = False


_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 30.0
_BACKOFF_JITTER_RATIO = 0.25


def _usage_tokens(response: Any) -> tuple[int, int]:
    usage = getattr(response, "usage", None)
    in_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
    out_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
    return in_tokens, out_tokens


def _sdk_types(*names: str) -> tuple[type[BaseException], ...]:
    return tuple(
        cls for cls in (getattr(_openai_sdk, name, None) for name in names) if cls is not None
    )


def _error_status_label(exc: Exception) -> str:
    return status_label(exc, timeout_types=_sdk_types("APITimeoutError"))


def _is_retryable(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        return is_retryable_status(status_code)
    retryable_types = (
        *_sdk_types("RateLimitError", "APITimeoutError", "APIConnectionError"),
        TimeoutError,
        asyncio.TimeoutError,
    )
    return isinstance(exc, retryable_types)


def _rejects_json_schema(exc: Exception) -> bool:
    """True when the provider refused the request because of ``response_format``.

    Servers word the rejection differently ("Unrecognized request argument
    supplied: json_schema", "response_format is not supported", ...) and some
    gateways answer 422 instead of 400, so any mention of either token on a
    400/422 counts.
    """
    if getattr(exc, "status_code", None) not in SCHEMA_REJECT_STATUS_CODES:
        return False
    message = str(exc).lower()
    return "response_format" in message or "json_schema" in message or "json schema" in message


def _retry_after_seconds(exc: Exception) -> float | None:
    """Seconds from a ``Retry-After`` header, if the provider sent a numeric one."""
    headers = getattr(getattr(exc, "response", None), "headers", None)
    raw = headers.get("retry-after") if hasattr(headers, "get") else None
    if raw is None:
        return None
    try:
        value = float(str(raw).strip())
    except ValueError:  # HTTP-date form: fall back to the exponential delay
        return None
    return value if value >= 0 else None


def _backoff_seconds(attempt_index: int) -> float:
    delay = min(_BACKOFF_BASE_SECONDS * (2**attempt_index), _BACKOFF_CAP_SECONDS)
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
        # A blank URL (explicit or from OPENAI_BASE_URL) means "SDK default",
        # never a schemeless "" that the SDK rejects as an invalid URL. Presets
        # such as nebius pass their own URL; get_client() fills it in when the
        # operator blanked NEBIUS_BASE_URL.
        cleaned = (base_url or "").strip()
        if not cleaned and provider_name == "openai":
            cleaned = settings.openai_base_url.strip()
        self._base_url = cleaned or None

    @staticmethod
    def model_for_route(route: Literal["reasoning", "fast"]) -> str:
        """The model a request on *route* is sent to (persisted with the finding)."""
        return resolve_model_for_route(route)

    async def complete(
        self,
        system: str,
        user: str,
        *,
        timeout: float,
        model_route: Literal["reasoning", "fast"] = "reasoning",
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        """One /v1/chat/completions call (temperature 0) within *timeout*; returns the raw text."""
        if not _HAS_OPENAI:
            raise RuntimeError("openai package is not installed; run: pip install openai")

        model = self.model_for_route(model_route)
        client = _openai_sdk.AsyncOpenAI(
            api_key=self._api_key,
            base_url=self._base_url,
            timeout=timeout,
            max_retries=0,
        )
        log_extra = {"provider": self._provider_name, "model": model}

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

        deadline = time.monotonic() + timeout
        attempt = 0
        while True:
            started = time.monotonic()
            remaining = max(deadline - started, 0.001)
            try:
                response = await client.chat.completions.create(**payload, timeout=remaining)
            except Exception as exc:  # noqa: BLE001
                if "response_format" in payload and _rejects_json_schema(exc):
                    # Capability probe, not a failure: the request is repeated
                    # without the schema and the attempt counter is untouched.
                    payload.pop("response_format")
                    record_request(self._provider_name, model, "schema_downgrade")
                    logger.info(
                        "LLM provider rejected JSON schema response_format; retrying without it: "
                        "provider=%s model=%s",
                        self._provider_name,
                        model,
                        extra={**log_extra, "status": "schema_downgrade"},
                    )
                    continue

                attempt += 1
                duration_ms = int((time.monotonic() - started) * 1000)
                status = _error_status_label(exc)
                logger.warning(
                    "LLM request failed: provider=%s model=%s status=%s attempt=%d/%d",
                    self._provider_name,
                    model,
                    status,
                    attempt,
                    _MAX_ATTEMPTS,
                    extra={
                        **log_extra,
                        "status": status,
                        "latency_ms": duration_ms,
                        "input_tokens": 0,
                        "output_tokens": 0,
                    },
                )
                record_request(self._provider_name, model, status)
                if attempt >= _MAX_ATTEMPTS or not _is_retryable(exc):
                    raise
                retry_after = _retry_after_seconds(exc)
                delay = retry_after if retry_after is not None else _backoff_seconds(attempt - 1)
                if delay >= deadline - time.monotonic():
                    # Waiting would leave no budget for the next attempt.
                    raise
                await asyncio.sleep(delay)
                continue

            duration_ms = int((time.monotonic() - started) * 1000)
            in_tokens, out_tokens = _usage_tokens(response)
            logger.info(
                "LLM request completed: provider=%s model=%s status=ok",
                self._provider_name,
                model,
                extra={
                    **log_extra,
                    "status": "ok",
                    "latency_ms": duration_ms,
                    "input_tokens": in_tokens,
                    "output_tokens": out_tokens,
                },
            )
            record_request(
                self._provider_name, model, "ok", in_tokens=in_tokens, out_tokens=out_tokens
            )
            return str(response.choices[0].message.content or "")
