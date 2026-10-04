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

from orchestrator.config import NEBIUS_DEFAULT_BASE_URL, settings
from orchestrator.synthesizer.model_routing import resolve_model_for_route
from orchestrator.synthesizer.providers._policy import (
    SCHEMA_REJECT_STATUS_CODES,
    is_retryable_status,
    status_label,
)
from orchestrator.synthesizer.providers._telemetry import record_request

logger = logging.getLogger(__name__)

try:
    import openai as _openai_sdk

    _HAS_OPENAI = True
except ImportError:
    _openai_sdk = None
    _HAS_OPENAI = False


_MAX_ATTEMPTS = 3
# Named presets and the endpoint they must never fall away from. "openai"
# follows OPENAI_BASE_URL (blank = SDK default); any other preset without a
# URL is a configuration error rather than a silent call to api.openai.com.
_PRESET_BASE_URLS: dict[str, str] = {"nebius": NEBIUS_DEFAULT_BASE_URL}
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


def _error_param(exc: Exception) -> str | None:
    """The ``error.param`` of an OpenAI-style error body, when the SDK exposes one."""
    body = getattr(exc, "body", None)
    error = body.get("error", body) if isinstance(body, dict) else None
    param = error.get("param") if isinstance(error, dict) else None
    return str(param) if param else None


def _rejects_json_schema(exc: Exception) -> bool:
    """True when the provider refused the request because of ``response_format``.

    The structured ``error.param`` is authoritative when present. Without it
    (gateways, older servers) the message is inspected: servers word the
    rejection differently ("Unrecognized request argument supplied:
    json_schema", "response_format is not supported", ...) and some answer 422
    instead of 400. The probe runs once per call (the key is popped), so a
    misread costs one tolerant-parsing request, never schema enforcement on
    the retries of an unrelated error.
    """
    if getattr(exc, "status_code", None) not in SCHEMA_REJECT_STATUS_CODES:
        return False
    param = _error_param(exc)
    if param is not None:
        return param.startswith("response_format")
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
        # A blank URL never reaches the SDK as a schemeless "": "openai" falls
        # back to OPENAI_BASE_URL and then to the SDK default; a named preset
        # falls back to its own endpoint; anything else must say where it goes.
        cleaned = (base_url or "").strip()
        if not cleaned:
            if provider_name == "openai":
                cleaned = settings.openai_base_url.strip()
            elif provider_name in _PRESET_BASE_URLS:
                cleaned = _PRESET_BASE_URLS[provider_name]
            else:
                raise ValueError(f"LLM preset {provider_name!r} needs an explicit base_url")
        self._base_url = cleaned or None

    @property
    def provider(self) -> str:
        """Provider name as recorded on findings and metrics (``openai`` or a preset)."""
        return self._provider_name

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
        last_exc: Exception | None = None
        while True:
            started = time.monotonic()
            remaining = deadline - started
            if remaining <= 0:
                # Budget gone before this attempt could start: never send a
                # doomed request whose timeout would mask the real outcome.
                if last_exc is not None:
                    raise last_exc
                # Only a slow schema probe gets here (an ordinary failure
                # raises inside its except block); report it as the timeout
                # it is, not as the 400 that was deliberately not a failure.
                record_request(self._provider_name, model, "timeout")
                logger.warning(
                    "LLM request budget exhausted after the schema probe: provider=%s model=%s",
                    self._provider_name,
                    model,
                    extra={**log_extra, "status": "timeout"},
                )
                raise TimeoutError(f"LLM request budget of {timeout:.0f}s exhausted")
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

                last_exc = exc
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
                        "attempt": attempt,
                        "max_attempts": _MAX_ATTEMPTS,
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
