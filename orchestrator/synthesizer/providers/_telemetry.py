"""
Shared request telemetry for the LLM providers.

Every provider records each completion in ``llm_requests_total`` and
``llm_tokens_total`` with the same ``provider`` / ``model`` labels, so an
operator sees the counters move whichever provider is configured and the
``model`` label never collides across providers.
"""

from __future__ import annotations

import asyncio

from orchestrator import metrics

RETRYABLE_STATUS_CODES = frozenset({408, 409, 429})  # plus every 5xx, see is_retryable_status
SCHEMA_REJECT_STATUS_CODES = frozenset({400, 422})


def is_retryable_status(status_code: int) -> bool:
    """Transient HTTP statuses: rate limit, request/lock timeouts and every 5xx."""
    return status_code in RETRYABLE_STATUS_CODES or status_code >= 500


def status_label(
    exc: Exception,
    *,
    timeout_types: tuple[type[BaseException], ...] = (),
    status_code: int | None = None,
) -> str:
    """Bucket an exception into the ``status`` label values documented in the README.

    *status_code* overrides the exception's own ``status_code`` attribute for
    SDKs that keep it on a nested response object (httpx).
    """
    if status_code is None:
        status_code = getattr(exc, "status_code", None)
    if status_code == 429:
        return "http_429"
    if isinstance(status_code, int) and status_code >= 500:
        return "http_5xx"
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError, *timeout_types)):
        return "timeout"
    return "error"


def record_request(
    provider: str, model: str, status: str, *, in_tokens: int = 0, out_tokens: int = 0
) -> None:
    """Count one request outcome and, on success, its token usage."""
    metrics.llm_requests_total.labels(provider, model, status).inc()
    if in_tokens:
        metrics.llm_tokens_total.labels(provider, model, "input").inc(in_tokens)
    if out_tokens:
        metrics.llm_tokens_total.labels(provider, model, "output").inc(out_tokens)
