"""
Shared request policy for the LLM providers: which HTTP statuses are
transient, which ones mean "the provider refused ``response_format``", and
how an exception maps to the ``status`` label values documented in docs/operations.md.
"""

from __future__ import annotations

import asyncio

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
    """Bucket an exception into the ``status`` label values documented in docs/operations.md.

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
