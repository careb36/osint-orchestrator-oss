"""
OpenCTI sink: ingest a stix2.Bundle into OpenCTI, with a bounded retry policy,
off the event loop.

The design follows what pycti actually does (verified against 7.260907.0),
not what its method names suggest:

1. ``OpenCTIApiClient.__init__`` performs a network health check and raises
   ``ValueError`` when the platform is unreachable. The client is therefore
   built with ``perform_health_check=False`` so construction never does I/O;
   reachability is checked per ingest, under the retry policy, instead of
   aborting the whole run before the pipeline's per-bundle error handling.
2. ``OpenCTIApiClient.query()`` reports failures three ways: ``requests``
   exceptions for connection and timeout problems; ``ValueError(dict)`` with a
   ``name`` such as ``AUTH_REQUIRED`` for a GraphQL error on a 200; and
   ``ValueError(str)`` carrying the raw body for any non-200 status.
3. ``OpenCTIStix2.import_bundle_from_json()`` retries every object itself
   (10-30 s sleeps, up to ``MAX_PROCESSING_COUNT``) and, on an error it does
   not recognise — which is where an invalid token lands — logs it and returns
   the object as *imported*. It raises only for a malformed or empty bundle and
   otherwise returns ``(imported, failed)``.

So an authenticated probe runs before every bundle, turning a bad token or a
down platform into an exception this module can classify; the import's
returned ``failed`` list is treated as a failure; and only transient errors
are retried. OpenCTI de-duplicates by STIX id, so re-sending a bundle is
idempotent and retrying is safe.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections.abc import Callable
from typing import Any

import stix2

from orchestrator import metrics
from orchestrator.backoff import backoff_delay as _backoff_delay
from orchestrator.config import settings

logger = logging.getLogger(__name__)

# Indirections so tests can stub the waits without patching asyncio or time.
_async_sleep: Callable[[float], Any] = asyncio.sleep
_sync_sleep: Callable[[float], None] = time.sleep

MAX_BACKOFF_SECONDS = 30.0
BACKOFF_JITTER = 0.25

# Cheapest query that requires a valid token: OpenCTI answers AUTH_REQUIRED
# otherwise. ``about { version }`` (pycti's own health check) is public and
# would let an invalid token through.
_PROBE_QUERY = "query OrchestratorProbe { me { id } }"

# GraphQL error names pycti puts in ValueError(dict)["name"] that mean the
# platform is busy rather than refusing the request. Everything else —
# AUTH_REQUIRED, FORBIDDEN_ACCESS, VALIDATION_ERROR, MISSING_REFERENCE_ERROR,
# UNSUPPORTED_ERROR, GRAPHQL_VALIDATION_FAILED, and any name added by a future
# platform version — is treated as permanent: retrying cannot fix it.
_TRANSIENT_GRAPHQL_ERRORS = frozenset(
    {"LOCK_ERROR", "DATABASE_ERROR", "INTERNAL_ERROR", "UNKNOWN_ERROR"}
)
# Raw bodies from ValueError(str): a proxy or the platform answering with a
# status pycti does not decode. Only the statuses worth waiting for.
_TRANSIENT_BODY = re.compile(
    r"\b(?:429|502|503|504)\b"
    r"|Too Many Requests|Bad Gateway|Service (?:Temporarily )?Unavailable"
    r"|Gateway Time-?out|Request timed out",
    re.IGNORECASE,
)


class OpenCTIIngestError(RuntimeError):
    """Raised by the sink itself; ``transient`` decides whether it is retried."""

    def __init__(self, message: str, *, transient: bool) -> None:
        super().__init__(message)
        self.transient = transient


def is_transient(exc: BaseException) -> bool:
    """Classify an ingest failure.

    Transient (retried): connection errors and timeouts from ``requests``;
    HTTP 429/502/503/504 bodies; the platform's LOCK/DATABASE/INTERNAL errors.
    Permanent (fail first time): an invalid or unauthorised token (401/403,
    AUTH_REQUIRED, FORBIDDEN_ACCESS), a rejected bundle (400/422,
    VALIDATION_ERROR), anything unrecognised. Unknown errors are not retried
    on purpose: a wrong guess there costs minutes of waiting on every run.
    """
    if isinstance(exc, OpenCTIIngestError):
        return exc.transient
    try:
        import requests  # pycti depends on it; missing only when pycti is
    except ImportError:  # pragma: no cover
        requests = None  # type: ignore[assignment]
    if requests is not None and isinstance(exc, requests.RequestException):
        return True
    if isinstance(exc, ValueError) and exc.args:
        detail = exc.args[0]
        if isinstance(detail, dict):
            return str(detail.get("name", "")) in _TRANSIENT_GRAPHQL_ERRORS
        if isinstance(detail, str):
            return bool(_TRANSIENT_BODY.search(detail))
    return False


def backoff_delay(attempt: int, base: float | None = None) -> float:
    """Wait before retry number ``attempt`` (0-based): base·2^attempt, ±25 %, ≤30 s."""
    if base is None:
        base = settings.opencti_ingest_backoff_seconds
    return round(
        _backoff_delay(attempt, base=base, jitter_ratio=BACKOFF_JITTER, cap=MAX_BACKOFF_SECONDS),
        3,
    )


def _rejected_summary(failed: list, limit: int = 10) -> str:
    """Render the first rejected objects as ``id (type)`` for the error message."""
    parts = []
    for item in failed[:limit]:
        if isinstance(item, dict):
            ident = item.get("id") or item.get("standard_id") or "?"
            tipo = item.get("type") or item.get("entity_type") or "?"
            parts.append(f"{ident} ({tipo})")
        else:
            parts.append(str(item)[:80])
    extra = f" (+{len(failed) - limit} more)" if len(failed) > limit else ""
    return ", ".join(parts) + extra


class OpenCTISink:
    """
    Ingests STIX 2.1 bundles into OpenCTI through pycti's ``OpenCTIApiClient``
    (a direct API import, not a connector daemon).

    ``ingest_async`` is what the pipeline calls: the blocking pycti work runs in
    a worker thread so the API and the scheduler keep serving while a large
    bundle is pushed. ``ingest`` is the synchronous equivalent for callers that
    are not on the event loop.
    """

    def __init__(self) -> None:
        self._url = settings.opencti_url
        self._token = settings.opencti_admin_token
        self._config_error: str | None = None
        self._client = self._make_client()

    def _make_client(self):  # type: ignore[return]
        """Lazy-import pycti to avoid a hard dependency at import time."""
        try:
            from pycti import OpenCTIApiClient  # type: ignore[import]
        except ImportError:
            logger.warning(
                "pycti not installed — OpenCTI sink is a no-op. Install with: pip install pycti"
            )
            return None
        try:
            return OpenCTIApiClient(
                url=self._url,
                token=self._token,
                log_level="error",
                ssl_verify=settings.opencti_ssl_verify,
                # See module docstring, point 1.
                perform_health_check=False,
            )
        except ValueError as exc:
            # pycti refuses an empty URL or token here. Recording it, rather
            # than letting it escape, keeps the run alive: every bundle then
            # fails with this message, the run ends partial and the report and
            # alerts still go out.
            self._config_error = str(exc)
            logger.error("OpenCTI client not configured: %s", exc)
            return None

    # ── attempts ─────────────────────────────────────────────────────────────

    def _ingest_once(self, bundle_json: str, object_count: int, work_name: str) -> None:
        """One attempt, synchronous. ``ingest_async`` runs it in a worker thread."""
        client = self._client
        # 1. Authenticated probe: an invalid token or an unreachable platform
        #    raises here, where it can be classified, instead of being
        #    swallowed object by object inside pycti (docstring, point 3).
        client.query(_PROBE_QUERY)
        # 2. Import. pycti retries each object itself and returns whatever it
        #    gave up on; those objects are not in OpenCTI and the bundle must
        #    count as not ingested so the next run re-reports them (Issue #8).
        result = client.stix2.import_bundle_from_json(bundle_json, update=True)  # type: ignore[attr-defined]
        failed = result[1] if isinstance(result, tuple) and len(result) == 2 else []
        if failed:
            raise OpenCTIIngestError(
                f"{len(failed)} of {object_count} objects rejected by OpenCTI "
                f"after pycti's own per-object retries: {_rejected_summary(failed)}",
                transient=False,
            )
        logger.info("OpenCTI ingest OK: work=%s objects=%d", work_name, object_count)

    def _prepare(self, bundle: stix2.Bundle) -> tuple[str, int] | None:
        """Serialise once; ``None`` means there is nothing to do (pycti absent)."""
        if self._client is None:
            if self._config_error is not None:
                raise OpenCTIIngestError(
                    f"OpenCTI client not configured: {self._config_error}", transient=False
                )
            logger.warning("OpenCTI client not available — skipping ingest")
            return None
        return bundle.serialize(pretty=False), len(bundle.get("objects", []))

    def _note_retry(
        self,
        attempt: int,
        retries: int,
        delay: float,
        exc: BaseException,
        target_id: str | None,
        work_name: str,
    ) -> None:
        """Count a transient-ingest retry in metrics and log the backoff wait."""
        if target_id is not None:
            metrics.opencti_ingest_retries_total.labels(target_id).inc()
        logger.warning(
            "OpenCTI ingest attempt %d/%d failed, retrying in %.1fs: %s",
            attempt + 1,
            retries + 1,
            delay,
            exc,
            extra={
                "target_id": target_id,
                "work": work_name,
                "attempt": attempt + 1,
                "retries": retries,
                "delay_seconds": delay,
                "error": str(exc),
            },
        )

    # ── public API ───────────────────────────────────────────────────────────

    async def ingest_async(
        self,
        bundle: stix2.Bundle,
        *,
        work_name: str = "osint-orchestrator",
        target_id: str | None = None,
    ) -> None:
        """Push a bundle from a coroutine without blocking the event loop.

        Raises the last error once retries are exhausted, or immediately for a
        permanent one; the pipeline records either as a failed ingest.
        """
        prepared = self._prepare(bundle)
        if prepared is None:
            return
        bundle_json, count = prepared
        retries = max(0, settings.opencti_ingest_retries)
        for attempt in range(retries + 1):
            try:
                await asyncio.to_thread(self._ingest_once, bundle_json, count, work_name)
                return
            except Exception as exc:  # noqa: BLE001
                if attempt >= retries or not is_transient(exc):
                    logger.error("OpenCTI ingest failed: %s", exc)
                    raise
                delay = backoff_delay(attempt)
                self._note_retry(attempt, retries, delay, exc, target_id, work_name)
                await _async_sleep(delay)

    def ingest(
        self,
        bundle: stix2.Bundle,
        work_name: str = "osint-orchestrator",
        *,
        target_id: str | None = None,
    ) -> None:
        """Synchronous ``ingest_async``: same policy, blocking waits."""
        prepared = self._prepare(bundle)
        if prepared is None:
            return
        bundle_json, count = prepared
        retries = max(0, settings.opencti_ingest_retries)
        for attempt in range(retries + 1):
            try:
                self._ingest_once(bundle_json, count, work_name)
                return
            except Exception as exc:  # noqa: BLE001
                if attempt >= retries or not is_transient(exc):
                    logger.error("OpenCTI ingest failed: %s", exc)
                    raise
                delay = backoff_delay(attempt)
                self._note_retry(attempt, retries, delay, exc, target_id, work_name)
                _sync_sleep(delay)
