"""
API authentication — static API keys (Phase 5).

The orchestrator API can trigger collection runs against authorised targets
and exposes their results, so it must not sit open on a network. The model
is deliberately small: one or more shared API keys, presented either in the
``X-API-Key`` header or as a bearer token in the ``Authorization`` header.

Why not OAuth / OIDC / per-user accounts: the callers are operators and
automation (cron, CI, a SOAR playbook), not end users, and the platform of
record — OpenCTI — already has its own RBAC. A static key keeps the surface
auditable and the deployment dependency-free. See ADR-005.

Rules:
  - ORCHESTRATOR_API_KEY empty → authentication DISABLED. Every endpoint is
    open and a warning is logged once at startup. This keeps `docker compose
    up` on a laptop working, but a production deployment must set a key.
  - Several keys may be configured, comma-separated, so a key can be rotated
    without a cut-over window.
  - Always public: GET /health and GET /metrics (probe/scraper endpoints); the
    documentation/landing endpoints GET /, GET /docs (and /docs/*), GET
    /openapi.json, GET /redoc; and the console shell, GET /console and GET
    /console/i18n.json, which carry no target or run data — a browser cannot
    attach a header to its first navigation, so the page that asks for the
    key must itself be open. Every data and control endpoint, including
    everything the console fetches, remains protected.
  - Comparison is constant-time (hmac.compare_digest) and every configured
    key is checked so timing does not reveal which slot matched.
  - When a request carries both headers, either one matching is enough: a
    stale X-API-Key left in a client config must not shadow a valid bearer
    token (or vice versa) during a rotation or behind a proxy that injects
    one of them.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from orchestrator.config import settings
from orchestrator.i18n import t

logger = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"

# auto_error=False: we raise ourselves so the error detail is localised
# (ADR-004) and both header forms are accepted before failing.
_api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)
_bearer = HTTPBearer(auto_error=False)
# Module-level singletons (ruff B008): FastAPI resolves them per request.
_API_KEY_DEP = Security(_api_key_header)
_BEARER_DEP = Security(_bearer)


def configured_api_keys() -> tuple[str, ...]:
    """Accepted keys from ORCHESTRATOR_API_KEY (comma-separated, blanks dropped)."""
    return tuple(k.strip() for k in settings.orchestrator_api_key.split(",") if k.strip())


def auth_enabled() -> bool:
    """True when at least one API key is configured (empty key = open API)."""
    return bool(configured_api_keys())


def _matches_any(presented: str) -> bool:
    """Constant-time check of a presented key against every configured key."""
    presented_bytes = presented.encode()
    matched = False
    # No early return: check every key so the time taken does not depend on
    # which one (if any) matched.
    for key in configured_api_keys():
        if hmac.compare_digest(presented_bytes, key.encode()):
            matched = True
    return matched


async def require_api_key(
    header_key: str | None = _API_KEY_DEP,
    bearer: HTTPAuthorizationCredentials | None = _BEARER_DEP,
) -> None:
    """
    FastAPI dependency: reject the request unless it carries a valid key.

    A no-op when no key is configured (see module docstring).
    """
    if not auth_enabled():
        return

    presented = [
        value for value in (header_key, bearer.credentials if bearer is not None else None) if value
    ]
    if not presented:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("api_key_missing"),
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Evaluate every presented credential (no short-circuit) so the response
    # time does not depend on which header carried the valid key.
    matches = [_matches_any(value) for value in presented]
    if not any(matches):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=t("api_key_invalid"),
            headers={"WWW-Authenticate": "Bearer"},
        )


def log_auth_status() -> None:
    """Log once at startup whether the API is protected. Never logs the key."""
    keys = configured_api_keys()
    if keys:
        logger.info("API authentication enabled (%d key(s) configured)", len(keys))
    else:
        logger.warning(
            "API authentication is DISABLED: ORCHESTRATOR_API_KEY is empty. "
            "Every endpoint is open. Set a key before exposing the orchestrator "
            "beyond localhost."
        )
