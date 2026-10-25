"""Authentication for personal browser sessions and legacy automation keys.

Personal sessions carry an authenticated actor and enforce administrative
permissions on technical operations. Dossier decisions additionally require
an accountant identity. Machine keys cannot impersonate a professional.
Anonymous development mode is available only before any account is provisioned
and when no API key is configured. ADR-012 amends ADR-005/006/010.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import HTTPException, Request, Security, status
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
    request: Request,
    header_key: str | None = _API_KEY_DEP,
    bearer: HTTPAuthorizationCredentials | None = _BEARER_DEP,
) -> None:
    """
    FastAPI dependency: reject the request unless it carries a valid key.

    A no-op when no key is configured (see module docstring).
    """
    from orchestrator.accounts import (
        COOKIE_NAME,
        accounts_exist,
        check_browser_request,
        session_user,
    )

    if request.cookies.get(COOKIE_NAME):
        user = await session_user(request)
        if not user:
            raise HTTPException(401, t("access_required"))
        check_browser_request(request)
        request.state.actor = user
        if (
            request.url.path.startswith(("/scheduler/", "/opencti/", "/alerts/dlq", "/bundles"))
            and user["role"] != "admin"
        ):
            raise HTTPException(403, t("access_denied"))
        return
    request.state.actor = None
    if not auth_enabled():
        if await accounts_exist():
            raise HTTPException(401, t("access_required"))
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
            "Without personal accounts, legacy endpoints allow anonymous access. "
            "Configure personal accounts or a key before exposing the orchestrator beyond localhost."
        )


def log_secret_key_status() -> None:
    """Warn when the evidence-signing key (ADR-007) is the default or empty.

    A copied .env.example leaves the key blank, which Compose passes as an
    empty string: manifests would then be signed with an empty key.
    """
    if settings.orchestrator_secret_key in ("", "insecure-dev-key"):
        logger.warning(
            "ORCHESTRATOR_SECRET_KEY is empty or the default insecure-dev-key: evidence "
            "manifests are signed with a public key. Generate one (openssl rand -hex 32) "
            "before deployment.",
            extra={"setting": "ORCHESTRATOR_SECRET_KEY"},
        )


def require_person(request: Request) -> dict:
    """Professional decisions require personal identity, never a shared machine key."""
    actor = getattr(request.state, "actor", None)
    if not actor:
        raise HTTPException(401, t("access_required"))
    return actor


def require_admin(request: Request) -> dict:
    actor = require_person(request)
    if actor["role"] != "admin":
        raise HTTPException(403, t("access_denied"))
    return actor
