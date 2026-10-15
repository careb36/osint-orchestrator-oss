"""
Tests for orchestrator.auth — API-key protection of the HTTP API (Phase 5).

The properties that matter:
  - With no key configured the API is open (dev default) and says so loudly.
  - With a key configured every data endpoint rejects missing/wrong keys with
    a localised 401 and accepts either header form.
  - /health and /metrics never need a key (probes and scrapers).
  - Comma-separated keys all work (rotation).
"""

from __future__ import annotations

import logging
import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import orchestrator.api as api_mod
import orchestrator.auth as auth_mod
from orchestrator.api import app, router
from orchestrator.auth import auth_enabled, configured_api_keys, log_auth_status
from orchestrator.config import settings

PROTECTED_GET = "/targets"
AUTH_EXEMPT_PATHS = {
    "/health",
    "/metrics",
    "/",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/console",
}


def _probe_path(path_template: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path_template)


def _derived_route_calls() -> list[tuple[str, str]]:
    calls: set[tuple[str, str]] = set()
    for route in router.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path in AUTH_EXEMPT_PATHS or route.path.startswith("/docs/"):
            continue
        for method in route.methods - {"HEAD", "OPTIONS"}:
            calls.add((method, _probe_path(route.path)))
    return sorted(calls)


DERIVED_PROTECTED_CALLS = _derived_route_calls()


@pytest.fixture
def client():
    # As a context manager the app lifespan runs once and every request shares
    # one event loop; without `with`, each request spun up a throwaway loop and
    # the aiosqlite connection opened on it died after the loop was gone
    # ("Event loop is closed" from the connection worker thread).
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def no_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "orchestrator_api_key", "")


@pytest.fixture
def one_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "orchestrator_api_key", "test-key")


# ── Configuration parsing ────────────────────────────────────────────────────


def test_no_key_means_auth_disabled(no_key) -> None:
    assert configured_api_keys() == ()
    assert not auth_enabled()


def test_keys_are_comma_separated_and_trimmed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", " key-a , key-b,, ")
    assert configured_api_keys() == ("key-a", "key-b")
    assert auth_enabled()


# ── Open mode ────────────────────────────────────────────────────────────────


def test_open_mode_serves_protected_endpoint_without_key(no_key, client: TestClient) -> None:
    assert client.get(PROTECTED_GET).status_code == 200


def test_open_mode_warns_once_at_startup(no_key, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger=auth_mod.__name__):
        log_auth_status()
    assert any("DISABLED" in r.getMessage() for r in caplog.records)


def test_enabled_mode_logs_count_not_key(one_key, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger=auth_mod.__name__):
        log_auth_status()
    messages = [r.getMessage() for r in caplog.records]
    assert any("1 key(s)" in m for m in messages)
    assert not any("test-key" in m for m in messages)


# ── Enforcement ──────────────────────────────────────────────────────────────


def test_missing_key_is_401_with_localised_detail(
    one_key, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "orchestrator_language", "es")
    resp = client.get(PROTECTED_GET)
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"
    assert resp.json()["detail"].startswith("Falta la clave de API")

    monkeypatch.setattr(settings, "orchestrator_language", "en")
    assert client.get(PROTECTED_GET).json()["detail"].startswith("API key missing")


def test_wrong_key_is_401(one_key, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    resp = client.get(PROTECTED_GET, headers={"X-API-Key": "nope"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid API key"

    resp = client.get(PROTECTED_GET, headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401


def test_prefix_of_key_is_rejected(one_key, client: TestClient) -> None:
    """compare_digest, not startswith: a partial key must not pass."""
    assert client.get(PROTECTED_GET, headers={"X-API-Key": "test-ke"}).status_code == 401
    assert client.get(PROTECTED_GET, headers={"X-API-Key": "test-key "}).status_code == 401


def test_valid_key_via_x_api_key_header(one_key, client: TestClient) -> None:
    assert client.get(PROTECTED_GET, headers={"X-API-Key": "test-key"}).status_code == 200


def test_valid_key_via_bearer(one_key, client: TestClient) -> None:
    resp = client.get(PROTECTED_GET, headers={"Authorization": "Bearer test-key"})
    assert resp.status_code == 200


def test_either_header_matching_is_enough(one_key, client: TestClient) -> None:
    """A stale key in one header must not shadow a valid one in the other."""
    resp = client.get(
        PROTECTED_GET, headers={"X-API-Key": "stale", "Authorization": "Bearer test-key"}
    )
    assert resp.status_code == 200
    resp = client.get(
        PROTECTED_GET, headers={"X-API-Key": "test-key", "Authorization": "Bearer stale"}
    )
    assert resp.status_code == 200
    resp = client.get(PROTECTED_GET, headers={"X-API-Key": "stale", "Authorization": "Bearer no"})
    assert resp.status_code == 401


def test_basic_scheme_is_not_accepted_as_bearer(one_key, client: TestClient) -> None:
    resp = client.get(PROTECTED_GET, headers={"Authorization": "Basic dGVzdC1rZXk="})
    assert resp.status_code == 401


def test_every_rotated_key_is_accepted(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "old-key,new-key")
    assert client.get(PROTECTED_GET, headers={"X-API-Key": "old-key"}).status_code == 200
    assert client.get(PROTECTED_GET, headers={"X-API-Key": "new-key"}).status_code == 200
    assert client.get(PROTECTED_GET, headers={"X-API-Key": "other"}).status_code == 401


@pytest.mark.parametrize(("method", "path"), DERIVED_PROTECTED_CALLS)
def test_every_data_endpoint_is_protected(
    one_key, client: TestClient, method: str, path: str
) -> None:
    """Auth must run before the handler: a 401, never a 404 from the handler."""
    assert client.request(method, path).status_code == 401


def test_derived_route_calls_include_core_protected_endpoints() -> None:
    assert DERIVED_PROTECTED_CALLS, "no protected routes derived"
    assert ("GET", "/targets") in DERIVED_PROTECTED_CALLS
    assert ("POST", "/alerts/dlq/replay") in DERIVED_PROTECTED_CALLS


# ── Exemptions ───────────────────────────────────────────────────────────────


def test_health_never_needs_a_key(one_key, client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["status"] in {"ok", "degraded", "offline"}
    assert payload["version"]
    assert payload["checks"]["api"]["status"] == "ok"
    assert set(payload["checks"]).issubset({"api", "database", "scheduler", "opencti"})


def test_health_includes_actionable_recovery_hints(one_key, client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    payload = resp.json()
    for check in payload["checks"].values():
        assert "detail" in check
        assert "hint" in check
        assert "action" in check
        assert check["hint"]
        assert check["action"]


def test_health_reports_a_disabled_opencti_sink_without_degrading(
    one_key, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-008: running without the sink is a configuration, not a fault."""
    monkeypatch.setattr(settings, "opencti_enabled", False)
    resp = client.get("/health")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["status"] == "ok"
    assert payload["checks"]["opencti"]["status"] == "disabled"
    assert payload["checks"]["database"]["status"] == "ok"


def test_health_prioritizes_offline_when_database_check_fails(
    one_key, client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FailingSessionContext:
        async def __aenter__(self):
            raise RuntimeError("db down")

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(api_mod, "get_session", lambda: _FailingSessionContext())
    monkeypatch.setattr(settings, "opencti_enabled", False)
    resp = client.get("/health")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["status"] == "offline"
    assert payload["checks"]["database"]["status"] == "offline"
    assert payload["checks"]["opencti"]["status"] == "disabled"


def test_metrics_never_needs_a_key(one_key, client: TestClient) -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")


@pytest.mark.parametrize("path", sorted(AUTH_EXEMPT_PATHS))
def test_documented_auth_exemptions_never_return_401(
    one_key, client: TestClient, path: str
) -> None:
    assert client.get(path).status_code != 401


def test_docs_oauth_redirect_is_public(one_key, client: TestClient) -> None:
    assert client.get("/docs/oauth2-redirect").status_code != 401


def test_openapi_documents_the_security_schemes(client: TestClient) -> None:
    """Clients discover both header forms from the schema."""
    schemes = client.get("/openapi.json").json()["components"]["securitySchemes"]
    assert any(s.get("type") == "apiKey" and s.get("name") == "X-API-Key" for s in schemes.values())
    assert any(s.get("scheme") == "bearer" for s in schemes.values())
