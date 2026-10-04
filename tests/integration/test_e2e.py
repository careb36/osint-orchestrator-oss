"""
Integration test: end-to-end pipeline with a real compose stack.

Marked as `integration` — skipped by default in CI unless:
  pytest -m integration

Requirements:
  - docker compose stack running (see docker-compose.yml)
  - OPENCTI_ADMIN_TOKEN set in .env
  - orchestrator service reachable at http://localhost:8000
"""

from __future__ import annotations

import os

import httpx
import pytest

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8000")
OPENCTI_URL = os.getenv("OPENCTI_URL", "http://localhost:8080")


pytestmark = pytest.mark.integration


@pytest.mark.integration
def test_orchestrator_health():
    """Orchestrator /health must return 200 with status=ok."""
    resp = httpx.get(f"{ORCHESTRATOR_URL}/health", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.integration
def test_opencti_reachable():
    """OpenCTI must be accessible (health endpoint)."""
    try:
        resp = httpx.get(f"{OPENCTI_URL}/health", timeout=15)
        assert resp.status_code in (200, 302)
    except httpx.ConnectError:
        pytest.skip("OpenCTI not reachable — is docker compose up?")


@pytest.mark.integration
def test_targets_endpoint_returns_list():
    """GET /targets must return a list (may be empty if targets.yaml absent)."""
    resp = httpx.get(f"{ORCHESTRATOR_URL}/targets", timeout=10)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.integration
def test_trigger_run_unknown_target_returns_404():
    resp = httpx.post(f"{ORCHESTRATOR_URL}/targets/non-existent-target/run", timeout=10)
    assert resp.status_code == 404


@pytest.mark.integration
def test_misp_connector_registered_in_opencti():
    """
    The connector-misp service must appear as a registered connector in OpenCTI.

    Prerequisites:
      - docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d
      - MISP fully initialised (first start can take 5-10 min)
      - MISP_KEY set in .env (API key from MISP admin UI)
      - connector-misp container running and connected to OpenCTI

    Verify manually: OpenCTI → Data → Connectors → look for "MISP".
    """
    import os

    opencti_token = os.getenv("OPENCTI_ADMIN_TOKEN", "")
    if not opencti_token:
        pytest.skip("OPENCTI_ADMIN_TOKEN not set")

    try:
        from pycti import OpenCTIApiClient  # type: ignore[import]
    except ImportError:
        pytest.skip("pycti not installed")

    try:
        api = OpenCTIApiClient(OPENCTI_URL, opencti_token, ssl_verify=False)
        connectors = api.connector.list()
    except Exception as exc:
        pytest.skip(f"Could not query OpenCTI connectors: {exc}")

    connector_names = [c.get("name", "").lower() for c in (connectors or [])]
    assert any("misp" in name for name in connector_names), (
        f"MISP connector not found in OpenCTI. Registered connectors: {connector_names}"
    )
