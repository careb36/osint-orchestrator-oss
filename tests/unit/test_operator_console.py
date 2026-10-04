"""Unit tests for the minimal operator console route."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from orchestrator.api import app
from orchestrator.config import settings


def test_console_shell_is_reachable_from_a_browser_while_data_stays_protected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A browser cannot send X-API-Key on its first navigation. With a key
    configured the shell (no data) must load and show the key prompt, and
    every endpoint it fetches must still answer 401 without the key.
    """
    monkeypatch.setattr(settings, "orchestrator_api_key", "test-key")
    with TestClient(app, raise_server_exceptions=True) as client:
        shell = client.get("/console")
        catalogue = client.get("/console/i18n.json")
        data = client.get("/runs")
        trends = client.get("/analytics/risk-trends")
    assert shell.status_code == 200
    assert 'id="api-key-input"' in shell.text
    assert catalogue.status_code == 200
    assert data.status_code == 401
    assert trends.status_code == 401


def test_console_route_renders_html(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert 'id="skip-link"' in resp.text
    assert 'id="run-status-label"' in resp.text
    assert 'id="remember-key-toggle"' in resp.text
    assert 'id="auth-help"' in resp.text
    assert 'id="nav-risk"' in resp.text
    assert 'id="risk-table-wrap"' in resp.text
    assert "/console/i18n.json" in resp.text


def test_console_ships_a_nonce_csp_and_hardening_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    The console renders API data — run.error quotes collector/OpenCTI exception
    text that can carry internet-derived strings — into the origin that holds
    the operator's API key. The CSP allows only this response's inline
    script/style (by nonce) and nothing from elsewhere.
    """
    import re

    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console")
    assert resp.status_code == 200
    csp = resp.headers["content-security-policy"]
    nonce = re.search(r"script-src 'nonce-([A-Za-z0-9_-]+)'", csp)
    assert nonce, csp
    assert f'<script nonce="{nonce.group(1)}">' in resp.text
    assert f'<style nonce="{nonce.group(1)}">' in resp.text
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "'unsafe-inline'" not in csp
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"


def test_console_nonce_is_unique_per_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        first = client.get("/console").headers["content-security-policy"]
        second = client.get("/console").headers["content-security-policy"]
    assert first != second


def test_console_template_escapes_every_data_interpolation() -> None:
    """
    Static guard: any `${...}` rendered into innerHTML that does not come from
    the I18N catalogue must go through esc() (or encodeURIComponent for URL
    segments). A new interpolation of run.error, target.id, item.*, run.* or
    error.message added without it is a stored-XSS sink next to the API key.
    """
    import re
    from pathlib import Path

    src = Path("orchestrator/templates/console.html").read_text(encoding="utf-8")
    assert "function esc(" in src
    data_prefixes = (
        "run.",
        "target.",
        "item.",
        "error.",
        "delta.",
        "runId",
        "status",
        "newObs",
        "message",
    )
    offenders = []
    for lineno, line in enumerate(src.splitlines(), 1):
        for m in re.finditer(r"\$\{([^}]*)\}", line):
            expr = m.group(1).strip()
            if expr.startswith(("t(", "esc(", "encodeURIComponent(", "rows.join")):
                continue
            if "getElementById" in line or "apiGet(" in line or "new Error(" in line:
                continue
            if expr.startswith(data_prefixes):
                offenders.append(f"{lineno}: {line.strip()}")
    assert not offenders, "unescaped data interpolation(s):\n" + "\n".join(offenders)


def test_console_template_fetches_artifacts_with_api_key() -> None:
    from pathlib import Path

    src = Path("orchestrator/templates/console.html").read_text(encoding="utf-8")
    assert "apiFetch(`/runs/${encodeURIComponent(runId)}/${artifactType}`)" in src
    assert 'href="/runs/${encodeURIComponent(runId)}/report"' not in src
    assert 'href="/runs/${encodeURIComponent(runId)}/finding"' not in src
    assert 'data-artifact="evidence"' in src
    assert 'data-artifact="manifest"' in src
    assert "sessionStorage.setItem" in src
    assert "localStorage.setItem" not in src


def test_console_run_workspace_supports_evidence_search_filter_and_sort() -> None:
    from pathlib import Path

    src = Path("orchestrator/templates/console.html").read_text(encoding="utf-8")
    assert "renderEvidenceTable" in src
    assert "evidence-search" in src
    assert "evidence-category-filter" in src
    assert "evidence-relevance-filter" in src
    assert "evidence-sort" in src
    assert "loadRunArtifactPanel" in src


def test_console_i18n_endpoint_is_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console/i18n.json")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["es"]["pageTitle"]
    assert payload["en"]["pageTitle"]
