"""Unit tests for the minimal operator console route."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from orchestrator import api as api_module
from orchestrator.api import app
from orchestrator.config import settings


def test_console_shell_is_reachable_from_a_browser_while_data_stays_protected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    A browser cannot send X-API-Key on its first navigation. With a key
    configured the shell (no data) must load and show the key prompt, and
    every endpoint it fetches must still answer 401 without the key.
    """
    monkeypatch.setattr(settings, "orchestrator_api_key", "test-key")
    monkeypatch.setattr(api_module, "UI_DIST_DIR", tmp_path / "no-build")
    with TestClient(app, raise_server_exceptions=True) as client:
        shell = client.get("/console")
        legacy = client.get("/console/legacy")
        catalogue = client.get("/console/i18n.json")
        data = client.get("/runs")
        trends = client.get("/analytics/risk-trends")
    assert shell.status_code == 200
    # Without a dashboard build /console serves the legacy console itself.
    assert 'id="api-key-input"' in shell.text
    assert legacy.status_code == 200
    assert 'id="api-key-input"' in legacy.text
    assert catalogue.status_code == 200
    assert data.status_code == 401
    assert trends.status_code == 401


def test_console_route_renders_html(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console/legacy")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert 'id="skip-link"' in resp.text
    assert 'id="run-status-label"' in resp.text
    assert 'id="remember-key-toggle"' in resp.text
    assert 'id="auth-help"' in resp.text
    assert 'id="nav-risk"' in resp.text
    assert 'id="risk-table-wrap"' in resp.text
    assert "/console/i18n.json" in resp.text
    assert 'class="start-run-btn"' in resp.text


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
        resp = client.get("/console/legacy")
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
        first = client.get("/console/legacy").headers["content-security-policy"]
        second = client.get("/console/legacy").headers["content-security-policy"]
    assert first != second


def test_console_template_escapes_every_data_interpolation() -> None:
    """
    Static guard: any `${...}` rendered into innerHTML that does not come from
    the I18N catalogue must go through esc() (or encodeURIComponent for URL
    segments). A new interpolation of run.error, target.id, item.*, run.* or
    error.message added without it is a stored-XSS sink next to the API key.
    """
    import re

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
    src = Path("orchestrator/templates/console.html").read_text(encoding="utf-8")
    assert "apiFetch(`/runs/${encodeURIComponent(runId)}/${artifactType}`)" in src
    assert 'href="/runs/${encodeURIComponent(runId)}/report"' not in src
    assert 'href="/runs/${encodeURIComponent(runId)}/finding"' not in src
    assert 'data-artifact="evidence"' in src
    assert 'data-artifact="manifest"' in src
    assert "sessionStorage.setItem" in src
    assert "localStorage.setItem" not in src
    assert 'data-target-id="${esc(target.id)}"' in src
    assert "await startRun(targetId);" in src
    assert "sessionStorage.setItem(VIEW_STORAGE_KEY, viewName);" in src
    assert "const storedView = sessionStorage.getItem(VIEW_STORAGE_KEY);" in src
    assert "const storedRunId = sessionStorage.getItem(RUN_STORAGE_KEY);" in src
    assert "if (storedRunId) {" in src
    assert "loadRunDetail(storedRunId);" in src


def test_console_health_cards_include_recovery_hints() -> None:
    src = Path("orchestrator/templates/console.html").read_text(encoding="utf-8")
    assert "check.recovery || check.hint || check.action || check.detail" in src
    assert "healthAction" in src
    assert "Recommended action" in Path("orchestrator/i18n.py").read_text(encoding="utf-8")


def test_console_run_workspace_supports_evidence_search_filter_and_sort() -> None:
    src = Path("orchestrator/templates/console.html").read_text(encoding="utf-8")
    assert "renderEvidenceTable" in src
    assert "wireEvidenceTableControls" in src
    assert "evidence-search" in src
    assert "evidence-category-filter" in src
    assert "evidence-relevance-filter" in src
    assert "evidence-sort" in src
    assert 'searchInput.addEventListener("input"' in src
    assert 'categorySelect.addEventListener("change"' in src
    assert 'relevanceSelect.addEventListener("change"' in src
    assert 'sortSelect.addEventListener("change"' in src
    assert "loadRunArtifactPanel" in src


def test_console_i18n_endpoint_is_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console/i18n.json")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["es"]["pageTitle"]
    assert payload["en"]["pageTitle"]


def test_console_keyboard_enter_shortcuts_are_wired() -> None:
    src = Path("orchestrator/templates/console.html").read_text(encoding="utf-8")
    assert 'document.getElementById("api-key-input").addEventListener("keydown"' in src
    assert 'if (event.key === "Enter")' in src
    assert 'document.getElementById("save-key-btn").click();' in src
    assert 'document.getElementById("run-id-input").addEventListener("keydown"' in src
    assert 'document.getElementById("load-run-btn").click();' in src


def test_console_template_records_actionable_frontend_telemetry() -> None:
    """Browser-side telemetry must expose event, path and message context for debugging."""
    src = (Path(__file__).resolve().parents[2] / "orchestrator/templates/console.html").read_text(
        encoding="utf-8"
    )
    assert "recordUiTelemetry" in src
    assert 'window.addEventListener("error"' in src
    assert 'window.addEventListener("unhandledrejection"' in src
    assert "ui-telemetry" in src
    assert "path: window.location.pathname" in src
    assert "truncateTelemetryText" in src
    assert "rawReason instanceof Error" in src
    assert "rawReason.message || rawReason.name || reasonText" in src


# --- React dashboard build served under /console ---------------------------


@pytest.fixture
def ui_build(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A fake `npm run build` output wired in as the dashboard build."""
    dist = tmp_path / "ui-dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text(
        "<!doctype html><html><head>"
        '<script type="module" crossorigin src="/console/assets/index-abc123.js"></script>'
        '<link rel="stylesheet" crossorigin href="/console/assets/index-abc123.css">'
        '</head><body><div id="root"></div></body></html>',
        encoding="utf-8",
    )
    (assets / "index-abc123.js").write_text("console.log('dashboard');", encoding="utf-8")
    (assets / "index-abc123.css").write_text("body{margin:0}", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")
    monkeypatch.setattr(api_module, "UI_DIST_DIR", dist)
    monkeypatch.setattr(settings, "orchestrator_api_key", "test-key")
    return dist


def test_console_serves_the_dashboard_build_when_installed(ui_build: Path) -> None:
    with TestClient(app, raise_server_exceptions=True) as client:
        shell = client.get("/console")
        data = client.get("/targets")
    assert shell.status_code == 200
    assert "text/html" in shell.headers["content-type"]
    assert '<div id="root"></div>' in shell.text
    assert "/console/assets/index-abc123.js" in shell.text
    assert 'id="api-key-input"' not in shell.text
    # The shell is public but carries no data; the API still wants the key.
    assert data.status_code == 401


def test_console_dashboard_csp_allows_only_same_origin_bundles(ui_build: Path) -> None:
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console")
    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "'unsafe-inline'" not in csp
    assert "nonce-" not in csp
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"
    # The CSP only holds if the build has no inline script to allow.
    assert "<script>" not in resp.text


def test_console_assets_are_served_immutable(ui_build: Path) -> None:
    with TestClient(app, raise_server_exceptions=True) as client:
        script = client.get("/console/assets/index-abc123.js")
        style = client.get("/console/assets/index-abc123.css")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert script.text == "console.log('dashboard');"
    assert script.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert script.headers["x-content-type-options"] == "nosniff"
    assert style.status_code == 200
    assert "text/css" in style.headers["content-type"]


def test_console_assets_do_not_escape_the_build_directory(ui_build: Path) -> None:
    # A literal ".." is collapsed by the client before it is sent; the encoded
    # forms reach the handler as a path segment and must be refused there.
    with TestClient(app, raise_server_exceptions=True) as client:
        encoded = client.get("/console/assets/..%2F..%2Foutside.txt")
        dotted = client.get("/console/assets/%2e%2e/%2e%2e/outside.txt")
        index = client.get("/console/assets/..%2Findex.html")
        missing = client.get("/console/assets/nope.js")
    assert encoded.status_code == 404
    assert dotted.status_code == 404
    assert index.status_code == 404
    assert missing.status_code == 404
    assert "secret" not in encoded.text + dotted.text


def test_console_client_routes_get_the_shell(ui_build: Path) -> None:
    """Deep links and reloads land on the SPA; the router renders the view."""
    with TestClient(app, raise_server_exceptions=True) as client:
        targets = client.get("/console/targets")
        run = client.get("/console/runs/42")
    assert targets.status_code == 200
    assert '<div id="root"></div>' in targets.text
    assert targets.headers["content-security-policy"] == run.headers["content-security-policy"]
    assert run.status_code == 200


def test_console_client_routes_are_404_without_a_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(api_module, "UI_DIST_DIR", tmp_path / "no-build")
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console/targets")
        legacy = client.get("/console/legacy")
        catalogue = client.get("/console/i18n.json")
    assert resp.status_code == 404
    assert legacy.status_code == 200
    assert catalogue.status_code == 200


def test_console_legacy_stays_available_next_to_the_dashboard(ui_build: Path) -> None:
    with TestClient(app, raise_server_exceptions=True) as client:
        legacy = client.get("/console/legacy")
        catalogue = client.get("/console/i18n.json")
    assert legacy.status_code == 200
    assert 'id="api-key-input"' in legacy.text
    assert "nonce-" in legacy.headers["content-security-policy"]
    assert catalogue.status_code == 200
