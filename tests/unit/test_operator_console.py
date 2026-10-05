"""Unit tests for the operator dashboard routes (/console)."""

from __future__ import annotations

import re
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
    configured the shell (no data) must answer, and every endpoint it fetches
    must still answer 401 without the key.
    """
    monkeypatch.setattr(settings, "orchestrator_api_key", "test-key")
    monkeypatch.setattr(api_module, "UI_DIST_DIR", tmp_path / "no-build")
    with TestClient(app, raise_server_exceptions=True) as client:
        shell = client.get("/console")
        data = client.get("/runs")
        trends = client.get("/analytics/risk-trends")
    assert shell.status_code != 401
    assert data.status_code == 401
    assert trends.status_code == 401


def test_console_without_a_build_is_a_503_with_build_instructions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A deployment without the dashboard is an error a probe should notice."""
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    monkeypatch.setattr(api_module, "UI_DIST_DIR", tmp_path / "no-build")
    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/console")
    assert resp.status_code == 503
    assert "text/html" in resp.headers["content-type"]
    assert resp.headers["retry-after"] == "60"
    assert "npm run build" in resp.text
    assert "orchestrator/static/ui-dist" in resp.text
    assert "<script" not in resp.text
    csp = resp.headers["content-security-policy"]
    nonce = re.search(r"style-src 'nonce-([A-Za-z0-9_-]+)'", csp)
    assert nonce, csp
    assert f'<style nonce="{nonce.group(1)}">' in resp.text
    assert "default-src 'none'" in csp
    assert "script-src" not in csp
    # Same directive set as the shell's CSP apart from the script/style sources.
    for directive in (
        "connect-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "frame-ancestors 'none'",
    ):
        assert directive in csp
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"


def test_console_shell_and_missing_build_share_the_hardening_headers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ui_build: Path
) -> None:
    """Only the CSP (bundle vs. no script) and Retry-After may differ between the two branches."""
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        shell = client.get("/console")
        monkeypatch.setattr(api_module, "UI_DIST_DIR", tmp_path / "no-build")
        missing = client.get("/console")
    assert shell.status_code == 200
    assert missing.status_code == 503
    shared = ("x-content-type-options", "referrer-policy", "cache-control")
    for header in shared:
        assert shell.headers[header] == missing.headers[header], header
    assert "retry-after" not in shell.headers
    assert missing.headers["retry-after"] == "60"
    assert "script-src 'self'" in shell.headers["content-security-policy"]
    assert "script-src" not in missing.headers["content-security-policy"]


def test_console_missing_build_page_follows_the_operator_language(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    monkeypatch.setattr(api_module, "UI_DIST_DIR", tmp_path / "no-build")
    with TestClient(app, raise_server_exceptions=True) as client:
        monkeypatch.setattr(settings, "orchestrator_language", "es")
        spanish = client.get("/console")
        monkeypatch.setattr(settings, "orchestrator_language", "en")
        english = client.get("/console")
    assert 'lang="es"' in spanish.text
    assert "no está instalado" in spanish.text
    assert 'lang="en"' in english.text
    assert "is not installed" in english.text


def test_legacy_console_routes_are_gone(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The server-rendered console and its catalogue were retired with the React dashboard."""
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    monkeypatch.setattr(api_module, "UI_DIST_DIR", tmp_path / "no-build")
    with TestClient(app, raise_server_exceptions=True) as client:
        legacy = client.get("/console/legacy")
        catalogue = client.get("/console/i18n.json")
    assert legacy.status_code == 404
    assert catalogue.status_code == 404
    assert not (Path(api_module.__file__).parent / "templates" / "console.html").exists()


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
    assert resp.status_code == 404


def test_console_assets_keep_their_content_type_next_to_the_catch_all(ui_build: Path) -> None:
    """The fixed routes keep their own payloads: the catch-all must not shadow them."""
    with TestClient(app, raise_server_exceptions=True) as client:
        script = client.get("/console/assets/index-abc123.js")
        shell = client.get("/console/targets")
    assert script.status_code == 200
    assert "javascript" in script.headers["content-type"]
    assert '<div id="root">' not in script.text
    assert "text/html" in shell.headers["content-type"]


def test_console_catch_all_refuses_file_like_paths(ui_build: Path) -> None:
    """A stale or mistyped asset link is a miss, not a 200 shell."""
    with TestClient(app, raise_server_exceptions=True) as client:
        typo_dir = client.get("/console/asset/index-abc123.js")
        typo_file = client.get("/console/i18n.jso")
        favicon = client.get("/console/favicon.ico")
        stray = client.get("/console/report.md")
        views = [
            client.get("/console/targets/example.com"),
            client.get("/console/targets/notes.md"),
            client.get("/console/targets/logo.svg/runs/3"),
            client.get("/console/runs/42"),
        ]
    assert typo_dir.status_code == 404
    assert typo_file.status_code == 404
    assert favicon.status_code == 404
    assert stray.status_code == 404
    # Under the router's own prefixes everything is a view: target ids may end
    # in what looks like a file extension (orchestrator/models.py::_TARGET_ID_RE
    # allows ``notes.md``), so the suffix check must not apply there.
    for view in views:
        assert view.status_code == 200, view.url
        assert '<div id="root"></div>' in view.text
