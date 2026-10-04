"""
Tests for orchestrator.logging_config — structured logs and request ids (Phase 5).
"""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient

from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.logging_config import (
    JsonFormatter,
    RequestIdFilter,
    build_handler,
    configure_logging,
    request_id_var,
)


def _record(msg: str = "hello %s", args=("world",), **extra) -> logging.LogRecord:
    record = logging.LogRecord("orchestrator.test", logging.INFO, "x.py", 1, msg, args, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


@pytest.fixture(autouse=True)
def _restore_root_logging():
    """configure_logging replaces the root handlers; put them back for pytest."""
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


# ── JSON shape ───────────────────────────────────────────────────────────────


def test_json_formatter_emits_one_object_with_stable_keys() -> None:
    line = JsonFormatter().format(_record())
    payload = json.loads(line)
    assert "\n" not in line
    assert payload["level"] == "INFO"
    assert payload["logger"] == "orchestrator.test"
    assert payload["msg"] == "hello world"
    assert payload["ts"].endswith("Z")
    assert "request_id" not in payload  # none bound outside a request


def test_json_formatter_promotes_extra_fields() -> None:
    payload = json.loads(JsonFormatter().format(_record(target_id="acme", run_id=7)))
    assert payload["target_id"] == "acme"
    assert payload["run_id"] == 7


def test_json_formatter_extras_cannot_clobber_stable_keys() -> None:
    """An extra named `level` must not replace the real log level."""
    record = _record(level="CRITICAL", ts="1970-01-01", logger="forged", request_id="forged")
    payload = json.loads(JsonFormatter().format(record))
    assert payload["level"] == "INFO"
    assert payload["logger"] == "orchestrator.test"
    assert payload["ts"] != "1970-01-01"
    assert "request_id" not in payload  # reserved: never promoted from extras
    assert payload["extra_level"] == "CRITICAL"
    assert payload["extra_ts"] == "1970-01-01"
    assert payload["extra_logger"] == "forged"


def test_json_formatter_never_raises_on_unserialisable_extra(tmp_path) -> None:
    from datetime import UTC, datetime

    payload = json.loads(
        JsonFormatter().format(_record(when=datetime(2026, 9, 8, tzinfo=UTC), where=tmp_path))
    )
    assert payload["when"].startswith("2026-09-08")
    assert payload["where"] == str(tmp_path)


def test_json_formatter_includes_traceback() -> None:
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        record = _record("failed", args=())
        record.exc_info = sys.exc_info()
    payload = json.loads(JsonFormatter().format(record))
    assert "ValueError: boom" in payload["exc"]


def test_request_id_reaches_both_formats() -> None:
    token = request_id_var.set("req-123")
    try:
        record = _record()
        assert RequestIdFilter().filter(record)
        assert json.loads(JsonFormatter().format(record))["request_id"] == "req-123"
        text = build_handler("text").formatter.format(record)
        assert "[req-123]" in text
    finally:
        request_id_var.reset(token)


def test_text_format_shows_dash_outside_requests() -> None:
    record = _record()
    RequestIdFilter().filter(record)
    assert "[-]" in build_handler("text").formatter.format(record)


# ── configure_logging ────────────────────────────────────────────────────────


def test_configure_logging_installs_single_root_handler_from_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "orchestrator_log_format", "json")
    monkeypatch.setattr(settings, "orchestrator_log_level", "debug")
    configure_logging()
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)
    assert root.level == logging.DEBUG
    # uvicorn's loggers must not keep their own (text) handlers.
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        assert logging.getLogger(name).handlers == []
        assert logging.getLogger(name).propagate


def test_configure_logging_is_idempotent() -> None:
    configure_logging(level="INFO", log_format="text")
    configure_logging(level="INFO", log_format="text")
    assert len(logging.getLogger().handlers) == 1


def test_invalid_level_and_format_fall_back_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configure_logging(level="LOUD", log_format="xml")
    root = logging.getLogger()
    assert root.level == logging.INFO
    assert not isinstance(root.handlers[0].formatter, JsonFormatter)


# ── Middleware ───────────────────────────────────────────────────────────────


def test_response_carries_a_request_id() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert len(resp.headers["X-Request-ID"]) == 16


def test_caller_supplied_request_id_is_echoed_and_capped() -> None:
    client = TestClient(app)
    assert (
        client.get("/health", headers={"X-Request-ID": "trace-abc"}).headers["X-Request-ID"]
        == "trace-abc"
    )
    long_id = "x" * 500
    assert (
        len(client.get("/health", headers={"X-Request-ID": long_id}).headers["X-Request-ID"]) == 64
    )


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"trace-abc", "trace-abc"),
        (b"bad\r\nX-Injected: 1", "badX-Injected:1"),  # CR/LF and spaces dropped
        (b"tab\tsep", "tabsep"),
        ("caf\u00e9-\u00fc".encode(), "caf-"),  # non-ASCII bytes dropped
        (b"\xff\xfe", None),  # nothing printable left → fresh id
        (b"", None),
        (None, None),
    ],
)
def test_sanitize_request_id(raw: bytes | None, expected: str | None) -> None:
    from orchestrator.api import sanitize_request_id

    result = sanitize_request_id(raw)
    if expected is None:
        assert len(result) == 16 and result.isalnum()
    else:
        assert result == expected


def test_hostile_request_id_never_breaks_the_response() -> None:
    """Non-UTF-8 bytes must not turn into a 500, and CR/LF must not be echoed."""
    client = TestClient(app)
    # httpx refuses to send raw CR/LF in a header value, so exercise the
    # middleware directly for the injection case and the client for latin-1.
    resp = client.get("/health", headers={b"X-Request-ID": "caf\u00e9".encode("latin-1")})
    assert resp.status_code == 200
    assert resp.headers["X-Request-ID"] == "caf"

    from orchestrator.api import RequestContextMiddleware

    captured: dict = {}

    async def _app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def _send(message):
        if message["type"] == "http.response.start":
            captured["headers"] = message["headers"]

    async def _receive():
        return {"type": "http.request"}

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/health",
        "headers": [(b"x-request-id", b"evil\r\nSet-Cookie: x=1\xff")],
    }
    import asyncio

    asyncio.run(RequestContextMiddleware(_app)(scope, _receive, _send))
    echoed = dict(captured["headers"])[b"x-request-id"]
    assert echoed == b"evilSet-Cookie:x=1"
    assert b"\r" not in echoed and b"\n" not in echoed


def test_request_id_is_bound_while_handling(caplog: pytest.LogCaptureFixture) -> None:
    seen: list[str | None] = []

    @app.get("/_test_request_id", include_in_schema=False)
    async def _probe() -> dict:
        seen.append(request_id_var.get())
        return {}

    try:
        client = TestClient(app)
        client.get("/_test_request_id", headers={"X-Request-ID": "bound-1"})
        assert seen == ["bound-1"]
        assert request_id_var.get() is None  # reset after the request
    finally:
        app.router.routes[:] = [
            r for r in app.router.routes if getattr(r, "path", "") != "/_test_request_id"
        ]
