"""
Unit tests for Phase 4a: alerts, Issue #8, Issue #10.

Tests run without network access:
- Webhook: schema, HMAC, single-shot on 503/400, timeout → failed, run not failed
- Email: mock smtplib, subject language, multiple recipients
- Dispatch rules: various combinations
- include_values=False → no values in payload
- Channel not configured → skipped
- Issue #8: sink that fails → second run re-marks as new
- Issue #10: GET /runs/{id}/delta returns is_new rows
- Extended pipeline test: fake notifier fires only when it should
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import smtplib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from pytest_httpx import HTTPXMock
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator.alerts import (
    AlertEvent,
    AlertObservable,
    EmailNotifier,
    WebhookNotifier,
    build_notifiers,
    should_alert,
)
from orchestrator.models import (
    AlertRecord,
    AlertStatus,
    CollectorName,
    CollectorResult,
    Observable,
    Run,
    RunObservable,
    RunStatus,
    SeenObservable,
    Target,
)
from orchestrator.pipeline import get_run_delta, run_target_pipeline

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_engine():
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


async def _setup_db(engine):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    return _session


def _make_target(**kwargs) -> Target:
    defaults = dict(
        id="test-target",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
    )
    defaults.update(kwargs)
    return Target(**defaults)


def _make_event(**kwargs) -> AlertEvent:
    defaults = dict(
        target_id="test-target",
        target_fqdn="example.com",
        run_id=1,
        run_status="success",
        risk_level="high",
        new_observables=[
            AlertObservable(
                stix_type="domain-name", value="example.com", stix_id="domain-name--abc"
            )
        ],
        new_observable_count=1,
        report_path=None,
        finding_summary="Test finding",
        generated_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
    )
    defaults.update(kwargs)
    return AlertEvent(**defaults)


# ─── Webhook tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_sends_correct_schema_and_hmac(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=200)
    notifier = WebhookNotifier(url="http://hook.test/alert", secret="mysecret", timeout=5)
    event = _make_event()
    await notifier.send(event)

    request = httpx_mock.get_requests()[0]
    body = request.content
    payload = json.loads(body)

    # Schema check
    assert payload["target_id"] == "test-target"
    assert payload["target_fqdn"] == "example.com"
    assert payload["run_id"] == 1
    assert payload["risk_level"] == "high"
    assert payload["new_observable_count"] == 1
    assert isinstance(payload["new_observables"], list)
    obs = payload["new_observables"][0]
    assert obs["stix_type"] == "domain-name"
    assert obs["value"] == "example.com"

    # HMAC check
    sig_header = request.headers["x-orchestrator-signature"]
    expected = "sha256=" + hmac.new(b"mysecret", body, hashlib.sha256).hexdigest()
    assert sig_header == expected


@pytest.mark.asyncio
async def test_webhook_is_single_shot_on_503(httpx_mock: HTTPXMock) -> None:
    """
    The notifier makes exactly one request and raises; the persistent alert
    delivery queue owns retries. With both retrying, one alert could go out
    3 × ALERT_RETRY_MAX_ATTEMPTS times on two different backoff curves.
    """
    import httpx

    httpx_mock.add_response(status_code=503)

    notifier = WebhookNotifier(url="http://hook.test/alert", secret="s", timeout=5)

    with pytest.raises(httpx.HTTPStatusError, match="HTTP 503"):
        await notifier.send(_make_event())

    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_webhook_no_retry_on_400(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(status_code=400)

    notifier = WebhookNotifier(url="http://hook.test/alert", secret="s", timeout=5)
    import httpx

    with pytest.raises(httpx.HTTPStatusError):
        await notifier.send(_make_event())

    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_webhook_timeout_records_failed_not_run_failed(
    tmp_path: Path,
    httpx_mock: HTTPXMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the webhook times out the alert is recorded as failed but run stays SUCCESS."""
    import httpx as _httpx

    import orchestrator.alerts as alerts_mod

    httpx_mock.add_exception(_httpx.TimeoutException("timed out"))

    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])
    # Patch the alerts module's get_session too (used by _dispatch_alerts)
    monkeypatch.setattr("orchestrator.pipeline.get_session", session_ctx)

    async def _no_synth(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synth)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    # Patch settings in the alerts module directly (it's bound at import time)
    alerts_mod._WEBHOOK_WARNING_LOGGED = False
    alerts_mod._EMAIL_WARNING_LOGGED = False

    fake_settings = _PatchedSettings(alert_webhook_url="http://hook.test/alert")
    monkeypatch.setattr(alerts_mod, "settings", fake_settings)

    target = _make_target(report_dir=str(tmp_path))

    async with session_ctx() as session:
        run = Run(
            target_id=target.id,
            started_at=datetime.now(UTC),
            status=RunStatus.PENDING,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await run_target_pipeline(target, run_id)

    async with session_ctx() as session:
        run_db = await session.get(Run, run_id)
        assert run_db is not None
        # Run is NOT failed even though webhook timed out
        assert run_db.status == RunStatus.SUCCESS

        alerts = (await session.exec(select(AlertRecord).where(AlertRecord.run_id == run_id))).all()
        assert any(a.status == AlertStatus.FAILED for a in alerts)


# ─── Email tests ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_email_spanish_subject_and_multiple_recipients() -> None:
    sent: list[dict] = []

    class _FakeSMTP:
        def __init__(self, host, port, timeout=None):
            assert timeout is not None, "SMTP must be opened with a timeout"
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def ehlo(self):
            pass

        def starttls(self, context=None):
            pass

        def login(self, user, pw):
            pass

        def sendmail(self, from_addr, to_addrs, msg):
            sent.append({"from": from_addr, "to": to_addrs, "msg": msg})

    with patch.object(smtplib, "SMTP", _FakeSMTP):
        notifier = EmailNotifier(
            host="smtp.test",
            port=587,
            user="u",
            password="p",
            from_addr="from@test.com",
            to_addrs=["a@test.com", "b@test.com"],
            starttls=True,
            language="es",
        )
        await notifier.send(_make_event())

    assert len(sent) == 1
    assert sent[0]["to"] == ["a@test.com", "b@test.com"]
    import email as _email
    from email.header import decode_header

    msg_obj = _email.message_from_string(sent[0]["msg"])
    subject_parts = decode_header(msg_obj["Subject"])
    subject = "".join(
        part.decode(enc or "utf-8") if isinstance(part, bytes) else part
        for part, enc in subject_parts
    )
    assert "Alerta OSINT" in subject
    assert subject.find("example.com") >= 0
    # The risk level is a stable English identifier in the event; the reader
    # gets its label.
    assert "riesgo alto (high)" in subject
    body = msg_obj.get_payload(decode=True).decode("utf-8")
    assert "Riesgo    : alto (high)" in body
    assert "Estado    : exitosa (success)" in body
    # Local date with the UTC instant beside it (UTC here: no zone configured).
    assert re.search(r"Generado  : \d\d/\d\d/\d{4} \d\d:\d\d UTC \(\d{4}-\d\d-\d\dT", body)


@pytest.mark.asyncio
async def test_email_english_subject() -> None:
    sent: list[dict] = []

    class _FakeSMTP:
        def __init__(self, h, p, timeout=None):
            assert timeout is not None, "SMTP must be opened with a timeout"
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def ehlo(self):
            pass

        def starttls(self, context=None):
            pass

        def login(self, u, pw):
            pass

        def sendmail(self, f, t, m):
            sent.append(m)

    with patch.object(smtplib, "SMTP", _FakeSMTP):
        notifier = EmailNotifier(
            host="smtp.test",
            port=587,
            user="u",
            password="p",
            from_addr="f@test.com",
            to_addrs=["x@test.com"],
            starttls=True,
            language="en",
        )
        await notifier.send(_make_event())

    assert len(sent) == 1
    import email as _email
    from email.header import decode_header

    msg_obj = _email.message_from_string(sent[0])
    subject_parts = decode_header(msg_obj["Subject"])
    subject = "".join(
        part.decode(enc or "utf-8") if isinstance(part, bytes) else part
        for part, enc in subject_parts
    )
    assert "OSINT Alert" in subject


# ─── Dispatch rules ───────────────────────────────────────────────────────────


def test_should_alert_no_new_medium_risk_does_not_alert():
    assert not should_alert(
        new_observable_count=0,
        risk_level="medium",
        on_new_observables=True,
        min_risk_level="high",
    )


def test_should_alert_critical_no_new_does_alert():
    assert should_alert(
        new_observable_count=0,
        risk_level="critical",
        on_new_observables=True,
        min_risk_level="high",
    )


def test_should_alert_new_observables_triggers():
    assert should_alert(
        new_observable_count=3,
        risk_level="low",
        on_new_observables=True,
        min_risk_level="high",
    )


def test_should_alert_high_risk_no_new():
    assert should_alert(
        new_observable_count=0,
        risk_level="high",
        on_new_observables=True,
        min_risk_level="high",
    )


# ─── include_values=False ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_include_values_false_omits_observable_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])

    async def _no_synth(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synth)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    received_events: list[AlertEvent] = []

    class _FakeNotifier:
        channel = "test"

        async def send(self, event: AlertEvent) -> None:
            received_events.append(event)

    import orchestrator.alerts as alerts_mod

    monkeypatch.setattr(alerts_mod, "build_notifiers", lambda language=None: [_FakeNotifier()])

    from orchestrator.models import AlertsConfig

    target = _make_target(
        report_dir=str(tmp_path),
        alerts=AlertsConfig(include_values=False, on_new_observables=True),
    )

    async with session_ctx() as session:
        run = Run(target_id=target.id, started_at=datetime.now(UTC), status=RunStatus.PENDING)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    await run_target_pipeline(target, run_id)

    assert len(received_events) == 1
    ev = received_events[0]
    assert ev.new_observable_count >= 1
    assert ev.new_observables == []  # values omitted


# ─── Channel not configured → skipped ────────────────────────────────────────


def test_unconfigured_channel_skipped_with_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    import orchestrator.alerts as alerts_mod

    # Reset flags
    alerts_mod._WEBHOOK_WARNING_LOGGED = False
    alerts_mod._EMAIL_WARNING_LOGGED = False

    monkeypatch.setattr("orchestrator.config.settings.alert_webhook_url", "")
    monkeypatch.setattr("orchestrator.config.settings.alert_smtp_host", "")
    monkeypatch.setattr("orchestrator.config.settings.alert_email_to", "")

    import logging

    with patch.object(logging.Logger, "warning") as mock_warn:
        notifiers = build_notifiers()

    assert notifiers == []
    assert mock_warn.call_count >= 2


def test_email_notifier_is_built_when_smtp_is_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchestrator.config.settings.alert_webhook_url", "")
    monkeypatch.setattr("orchestrator.config.settings.alert_smtp_host", "smtp.example.com")
    monkeypatch.setattr("orchestrator.config.settings.alert_smtp_port", 587)
    monkeypatch.setattr("orchestrator.config.settings.alert_smtp_user", "ops")
    monkeypatch.setattr("orchestrator.config.settings.alert_smtp_password", "secret")
    monkeypatch.setattr("orchestrator.config.settings.alert_smtp_from", "alerts@example.com")
    monkeypatch.setattr("orchestrator.config.settings.alert_email_to", "team@example.com")

    notifiers = build_notifiers()

    assert len(notifiers) == 1
    assert isinstance(notifiers[0], EmailNotifier)
    assert notifiers[0]._host == "smtp.example.com"
    assert notifiers[0]._user == "ops"
    assert notifiers[0]._password == "secret"


# ─── Issue #8: sink failure → second run re-marks as new ─────────────────────


class _FakeCollector:
    name = CollectorName.OPENOSINT

    def __init__(self, target: Target) -> None:
        self.target = target

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[
                Observable(type="domain-name", value=self.target.fqdn),
            ],
            success=True,
        )


@pytest.mark.asyncio
async def test_issue8_sink_failure_reraises_on_second_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When OpenCTI ingest fails for the first run, observables must NOT be
    inserted into SeenObservable. The second run should mark them as new again
    and successfully ingest them.
    """
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])

    async def _no_synth(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synth)

    call_count = {"n": 0}

    class _FailFirstSink:
        async def ingest_async(self, bundle, *, work_name="", target_id=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("OpenCTI unavailable")

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _FailFirstSink)

    import orchestrator.alerts as alerts_mod

    monkeypatch.setattr(alerts_mod, "build_notifiers", lambda language=None: [])

    target = _make_target(report_dir=str(tmp_path))

    async def _make_run() -> int:
        async with session_ctx() as session:
            run = Run(target_id=target.id, started_at=datetime.now(UTC), status=RunStatus.PENDING)
            session.add(run)
            await session.commit()
            await session.refresh(run)
            assert run.id is not None
            return run.id

    # First run: ingest fails → observables should NOT be in SeenObservable
    run1_id = await _make_run()
    await run_target_pipeline(target, run1_id)

    async with session_ctx() as session:
        seen = (await session.exec(select(SeenObservable))).all()
        assert len(seen) == 0, "SeenObservable must be empty when ingest failed"

        r1_obs = (
            await session.exec(select(RunObservable).where(RunObservable.run_id == run1_id))
        ).all()
        assert len(r1_obs) == 1
        assert r1_obs[0].is_new is True
        assert r1_obs[0].ingested is False

    # Second run: ingest succeeds → observables should be new AND ingested
    run2_id = await _make_run()
    await run_target_pipeline(target, run2_id)

    async with session_ctx() as session:
        seen_after = (await session.exec(select(SeenObservable))).all()
        assert len(seen_after) == 1, "SeenObservable must be populated after successful ingest"

        r2_obs = (
            await session.exec(select(RunObservable).where(RunObservable.run_id == run2_id))
        ).all()
        assert len(r2_obs) == 1
        assert r2_obs[0].is_new is True
        assert r2_obs[0].ingested is True

        run2 = await session.get(Run, run2_id)
        assert run2 is not None
        assert run2.new_observables == 1


# ─── Issue #10: GET /runs/{id}/delta ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_run_delta_returns_only_new_observables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)

    async with session_ctx() as session:
        session.add(
            RunObservable(
                run_id=5,
                stix_id="a",
                stix_type="domain-name",
                value="a.com",
                is_new=True,
                ingested=True,
            )
        )
        session.add(
            RunObservable(
                run_id=5,
                stix_id="b",
                stix_type="ipv4-addr",
                value="1.2.3.4",
                is_new=False,
                ingested=True,
            )
        )
        session.add(
            RunObservable(
                run_id=5, stix_id="c", stix_type="url", value="http://x", is_new=True, ingested=True
            )
        )
        await session.commit()

    delta = await get_run_delta(5)
    assert len(delta) == 2
    values = {d["value"] for d in delta}
    assert values == {"a.com", "http://x"}


@pytest.mark.asyncio
async def test_api_delta_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi.testclient import TestClient

    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)

    # Patch api module's get_session
    import orchestrator.api as api_mod

    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)

    async with session_ctx() as session:
        run = Run(target_id="t", started_at=datetime.now(UTC), status=RunStatus.SUCCESS)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id
        session.add(
            RunObservable(
                run_id=run_id,
                stix_id="x",
                stix_type="domain-name",
                value="x.com",
                is_new=True,
                ingested=True,
            )
        )
        session.add(
            RunObservable(
                run_id=run_id,
                stix_id="y",
                stix_type="url",
                value="http://y",
                is_new=False,
                ingested=True,
            )
        )
        await session.commit()

    from orchestrator.api import app

    client = TestClient(app, raise_server_exceptions=True)
    resp = client.get(f"/runs/{run_id}/delta")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["value"] == "x.com"


# ─── Extended pipeline test with fake notifier ────────────────────────────────


class _PatchedSettings:
    """Minimal settings replacement for alert channel tests."""

    def __init__(self, alert_webhook_url: str = ""):
        # Copy real settings values

        from orchestrator.config import settings

        # Copy declared settings only. dir() also walks pydantic's deprecated
        # instance-level `model_computed_fields`, which warns on access.
        for attr in type(settings).model_fields:
            setattr(self, attr, getattr(settings, attr))
        self.alert_webhook_url = alert_webhook_url
        self.alert_smtp_host = ""
        self.alert_email_to = ""


@pytest.mark.asyncio
async def test_pipeline_alert_fires_only_when_conditions_met(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First run: new observables → alert fires. Second run: no new → no alert."""
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])

    async def _no_synth(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synth)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    sent: list[AlertEvent] = []

    class _FakeNotifier:
        channel = "test"

        async def send(self, event: AlertEvent) -> None:
            sent.append(event)

    import orchestrator.alerts as alerts_mod

    monkeypatch.setattr(alerts_mod, "build_notifiers", lambda language=None: [_FakeNotifier()])

    target = _make_target(report_dir=str(tmp_path))

    async def _make_run() -> int:
        async with session_ctx() as session:
            run = Run(target_id=target.id, started_at=datetime.now(UTC), status=RunStatus.PENDING)
            session.add(run)
            await session.commit()
            await session.refresh(run)
            return run.id

    run1 = await _make_run()
    await run_target_pipeline(target, run1)
    assert len(sent) == 1  # new observables in first run

    run2 = await _make_run()
    await run_target_pipeline(target, run2)
    assert len(sent) == 1  # no new observables in second run


# ─── Point 1: get_run_delta excludes not-ingested rows ───────────────────────


@pytest.mark.asyncio
async def test_get_run_delta_excludes_not_ingested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_run_delta must filter is_new=True AND ingested=True."""
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)

    async with session_ctx() as session:
        # is_new=True, ingested=True → should appear
        session.add(
            RunObservable(
                run_id=7,
                stix_id="a",
                stix_type="domain-name",
                value="a.com",
                is_new=True,
                ingested=True,
            )
        )
        # is_new=True, ingested=False → must NOT appear
        session.add(
            RunObservable(
                run_id=7,
                stix_id="b",
                stix_type="domain-name",
                value="b.com",
                is_new=True,
                ingested=False,
            )
        )
        # is_new=False, ingested=True → must NOT appear
        session.add(
            RunObservable(
                run_id=7,
                stix_id="c",
                stix_type="domain-name",
                value="c.com",
                is_new=False,
                ingested=True,
            )
        )
        await session.commit()

    delta = await get_run_delta(7)
    assert len(delta) == 1
    assert delta[0]["value"] == "a.com"


# ─── Point 2: build_notifiers raises → run intact ────────────────────────────


@pytest.mark.asyncio
async def test_dispatch_alerts_build_notifiers_raises_run_intact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception in build_notifiers must not change run status; Run.error gets 'alerts:' prefix."""
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])
    monkeypatch.setattr(pipeline_module, "synthesize", AsyncMock(return_value=(None, "skipped")))
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    import orchestrator.alerts as alerts_mod

    def _boom(language=None):
        raise RuntimeError("notifier configuration exploded")

    monkeypatch.setattr(alerts_mod, "build_notifiers", _boom)

    target = _make_target(report_dir=str(tmp_path))

    async with session_ctx() as session:
        run = Run(target_id=target.id, started_at=datetime.now(UTC), status=RunStatus.PENDING)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    await run_target_pipeline(target, run_id)

    async with session_ctx() as session:
        run_db = await session.get(Run, run_id)
        assert run_db is not None
        assert run_db.status == RunStatus.SUCCESS, "Run must not be failed due to alert error"
        assert run_db.error is not None and "alerts:" in run_db.error


# ─── Point 3: empty webhook secret → no signature header ─────────────────────


@pytest.mark.asyncio
async def test_webhook_no_secret_omits_signature_header(
    httpx_mock: HTTPXMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ALERT_WEBHOOK_SECRET is empty, the signature header must be absent."""
    import orchestrator.alerts as alerts_mod

    alerts_mod._WEBHOOK_NO_SECRET_LOGGED = False
    httpx_mock.add_response(status_code=200)

    notifier = WebhookNotifier(url="http://hook.test/alert", secret="", timeout=5)
    import logging

    with patch.object(logging.Logger, "warning") as mock_warn:
        await notifier.send(_make_event())

    req = httpx_mock.get_requests()[0]
    assert "x-orchestrator-signature" not in req.headers
    mock_warn.assert_called_once()


@pytest.mark.asyncio
async def test_webhook_with_secret_includes_signature_header(
    httpx_mock: HTTPXMock,
) -> None:
    """When ALERT_WEBHOOK_SECRET is set, the signature header must be present and valid."""
    httpx_mock.add_response(status_code=200)

    notifier = WebhookNotifier(url="http://hook.test/alert", secret="topsecret", timeout=5)
    await notifier.send(_make_event())

    req = httpx_mock.get_requests()[0]
    assert "x-orchestrator-signature" in req.headers
    body = req.content
    expected = "sha256=" + hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
    assert req.headers["x-orchestrator-signature"] == expected


@pytest.mark.asyncio
async def test_webhook_no_secret_warning_logged_once(
    httpx_mock: HTTPXMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The no-secret warning must be logged only once, not on every send."""
    import orchestrator.alerts as alerts_mod

    alerts_mod._WEBHOOK_NO_SECRET_LOGGED = False
    httpx_mock.add_response(status_code=200)
    httpx_mock.add_response(status_code=200)

    notifier = WebhookNotifier(url="http://hook.test/alert", secret="", timeout=5)
    import logging

    with patch.object(logging.Logger, "warning") as mock_warn:
        await notifier.send(_make_event())
        await notifier.send(_make_event())

    # Only one warning for two sends
    assert mock_warn.call_count == 1


# ─── Secrets and hangs in the notifiers ──────────────────────────────────────


@pytest.mark.asyncio
async def test_webhook_4xx_error_never_carries_the_url(httpx_mock: HTTPXMock) -> None:
    """
    httpx's raise_for_status() message embeds the full URL. Hosted webhooks
    (Slack, Teams, Discord) put their secret in the path, and this string is
    persisted in runs.error / alert_deliveries.last_error and logged.
    """
    httpx_mock.add_response(status_code=404)
    notifier = WebhookNotifier(
        url="http://hook.test/services/T000/B000/SECRETTOKEN123", secret="s", timeout=5
    )
    with pytest.raises(Exception) as excinfo:
        await notifier.send(_make_event())
    text = str(excinfo.value)
    assert "SECRETTOKEN123" not in text
    assert "hook.test" not in text
    assert "404" in text


def test_smtp_connection_is_opened_with_a_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """smtplib.SMTP() has no default timeout; a server that accepts the TCP
    connection and never sends its banner would hang the run forever."""
    from email.mime.text import MIMEText
    from unittest.mock import MagicMock

    import orchestrator.alerts as alerts_mod

    smtp_cls = MagicMock()
    monkeypatch.setattr(alerts_mod.smtplib, "SMTP", smtp_cls)

    for starttls in (True, False):
        smtp_cls.reset_mock()
        notifier = EmailNotifier(
            host="smtp.test",
            port=25,
            user="",
            password="",
            from_addr="a@example.com",
            to_addrs=["b@example.com"],
            starttls=starttls,
            timeout=7.5,
        )
        notifier._send_sync(MIMEText("hello"))
        assert smtp_cls.call_args.kwargs.get("timeout") == 7.5, smtp_cls.call_args


def test_email_notifier_from_settings_gets_alert_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    import orchestrator.alerts as alerts_mod

    monkeypatch.setattr(alerts_mod.settings, "alert_smtp_host", "smtp.test")
    monkeypatch.setattr(alerts_mod.settings, "alert_email_to", "ops@example.com")
    monkeypatch.setattr(alerts_mod.settings, "alert_webhook_url", "")
    monkeypatch.setattr(alerts_mod.settings, "alert_timeout_seconds", 12)
    notifiers = [n for n in alerts_mod.build_notifiers() if isinstance(n, EmailNotifier)]
    assert notifiers and notifiers[0]._timeout == 12.0
