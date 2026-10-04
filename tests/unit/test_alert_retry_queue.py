"""Unit tests for persistent alert retry queue and DLQ replay."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator.alerts import AlertEvent
from orchestrator.api import app
from orchestrator.models import AlertDelivery, AlertDeliveryStatus, AlertRecord, AlertStatus
from orchestrator.pipeline import process_pending_alert_deliveries


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
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    return _session


def _event() -> AlertEvent:
    return AlertEvent(
        target_id="target-1",
        target_fqdn="example.com",
        run_id=1,
        run_status="success",
        risk_level="high",
        new_observables=[],
        new_observable_count=1,
        report_path=None,
        finding_summary="test",
        generated_at=datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_retry_queue_eventually_sends_after_transient_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr("orchestrator.pipeline.settings.alert_retry_base_delay_seconds", 0.0)
    monkeypatch.setattr("orchestrator.pipeline.settings.alert_retry_jitter_ratio", 0.0)

    async with session_ctx() as session:
        session.add(
            AlertDelivery(
                run_id=1,
                target_id="target-1",
                channel="webhook",
                language="en",
                payload_json=_event().model_dump_json(),
                status=AlertDeliveryStatus.PENDING,
                attempts=1,
                max_attempts=4,
            )
        )
        await session.commit()

    class _FlakyNotifier:
        channel = "webhook"

        def __init__(self):
            self.calls = 0

        async def send(self, event: AlertEvent) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("temporary")

    flaky = _FlakyNotifier()
    monkeypatch.setattr(
        "orchestrator.alerts.build_notifiers",
        lambda language=None: [flaky],
    )

    first = await process_pending_alert_deliveries(limit=10)
    assert first["processed"] == 1
    assert first["failed"] == 1

    second = await process_pending_alert_deliveries(limit=10)
    assert second["processed"] == 1
    assert second["sent"] == 1
    assert second["retried"] == 1

    async with session_ctx() as session:
        delivery = (await session.exec(select(AlertDelivery))).one()
        assert delivery.status == AlertDeliveryStatus.SENT
        assert delivery.sent_at is not None
        records = (await session.exec(select(AlertRecord).order_by(AlertRecord.id.asc()))).all()
        assert [r.status for r in records] == [AlertStatus.FAILED, AlertStatus.SENT]


@pytest.mark.asyncio
async def test_retry_queue_moves_to_dead_letter_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr("orchestrator.pipeline.settings.alert_retry_base_delay_seconds", 0.0)
    monkeypatch.setattr("orchestrator.pipeline.settings.alert_retry_jitter_ratio", 0.0)

    async with session_ctx() as session:
        session.add(
            AlertDelivery(
                run_id=7,
                target_id="target-1",
                channel="webhook",
                language="en",
                payload_json=_event().model_dump_json(),
                status=AlertDeliveryStatus.PENDING,
                attempts=2,
                max_attempts=3,
            )
        )
        await session.commit()

    class _FailingNotifier:
        channel = "webhook"

        async def send(self, event: AlertEvent) -> None:
            raise RuntimeError("still failing")

    monkeypatch.setattr(
        "orchestrator.alerts.build_notifiers",
        lambda language=None: [_FailingNotifier()],
    )

    result = await process_pending_alert_deliveries(limit=10)
    assert result["processed"] == 1
    assert result["dlq"] == 1

    async with session_ctx() as session:
        delivery = (await session.exec(select(AlertDelivery))).one()
        assert delivery.status == AlertDeliveryStatus.DEAD_LETTER
        assert delivery.last_error == "still failing"


@pytest.mark.asyncio
async def test_replay_dlq_endpoint_moves_and_processes(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr("orchestrator.config.settings.orchestrator_api_key", "")

    async with session_ctx() as session:
        session.add(
            AlertDelivery(
                run_id=9,
                target_id="target-1",
                channel="webhook",
                language="es",
                payload_json=_event().model_dump_json(),
                status=AlertDeliveryStatus.DEAD_LETTER,
                attempts=4,
                max_attempts=4,
            )
        )
        await session.commit()

    class _OkNotifier:
        channel = "webhook"

        async def send(self, event: AlertEvent) -> None:
            return None

    monkeypatch.setattr(
        "orchestrator.alerts.build_notifiers", lambda language=None: [_OkNotifier()]
    )

    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.post("/alerts/dlq/replay?run_id=9&channel=webhook")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["moved"] == 1
    assert payload["processed_now"]["sent"] == 1

    async with session_ctx() as session:
        delivery = (await session.exec(select(AlertDelivery))).one()
        assert delivery.status == AlertDeliveryStatus.SENT


def test_replay_dlq_endpoint_validates_channel_and_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchestrator.config.settings.orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as client:
        invalid_channel = client.post("/alerts/dlq/replay?channel=sms")
        assert invalid_channel.status_code == 422

        invalid_limit = client.post("/alerts/dlq/replay?limit=0")
        assert invalid_limit.status_code == 422
