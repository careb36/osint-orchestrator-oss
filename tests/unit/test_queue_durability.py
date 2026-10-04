"""
Durability of the two persistent queues (alert deliveries, OpenCTI outbox).

The property under test is not "a retry eventually succeeds" — the older
suites cover that — but what happens *between* the external call and the
commit. Before per-row transactions a crash on row N re-sent rows 1..N-1 on
the next tick and two drains running at once sent everything twice; the
tests here would have failed on that code.
"""

from __future__ import annotations

import asyncio
import importlib.resources
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import httpx
import pytest
from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool, StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator import metrics
from orchestrator.alerts import AlertEvent
from orchestrator.api import app
from orchestrator.models import (
    AlertDelivery,
    AlertDeliveryStatus,
    OpenCTIOutbox,
    OpenCTIOutboxStatus,
    SeenObservable,
)
from orchestrator.pipeline import (
    _queue_failed_alert_delivery,
    drain_opencti_outbox,
    enqueue_opencti_outbox,
    process_pending_alert_deliveries,
    requeue_interrupted_deliveries,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    return _session


async def _bind(monkeypatch: pytest.MonkeyPatch, engine):
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    for name in (
        "alert_retry_base_delay_seconds",
        "alert_retry_jitter_ratio",
        "opencti_outbox_base_delay_seconds",
        "opencti_outbox_jitter_ratio",
    ):
        monkeypatch.setattr(f"orchestrator.pipeline.settings.{name}", 0.0)
    return session_ctx


@pytest.fixture
async def env(monkeypatch: pytest.MonkeyPatch):
    """In-memory database bound to the pipeline, retry delays zeroed."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    return await _bind(monkeypatch, engine)


@pytest.fixture
async def file_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """
    File-backed database with one connection per session, so two drains
    running concurrently really contend for the same rows.
    """
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/queues.db", poolclass=NullPool)
    return await _bind(monkeypatch, engine)


def _event(run_id: int) -> AlertEvent:
    return AlertEvent(
        target_id="target-1",
        target_fqdn="example.com",
        run_id=run_id,
        run_status="success",
        risk_level="high",
        new_observables=[],
        new_observable_count=1,
        report_path=None,
        finding_summary="test",
        generated_at=datetime.now(UTC),
    )


def _delivery(run_id: int, **overrides) -> AlertDelivery:
    fields = dict(
        run_id=run_id,
        target_id="target-1",
        channel="webhook",
        language="en",
        payload_json=_event(run_id).model_dump_json(),
        status=AlertDeliveryStatus.PENDING,
        attempts=1,
        max_attempts=4,
    )
    fields.update(overrides)
    return AlertDelivery(**fields)


def _outbox_row(run_id: int, **overrides) -> OpenCTIOutbox:
    fields = dict(
        run_id=run_id,
        target_id="target-1",
        work_name=f"osint-orchestrator/target-1/{run_id}",
        bundle_json='{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000000","objects":[]}',
        status=OpenCTIOutboxStatus.PENDING,
        attempts=1,
        max_attempts=6,
    )
    fields.update(overrides)
    return OpenCTIOutbox(**fields)


async def _statuses(session_ctx) -> dict[int, AlertDeliveryStatus]:
    async with session_ctx() as session:
        rows = (await session.exec(select(AlertDelivery))).all()
    return {r.run_id: r.status for r in rows}


# ── Alert delivery queue ──────────────────────────────────────────────────────


async def test_crash_mid_drain_resends_only_the_unsent_rows(env, monkeypatch) -> None:
    """
    The process dies while sending row 2 of 3. Row 1 must already be
    committed as SENT, row 2 must be visible as IN_PROGRESS, row 3 untouched;
    after the startup requeue the next drain sends 2 and 3 — and never 1
    again.
    """
    async with env() as session:
        session.add_all([_delivery(1), _delivery(2), _delivery(3)])
        session.add(_outbox_row(9, status=OpenCTIOutboxStatus.IN_PROGRESS))
        await session.commit()

    class _DiesOnSecondSend:
        channel = "webhook"
        sent: list[int] = []

        async def send(self, event: AlertEvent) -> None:
            self.sent.append(event.run_id)
            if len(self.sent) == 2:
                raise asyncio.CancelledError  # the process is going down

    notifier = _DiesOnSecondSend()
    monkeypatch.setattr("orchestrator.alerts.build_notifiers", lambda language=None: [notifier])

    with pytest.raises(asyncio.CancelledError):
        await process_pending_alert_deliveries(limit=10)

    assert await _statuses(env) == {
        1: AlertDeliveryStatus.SENT,
        2: AlertDeliveryStatus.IN_PROGRESS,
        3: AlertDeliveryStatus.PENDING,
    }

    # Startup of the next process.
    assert await requeue_interrupted_deliveries() == {"alert_deliveries": 1, "opencti_outbox": 1}
    assert (await _statuses(env))[2] == AlertDeliveryStatus.PENDING

    second = await process_pending_alert_deliveries(limit=10)
    assert second["sent"] == 2
    assert notifier.sent == [1, 2, 2, 3], "row 1 was delivered exactly once"


async def test_concurrent_drains_never_send_a_row_twice(file_env, monkeypatch) -> None:
    """The cron worker and the replay endpoint can drain at the same time."""
    async with file_env() as session:
        session.add_all([_delivery(1), _delivery(2), _delivery(3)])
        await session.commit()

    class _YieldingNotifier:
        channel = "webhook"
        sent: list[int] = []

        async def send(self, event: AlertEvent) -> None:
            self.sent.append(event.run_id)
            await asyncio.sleep(0)  # let the other drain interleave here

    notifier = _YieldingNotifier()
    monkeypatch.setattr("orchestrator.alerts.build_notifiers", lambda language=None: [notifier])

    results = await asyncio.gather(
        process_pending_alert_deliveries(limit=10),
        process_pending_alert_deliveries(limit=10),
    )

    assert sum(r["sent"] for r in results) == 3
    assert sorted(notifier.sent) == [1, 2, 3]
    assert set((await _statuses(file_env)).values()) == {AlertDeliveryStatus.SENT}


def _http_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://hook.test/alert")
    return httpx.HTTPStatusError(
        f"HTTP {status}", request=request, response=httpx.Response(status, request=request)
    )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, AlertDeliveryStatus.DEAD_LETTER),  # the receiver rejected the request
        (429, AlertDeliveryStatus.PENDING),  # "not now" — retried
        (503, AlertDeliveryStatus.PENDING),
    ],
)
async def test_rejected_webhook_is_dead_lettered_without_burning_retries(
    env, monkeypatch, status: int, expected: AlertDeliveryStatus
) -> None:
    async with env() as session:
        session.add(_delivery(1, attempts=1, max_attempts=4))
        await session.commit()

    class _Notifier:
        channel = "webhook"

        async def send(self, event: AlertEvent) -> None:
            raise _http_error(status)

    monkeypatch.setattr("orchestrator.alerts.build_notifiers", lambda language=None: [_Notifier()])
    result = await process_pending_alert_deliveries(limit=10)

    assert result["failed"] == 1
    assert result["dlq"] == (1 if expected is AlertDeliveryStatus.DEAD_LETTER else 0)
    assert (await _statuses(env))[1] == expected


async def test_unconfigured_channel_is_dead_lettered_immediately(env, monkeypatch) -> None:
    async with env() as session:
        session.add(_delivery(1, channel="email"))
        await session.commit()
    monkeypatch.setattr("orchestrator.alerts.build_notifiers", lambda language=None: [])

    result = await process_pending_alert_deliveries(limit=10)

    assert result["dlq"] == 1
    async with env() as session:
        row = (await session.exec(select(AlertDelivery))).one()
    assert row.status == AlertDeliveryStatus.DEAD_LETTER
    assert "Channel not configured: email" in (row.last_error or "")


async def test_first_send_permanent_failure_skips_the_queue(env) -> None:
    await _queue_failed_alert_delivery(
        run_id=1,
        target_id="target-1",
        channel="webhook",
        language="en",
        event=_event(1),
        first_error="HTTP 404",
        max_attempts=4,
        permanent=True,
    )
    async with env() as session:
        row = (await session.exec(select(AlertDelivery))).one()
    assert row.status == AlertDeliveryStatus.DEAD_LETTER
    assert metrics.alert_deliveries_dead_letter._value.get() >= 1


# ── OpenCTI outbox ────────────────────────────────────────────────────────────


async def test_permanent_ingest_error_is_dead_lettered_on_enqueue(env) -> None:
    """An invalid token cannot be fixed by retrying six times over half an hour."""
    import stix2

    await enqueue_opencti_outbox(
        run_id=1,
        target_id="target-1",
        work_name="w",
        bundle=stix2.Bundle(objects=[], allow_custom=True),
        first_error="AUTH_REQUIRED",
        transient=False,
    )
    async with env() as session:
        row = (await session.exec(select(OpenCTIOutbox))).one()
    assert row.status == OpenCTIOutboxStatus.DEAD_LETTER
    assert row.bundle_json is not None, "a dead letter keeps its bundle for replay"
    assert metrics.opencti_outbox_dead_letter._value.get() >= 1


async def test_permanent_error_during_drain_ignores_remaining_attempts(env, monkeypatch) -> None:
    async with env() as session:
        session.add(_outbox_row(1, attempts=1, max_attempts=6))
        await session.commit()

    class _RejectingSink:
        async def ingest_async(self, bundle, *, work_name="", target_id=None):
            raise ValueError({"name": "VALIDATION_ERROR", "message": "bad bundle"})

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _RejectingSink)
    summary = await drain_opencti_outbox(limit=10)

    assert summary == {"processed": 1, "sent": 0, "failed": 1, "dead_letter": 1}


async def test_bundle_is_parsed_off_the_event_loop(env, monkeypatch) -> None:
    import threading

    async with env() as session:
        session.add(_outbox_row(1))
        await session.commit()

    parse_threads: list[str] = []

    def _fake_parse(*_args, **_kwargs):
        parse_threads.append(threading.current_thread().name)
        return {"objects": []}

    class _OkSink:
        async def ingest_async(self, bundle, *, work_name="", target_id=None):
            return None

    monkeypatch.setattr(pipeline_module.stix2, "parse", _fake_parse)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", _OkSink)
    await drain_opencti_outbox(limit=10)

    assert parse_threads and parse_threads[0] != threading.main_thread().name


async def test_outbox_replay_endpoint_requeues_dead_letters_and_drains(env, monkeypatch) -> None:
    monkeypatch.setattr("orchestrator.config.settings.orchestrator_api_key", "")
    async with env() as session:
        session.add(_outbox_row(5, status=OpenCTIOutboxStatus.DEAD_LETTER, attempts=6))
        session.add(_outbox_row(6, status=OpenCTIOutboxStatus.DEAD_LETTER, attempts=6))
        await session.commit()

    class _OkSink:
        async def ingest_async(self, bundle, *, work_name="", target_id=None):
            return None

    monkeypatch.setattr(pipeline_module.stix2, "parse", lambda *_a, **_k: {"objects": []})
    monkeypatch.setattr(pipeline_module, "OpenCTISink", _OkSink)

    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.post("/opencti/outbox/replay?run_id=5")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["moved"] == 1
    assert payload["processed_now"]["sent"] == 1

    async with env() as session:
        rows = {r.run_id: r for r in (await session.exec(select(OpenCTIOutbox))).all()}
    assert rows[5].status == OpenCTIOutboxStatus.SENT and rows[5].bundle_json is None
    assert rows[6].status == OpenCTIOutboxStatus.DEAD_LETTER, "run_id filter respected"


# ── seen_observables uniqueness ───────────────────────────────────────────────


async def test_seen_observables_rejects_duplicates(env) -> None:
    async with env() as session:
        session.add(SeenObservable(target_id="t", stix_id="domain-name--x", first_seen_run_id=1))
        await session.commit()
    async with env() as session:
        session.add(SeenObservable(target_id="t", stix_id="domain-name--x", first_seen_run_id=2))
        with pytest.raises(IntegrityError):
            await session.commit()


def test_migration_0004_collapses_duplicates_before_adding_the_unique_index(
    tmp_path: Path,
) -> None:
    db_url = f"sqlite:///{tmp_path}/legacy.db"
    cfg = AlembicConfig()
    cfg.set_main_option(
        "script_location", str(importlib.resources.files("orchestrator.migrations"))
    )
    cfg.set_main_option("sqlalchemy.url", db_url)
    cfg.stdout = StringIO()

    alembic_command.upgrade(cfg, "0003")
    engine = create_engine(db_url)
    with engine.begin() as conn:
        for run_id in (1, 2, 3):
            conn.execute(
                text(
                    "INSERT INTO seen_observables (target_id, stix_id, first_seen_run_id) "
                    "VALUES ('t', 'domain-name--x', :run_id)"
                ),
                {"run_id": run_id},
            )
    alembic_command.upgrade(cfg, "head")

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT first_seen_run_id FROM seen_observables ORDER BY id")
        ).all()
    assert rows == [(1,)], "the oldest row survives"
    unique = [i for i in inspect(engine).get_indexes("seen_observables") if i["unique"]]
    assert [i["column_names"] for i in unique] == [["target_id", "stix_id"]]
    engine.dispose()
