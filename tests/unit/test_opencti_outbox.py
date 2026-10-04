"""Unit tests for persistent OpenCTI outbox lifecycle."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    OpenCTIOutbox,
    OpenCTIOutboxStatus,
    Run,
    RunObservable,
    RunStatus,
    SeenObservable,
    Target,
)
from orchestrator.pipeline import drain_opencti_outbox, run_target_pipeline
from orchestrator.sinks import OpenCTIIngestError


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


def _target() -> Target:
    return Target(
        id="target-1",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
    )


class _Collector:
    name = CollectorName.OPENOSINT

    def __init__(self, target: Target) -> None:
        self.target = target

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[Observable(type="domain-name", value=self.target.fqdn)],
            success=True,
        )


@pytest.mark.asyncio
async def test_opencti_failure_enqueues_outbox_and_drain_sends(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_Collector(t)])
    monkeypatch.setattr(pipeline_module, "synthesize", AsyncMock(return_value=(None, "skipped")))
    monkeypatch.setattr("orchestrator.pipeline.settings.opencti_outbox_base_delay_seconds", 0.0)
    monkeypatch.setattr("orchestrator.pipeline.settings.opencti_outbox_jitter_ratio", 0.0)

    class _FailingSink:
        async def ingest_async(self, bundle, *, work_name="", target_id=None):
            # A transient failure (platform down) is what the outbox is for;
            # a permanent one goes straight to the dead-letter queue.
            raise OpenCTIIngestError("opencti down", transient=True)

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _FailingSink)
    monkeypatch.setattr("orchestrator.alerts.build_notifiers", lambda language=None: [])

    target = _target()
    target.report_dir = str(tmp_path)

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
        assert run_db.status == RunStatus.PARTIAL
        queued = (await session.exec(select(OpenCTIOutbox))).all()
        assert len(queued) == 1
        assert queued[0].status == OpenCTIOutboxStatus.PENDING

    class _RecoveredSink:
        async def ingest_async(self, bundle, *, work_name="", target_id=None):
            return None

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _RecoveredSink)
    summary = await drain_opencti_outbox(limit=10)
    assert summary["processed"] == 1
    assert summary["sent"] == 1

    async with session_ctx() as session:
        entry = (await session.exec(select(OpenCTIOutbox))).one()
        assert entry.status == OpenCTIOutboxStatus.SENT
        assert entry.sent_at is not None
        # ADR-003: once the bundle is in OpenCTI, SQLite keeps no copy of it.
        assert entry.bundle_json is None
        # The deferred bundle's observables are now ingested and seen, and the
        # run's new-observable count reflects it.
        observables = (await session.exec(select(RunObservable))).all()
        assert observables and all(o.ingested for o in observables)
        seen = (await session.exec(select(SeenObservable))).all()
        assert {s.stix_id for s in seen} == {o.stix_id for o in observables if o.is_new}
        run_db = await session.get(Run, run_id)
        assert run_db is not None and run_db.new_observables == len(seen)


@pytest.mark.asyncio
async def test_opencti_outbox_reaches_dead_letter(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr("orchestrator.pipeline.settings.opencti_outbox_base_delay_seconds", 0.0)
    monkeypatch.setattr("orchestrator.pipeline.settings.opencti_outbox_jitter_ratio", 0.0)

    async with session_ctx() as session:
        session.add(
            OpenCTIOutbox(
                run_id=11,
                target_id="target-1",
                work_name="osint-orchestrator/target-1/11",
                bundle_json='{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000000","objects":[]}',
                status=OpenCTIOutboxStatus.PENDING,
                attempts=2,
                max_attempts=3,
            )
        )
        await session.commit()

    class _StillFailingSink:
        async def ingest_async(self, bundle, *, work_name="", target_id=None):
            raise RuntimeError("still unavailable")

    monkeypatch.setattr(pipeline_module.stix2, "parse", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(pipeline_module, "OpenCTISink", _StillFailingSink)
    summary = await drain_opencti_outbox(limit=10)
    assert summary["processed"] == 1
    assert summary["dead_letter"] == 1

    async with session_ctx() as session:
        entry = (await session.exec(select(OpenCTIOutbox))).one()
        assert entry.status == OpenCTIOutboxStatus.DEAD_LETTER
        assert entry.last_error == "still unavailable"
