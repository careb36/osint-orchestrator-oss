from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator import metrics
from orchestrator.api import app
from orchestrator.i18n import t
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    OpenCTIOutbox,
    Run,
    RunStatus,
    Target,
)
from orchestrator.pipeline import get_run_delta, run_target_pipeline
from orchestrator.scheduler import register_opencti_outbox_job, scheduler


def _make_engine():
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    return _session


class _Collector:
    name = CollectorName.OPENOSINT

    def __init__(self, target: Target) -> None:
        self.target = target

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[
                Observable(type="domain-name", value=self.target.fqdn),
                Observable(type="email-addr", value=f"admin@{self.target.fqdn}"),
            ],
            success=True,
        )


async def _create_run(session_ctx, target_id: str) -> int:
    async with session_ctx() as session:
        run = Run(target_id=target_id, started_at=datetime.now(UTC), status=RunStatus.PENDING)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        assert run.id is not None
        return run.id


@pytest.mark.asyncio
async def test_run_succeeds_without_opencti_and_no_sink_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _make_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_ctx = _session_factory(engine)

    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_Collector(t)])

    async def _skip_synthesize(*_args, **_kwargs):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _skip_synthesize)
    monkeypatch.setattr("orchestrator.config.settings.opencti_enabled", False)

    class _SinkMustNotBeBuilt:
        def __init__(self) -> None:
            raise AssertionError("OpenCTISink must not be instantiated when OPENCTI_ENABLED=false")

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _SinkMustNotBeBuilt)

    target = Target(
        id="opencti-disabled-run",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )
    run_id = await _create_run(session_ctx, target.id)
    await run_target_pipeline(target, run_id)

    async with session_ctx() as session:
        run_db = await session.get(Run, run_id)
        assert run_db is not None
        assert run_db.status == RunStatus.SUCCESS
        outbox_rows = (await session.exec(select(OpenCTIOutbox))).all()
        assert outbox_rows == []

    assert (
        metrics.sample(
            f"{metrics.PREFIX}_opencti_ingest_total",
            {"target_id": target.id, "outcome": "success"},
        )
        is None
    )
    assert (
        metrics.sample(
            f"{metrics.PREFIX}_opencti_ingest_total",
            {"target_id": target.id, "outcome": "failure"},
        )
        is None
    )

    await engine.dispose()


@pytest.mark.asyncio
async def test_second_run_has_no_new_observables_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _make_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_ctx = _session_factory(engine)

    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_Collector(t)])

    async def _skip_synthesize(*_args, **_kwargs):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _skip_synthesize)
    monkeypatch.setattr("orchestrator.config.settings.opencti_enabled", False)

    class _SinkMustNotBeBuilt:
        def __init__(self) -> None:
            raise AssertionError("OpenCTISink must not be instantiated when OPENCTI_ENABLED=false")

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _SinkMustNotBeBuilt)

    target = Target(
        id="opencti-disabled-delta",
        fqdn="example.org",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )

    first_run_id = await _create_run(session_ctx, target.id)
    await run_target_pipeline(target, first_run_id)
    second_run_id = await _create_run(session_ctx, target.id)
    await run_target_pipeline(target, second_run_id)

    assert await get_run_delta(second_run_id) == []

    async with session_ctx() as session:
        second_run = await session.get(Run, second_run_id)
        assert second_run is not None
        assert second_run.new_observables == 0
        assert second_run.report_path is not None
        delta = json.loads((Path(second_run.report_path).parent / "delta.json").read_text("utf-8"))
        assert delta == []

    await engine.dispose()


def test_outbox_replay_is_409_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("orchestrator.config.settings.opencti_enabled", False)
    monkeypatch.setattr("orchestrator.config.settings.orchestrator_api_key", "test-token")
    monkeypatch.setattr("orchestrator.config.settings.orchestrator_language", "es")

    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.post("/opencti/outbox/replay", headers={"X-API-Key": "test-token"})

    assert response.status_code == 409
    assert response.json()["detail"] == t("opencti_sink_disabled")


def test_scheduler_skips_outbox_job_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    if scheduler.get_job("opencti-outbox"):
        scheduler.remove_job("opencti-outbox")

    monkeypatch.setattr("orchestrator.scheduler.settings.opencti_enabled", False)
    monkeypatch.setattr("orchestrator.scheduler.settings.opencti_outbox_cron", "*/5 * * * *")
    register_opencti_outbox_job()
    assert scheduler.get_job("opencti-outbox") is None
