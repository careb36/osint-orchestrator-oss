"""
Run status must reflect what actually happened.

Two regressions guarded here:

* A collector that follows the contract — never raise, return
  ``success=False`` — used to be invisible to the run status: a target whose
  only collector was down was recorded SUCCESS with zero findings and a green
  freshness SLO. Only a *raising* collector counted as an error.
* An exception escaping the pipeline left the row RUNNING forever. The
  per-target guard is that persisted status, so one bad run locked its target
  out of every later run until someone edited SQLite by hand.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
import orchestrator.run_control as run_control
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Run,
    RunStatus,
    Target,
)
from orchestrator.pipeline import run_target_pipeline
from orchestrator.run_control import create_pending_run


class _Collector:
    def __init__(
        self, target: Target, *, name: CollectorName, success: bool, error: str | None = None
    ):
        self.target, self.name, self._success, self._error = target, name, success, error

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[Observable(type="domain-name", value=self.target.fqdn)]
            if self._success
            else [],
            success=self._success,
            error=self._error,
        )


class _FakeSink:
    def ingest(self, bundle, work_name: str = "osint-orchestrator", **_: object) -> None:
        pass

    async def ingest_async(
        self, bundle, *, work_name: str = "osint-orchestrator", **_: object
    ) -> None:
        pass


@pytest.fixture
async def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    monkeypatch.setattr(pipeline_module, "get_session", _session)
    monkeypatch.setattr(run_control, "get_session", _session)
    monkeypatch.setattr(pipeline_module, "OpenCTISink", _FakeSink)

    async def _no_synthesize(*args, **kwargs):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synthesize)
    run_control._target_locks.clear()

    target = Target(
        id="status-target",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )

    async def _run_status(run_id: int) -> Run:
        async with _session() as session:
            run = await session.get(Run, run_id)
            assert run is not None
            return run

    return target, _run_status, monkeypatch


async def _start(target: Target) -> int:
    run_id = await create_pending_run(target.id)
    assert run_id is not None
    return run_id


@pytest.mark.asyncio
async def test_collector_reporting_failure_makes_the_run_partial(env) -> None:
    target, run_status, monkeypatch = env
    monkeypatch.setattr(
        pipeline_module,
        "_get_collectors",
        lambda t: [
            _Collector(t, name=CollectorName.OPENOSINT, success=True),
            _Collector(
                t, name=CollectorName.SPIDERFOOT, success=False, error="scan API unreachable"
            ),
        ],
    )
    run_id = await _start(target)
    await run_target_pipeline(target, run_id)
    run = await run_status(run_id)
    assert run.status == RunStatus.PARTIAL
    assert "spiderfoot: scan API unreachable" in (run.error or "")


@pytest.mark.asyncio
async def test_every_collector_reporting_failure_makes_the_run_failed(env) -> None:
    target, run_status, monkeypatch = env
    monkeypatch.setattr(
        pipeline_module,
        "_get_collectors",
        lambda t: [
            _Collector(t, name=CollectorName.SOCIALOSINT, success=False, error="service down")
        ],
    )
    run_id = await _start(target)
    await run_target_pipeline(target, run_id)
    run = await run_status(run_id)
    assert run.status == RunStatus.FAILED
    assert "socialosint: service down" in (run.error or "")


@pytest.mark.asyncio
async def test_exception_escaping_the_pipeline_fails_the_run_and_releases_the_guard(env) -> None:
    target, run_status, monkeypatch = env

    def _boom(t):
        raise RuntimeError("collector wiring exploded")

    monkeypatch.setattr(pipeline_module, "_get_collectors", _boom)
    run_id = await _start(target)
    assert await create_pending_run(target.id) is None, "guard held while PENDING"

    with pytest.raises(RuntimeError, match="exploded"):
        await run_target_pipeline(target, run_id)

    run = await run_status(run_id)
    assert run.status == RunStatus.FAILED
    assert run.finished_at is not None
    assert run.error == "pipeline: collector wiring exploded"
    assert await create_pending_run(target.id) is not None, "target admissible again"
