from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.run_control as run_control
from orchestrator.models import Run, RunStatus
from orchestrator.run_control import create_pending_run


def _make_engine():
    return create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


async def _setup_db(engine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    return _session


@pytest.fixture(autouse=True)
def _clear_target_locks() -> None:
    run_control._target_locks.clear()


@pytest.mark.asyncio
async def test_create_pending_run_rejects_second_active_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(run_control, "get_session", session_ctx)

    first = await create_pending_run("alpha")
    second = await create_pending_run("alpha")
    assert first is not None
    assert second is None

    async with session_ctx() as session:
        run = await session.get(Run, first)
        assert run is not None
        run.status = RunStatus.SUCCESS
        session.add(run)
        await session.commit()

    third = await create_pending_run("alpha")
    assert third is not None
    assert third != first
    await engine.dispose()


@pytest.mark.asyncio
async def test_create_pending_run_serializes_concurrent_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    monkeypatch.setattr(run_control, "get_session", _session_factory(engine))

    results = await asyncio.gather(*(create_pending_run("alpha") for _ in range(8)))
    admitted = [r for r in results if r is not None]
    rejected = [r for r in results if r is None]

    assert len(admitted) == 1
    assert len(rejected) == 7
    await engine.dispose()


@pytest.mark.asyncio
async def test_mark_interrupted_runs_fails_stale_rows_and_readmits_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    The run guard is the persisted status: a row left RUNNING by a crash or a
    redeploy would refuse every later run of its target forever. At startup
    nothing can legitimately be in flight, so those rows are failed and the
    target becomes admissible again.
    """
    from datetime import UTC, datetime

    from orchestrator.models import Run, RunStatus
    from orchestrator.run_control import mark_interrupted_runs

    engine = _make_engine()
    await _setup_db(engine)
    monkeypatch.setattr(run_control, "get_session", _session_factory(engine))

    async with _session_factory(engine)() as session:
        for status in (RunStatus.RUNNING, RunStatus.PENDING, RunStatus.SUCCESS):
            session.add(Run(target_id="t1", started_at=datetime.now(UTC), status=status))
        await session.commit()

    assert await create_pending_run("t1") is None, "guard must hold while a run is RUNNING"

    assert await mark_interrupted_runs() == 2

    async with _session_factory(engine)() as session:
        rows = (await session.exec(select(Run).order_by(Run.id))).all()
    assert [r.status for r in rows] == [RunStatus.FAILED, RunStatus.FAILED, RunStatus.SUCCESS]
    assert all("interrupted" in (r.error or "") for r in rows[:2])
    assert rows[2].error is None

    assert await create_pending_run("t1") is not None, "target must be admissible again"
