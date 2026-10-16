"""
Run admission control.

Single-instance guard to prevent concurrent runs for the same target across
manual triggers and scheduler ticks.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from sqlmodel import col, select

from orchestrator.database import get_session
from orchestrator.models import Run, RunStatus

_target_locks: dict[str, asyncio.Lock] = {}


def _lock_for_target(target_id: str) -> asyncio.Lock:
    """Per-target in-process lock serialising admission checks (one active run)."""
    lock = _target_locks.get(target_id)
    if lock is None:
        lock = asyncio.Lock()
        _target_locks[target_id] = lock
    return lock


async def create_pending_run(target_id: str) -> int | None:
    """
    Create a pending run unless this target already has a pending/running run.

    Returns the run id when admitted; otherwise ``None``.
    """
    async with _lock_for_target(target_id), get_session() as session:
        existing = await session.exec(
            select(Run.id)
            .where(Run.target_id == target_id)
            .where(col(Run.status).in_([RunStatus.PENDING, RunStatus.RUNNING]))
            .limit(1)
        )
        if existing.first() is not None:
            return None

        run = Run(
            target_id=target_id,
            started_at=datetime.now(UTC),
            status=RunStatus.PENDING,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        return run.id


async def mark_interrupted_runs() -> int:
    """
    Fail every run still PENDING/RUNNING at startup and return how many.

    The per-target guard in create_pending_run() is the persisted Run.status,
    so a run cut short by a crash, an OOM kill or a redeploy would otherwise
    stay RUNNING forever and lock its target out of every future run until
    someone edited SQLite by hand. A process that has just started cannot be
    running anything, so anything still in flight belongs to a previous life.
    """
    async with get_session() as session:
        stale = (
            await session.exec(
                select(Run).where(col(Run.status).in_([RunStatus.PENDING, RunStatus.RUNNING]))
            )
        ).all()
        for run in stale:
            run.status = RunStatus.FAILED
            run.finished_at = datetime.now(UTC)
            run.error = "interrupted: the orchestrator restarted while this run was in progress"
            session.add(run)
        await session.commit()
    return len(stale)
