"""
Alert cases: the triage state of every run that met an alert rule.

The pipeline opens one case per such run before any channel is tried, so a
deployment without a webhook or SMTP still has a list to work through. An
operator acknowledges a case (it is being looked at) and resolves it (nothing
more to do). Both names are free text: the API has no users (ADR-005).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlmodel import col, select

from orchestrator import metrics
from orchestrator.database import get_session
from orchestrator.models import AlertCase, AlertCaseState

logger = logging.getLogger(__name__)

# The pipeline hands in its own session factory so one database wiring (and
# one monkeypatch in its tests) covers the case it opens. Resolved at call
# time, never as a default argument, so a patched get_session is honoured.
SessionFactory = Callable[[], AbstractAsyncContextManager[Any]]


def _sessions(session_factory: SessionFactory | None) -> SessionFactory:
    return session_factory or get_session


class AlertCaseNotFoundError(LookupError):
    """No case with that id."""


class AlertCaseStateConflictError(ValueError):
    """The transition is not allowed from the case's current state."""

    def __init__(self, state: str) -> None:
        super().__init__(state)
        self.state = state


async def open_case(
    *,
    run_id: int,
    target_id: str,
    run_status: str,
    risk_level: str,
    new_observable_count: int,
    reason: str,
    session_factory: SessionFactory | None = None,
) -> AlertCase:
    """Open the case for *run_id*, or return the one that already exists."""
    async with _sessions(session_factory)() as session:
        existing = (await session.exec(select(AlertCase).where(AlertCase.run_id == run_id))).first()
        if existing is not None:
            return existing
        case = AlertCase(
            run_id=run_id,
            target_id=target_id,
            run_status=run_status,
            risk_level=risk_level,
            new_observable_count=new_observable_count,
            reason=reason,
        )
        session.add(case)
        await session.commit()
        await session.refresh(case)
    logger.info(
        "Alert case opened case_id=%d run_id=%d target=%s reason=%s",
        case.id,
        run_id,
        target_id,
        reason,
        extra={"target_id": target_id, "run_id": run_id, "reason": reason},
    )
    await refresh_metrics(session_factory=session_factory)
    return case


async def list_cases(
    *,
    target_id: str | None = None,
    state: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AlertCase], int]:
    """Cases newest first with the total that matches the filters."""
    async with get_session() as session:
        base = select(AlertCase)
        count = select(func.count()).select_from(AlertCase)
        if target_id:
            base = base.where(AlertCase.target_id == target_id)
            count = count.where(AlertCase.target_id == target_id)
        if state:
            base = base.where(AlertCase.state == state)
            count = count.where(AlertCase.state == state)
        total = int((await session.exec(count)).one())
        rows = (
            await session.exec(
                base.order_by(col(AlertCase.created_at).desc(), col(AlertCase.id).desc())
                .offset(offset)
                .limit(limit)
            )
        ).all()
    return list(rows), total


async def get_case(case_id: int) -> AlertCase:
    async with get_session() as session:
        case = await session.get(AlertCase, case_id)
    if case is None:
        raise AlertCaseNotFoundError(case_id)
    return case


async def acknowledge_case(case_id: int, *, by: str, note: str | None = None) -> AlertCase:
    """open → acknowledged. Records the time-to-acknowledge metric."""
    async with get_session() as session:
        case = await session.get(AlertCase, case_id)
        if case is None:
            raise AlertCaseNotFoundError(case_id)
        if case.state != AlertCaseState.OPEN.value:
            raise AlertCaseStateConflictError(case.state)
        now = datetime.now(UTC)
        case.state = AlertCaseState.ACKNOWLEDGED.value
        case.acknowledged_at = now
        case.acknowledged_by = by
        if note:
            case.note = note
        session.add(case)
        await session.commit()
        await session.refresh(case)
        created_at = _aware(case.created_at)
    metrics.alert_case_time_to_acknowledge_seconds.observe(
        max(0.0, (now - created_at).total_seconds())
    )
    await refresh_metrics()
    return case


async def resolve_case(case_id: int, *, by: str, note: str | None = None) -> AlertCase:
    """open | acknowledged → resolved."""
    async with get_session() as session:
        case = await session.get(AlertCase, case_id)
        if case is None:
            raise AlertCaseNotFoundError(case_id)
        if case.state == AlertCaseState.RESOLVED.value:
            raise AlertCaseStateConflictError(case.state)
        case.state = AlertCaseState.RESOLVED.value
        case.resolved_at = datetime.now(UTC)
        case.resolved_by = by
        if note:
            case.note = note
        session.add(case)
        await session.commit()
        await session.refresh(case)
    await refresh_metrics()
    return case


async def refresh_metrics(session_factory: SessionFactory | None = None) -> None:
    """Point the ``alert_cases`` gauge at the open and acknowledged counts."""
    async with _sessions(session_factory)() as session:
        rows = (
            await session.exec(
                select(AlertCase.state, func.count()).group_by(AlertCase.state)  # type: ignore[arg-type]
            )
        ).all()
    counts = {str(state): int(count) for state, count in rows}
    for state in (AlertCaseState.OPEN, AlertCaseState.ACKNOWLEDGED):
        metrics.alert_cases.labels(state.value).set(counts.get(state.value, 0))


def _aware(value: datetime) -> datetime:
    """SQLite hands naive datetimes back; they were stored as UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
