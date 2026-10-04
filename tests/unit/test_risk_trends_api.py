"""Unit tests for /analytics/risk-trends API endpoint."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.api as api_mod
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.models import FindingRecord, Run, RunStatus


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


@pytest.mark.asyncio
async def test_risk_trends_returns_per_target_history(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(settings, "orchestrator_api_key", "")

    now = datetime.now(UTC)
    async with session_ctx() as session:
        first = Run(target_id="t1", started_at=now - timedelta(hours=2), status=RunStatus.SUCCESS)
        second = Run(target_id="t1", started_at=now - timedelta(hours=1), status=RunStatus.PARTIAL)
        third = Run(
            target_id="t2", started_at=now - timedelta(minutes=30), status=RunStatus.SUCCESS
        )
        session.add(first)
        session.add(second)
        session.add(third)
        await session.commit()
        await session.refresh(first)
        await session.refresh(second)
        await session.refresh(third)

        session.add(
            FindingRecord(
                run_id=first.id,
                target_id="t1",
                summary="old risk",
                risk_level="low",
                generated_at=first.started_at,
            )
        )
        session.add(
            FindingRecord(
                run_id=second.id,
                target_id="t1",
                summary="new risk",
                risk_level="high",
                generated_at=second.started_at,
            )
        )
        await session.commit()

    with TestClient(app, raise_server_exceptions=True) as client:
        resp = client.get("/analytics/risk-trends")
    assert resp.status_code == 200

    rows = resp.json()
    assert len(rows) == 2
    t1 = next(row for row in rows if row["target_id"] == "t1")
    t2 = next(row for row in rows if row["target_id"] == "t2")

    assert t1["latest_risk_level"] == "high"
    assert t1["peak_risk_level"] == "high"
    assert t1["risk_history"] == ["low", "high"]
    assert t2["latest_risk_level"] == "unknown"
