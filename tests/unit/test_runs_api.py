"""Unit tests for GET /runs and GET /runs/{id}: the risk level travels with each run."""

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


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    return _session


async def _seed(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Three runs of t1 (medium → high → failed, no finding) and one of t2 without a finding."""
    engine = _make_engine()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(settings, "orchestrator_api_key", "")

    now = datetime.now(UTC)
    async with session_ctx() as session:
        first = Run(target_id="t1", started_at=now - timedelta(hours=3), status=RunStatus.SUCCESS)
        second = Run(target_id="t1", started_at=now - timedelta(hours=2), status=RunStatus.SUCCESS)
        third = Run(target_id="t1", started_at=now - timedelta(hours=1), status=RunStatus.FAILED)
        other = Run(
            target_id="t2", started_at=now - timedelta(minutes=30), status=RunStatus.SUCCESS
        )
        session.add_all([first, second, third, other])
        await session.commit()
        for run in (first, second, third, other):
            await session.refresh(run)
        session.add(FindingRecord(run_id=first.id, target_id="t1", risk_level="medium"))
        session.add(FindingRecord(run_id=second.id, target_id="t1", risk_level="high"))
        await session.commit()
        return {"first": first.id, "second": second.id, "third": third.id, "other": other.id}


@pytest.mark.asyncio
async def test_run_list_carries_the_risk_level_of_each_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed(monkeypatch)
    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get("/runs")
    assert response.status_code == 200
    by_id = {row["id"]: row for row in response.json()}
    assert [row["id"] for row in response.json()] == [
        ids["other"],
        ids["third"],
        ids["second"],
        ids["first"],
    ]  # newest first
    assert by_id[ids["first"]]["risk_level"] == "medium"
    assert by_id[ids["second"]]["risk_level"] == "high"
    assert by_id[ids["third"]]["risk_level"] is None  # failed before any synthesis
    assert by_id[ids["other"]]["risk_level"] is None


@pytest.mark.asyncio
async def test_run_list_pages_with_limit_and_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    ids = await _seed(monkeypatch)
    with TestClient(app, raise_server_exceptions=True) as client:
        first_page = client.get("/runs", params={"limit": 2}).json()
        second_page = client.get("/runs", params={"limit": 2, "offset": 2}).json()
        beyond = client.get("/runs", params={"limit": 2, "offset": 4}).json()
        filtered = client.get("/runs", params={"target_id": "t1", "limit": 1, "offset": 1}).json()

    assert [row["id"] for row in first_page] == [ids["other"], ids["third"]]
    assert [row["id"] for row in second_page] == [ids["second"], ids["first"]]
    assert beyond == []
    assert [row["id"] for row in filtered] == [ids["second"]]


@pytest.mark.asyncio
@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 501}, {"offset": -1}])
async def test_run_list_rejects_out_of_range_paging(
    monkeypatch: pytest.MonkeyPatch, params: dict[str, int]
) -> None:
    await _seed(monkeypatch)
    with TestClient(app, raise_server_exceptions=True) as client:
        assert client.get("/runs", params=params).status_code == 422


@pytest.mark.asyncio
async def test_run_list_filter_by_target_keeps_the_risk_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed(monkeypatch)
    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get("/runs", params={"target_id": "t1"})
    rows = response.json()
    assert [row["target_id"] for row in rows] == ["t1", "t1", "t1"]
    assert [row["risk_level"] for row in rows] == [None, "high", "medium"]
    assert rows[-1]["id"] == ids["first"]


@pytest.mark.asyncio
async def test_run_detail_carries_the_risk_level_and_the_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = await _seed(monkeypatch)
    with TestClient(app, raise_server_exceptions=True) as client:
        with_finding = client.get(f"/runs/{ids['second']}")
        without = client.get(f"/runs/{ids['third']}")
        missing = client.get("/runs/999")
    assert with_finding.status_code == 200
    assert with_finding.json()["risk_level"] == "high"
    assert with_finding.json()["alerts"] == []
    assert without.json()["risk_level"] is None
    assert missing.status_code == 404
