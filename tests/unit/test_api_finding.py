"""Unit tests for GET /runs/{run_id}/finding."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.api as api_mod
from orchestrator import models as models_mod
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.models import FindingRecord


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
async def test_finding_lists_are_json_arrays(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(settings, "orchestrator_api_key", "")

    pivots = ["Verify TLS certificate", "Check WHOIS contacts"]
    new_items = ["new.example.com", "203.0.113.5"]
    async with session_ctx() as session:
        session.add(
            FindingRecord(
                run_id=101,
                target_id="target-1",
                summary="Synthetic finding",
                new_since_last_run=json.dumps(new_items),
                suggested_pivots=json.dumps(pivots),
            )
        )
        await session.commit()

    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get("/runs/101/finding")

    assert response.status_code == 200
    payload = response.json()
    assert payload["new_since_last_run"] == new_items
    assert payload["suggested_pivots"] == pivots
    assert all(isinstance(item, str) for item in payload["new_since_last_run"])
    assert all(isinstance(item, str) for item in payload["suggested_pivots"])


@pytest.mark.asyncio
async def test_corrupt_stored_list_returns_empty_and_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(settings, "orchestrator_api_key", "")

    warning_calls: list[dict[str, object]] = []

    def _warning_spy(msg: str, *args: object, **kwargs: object) -> None:
        warning_calls.append({"msg": msg, "kwargs": kwargs})

    monkeypatch.setattr(models_mod.logger, "warning", _warning_spy)

    async with session_ctx() as session:
        session.add(
            FindingRecord(
                run_id=102,
                target_id="target-1",
                summary="Synthetic finding",
                new_since_last_run="not json",
                suggested_pivots=json.dumps(["pivot a", "pivot b"]),
            )
        )
        await session.commit()

    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get("/runs/102/finding")

    assert response.status_code == 200
    payload = response.json()
    assert payload["new_since_last_run"] == []
    assert payload["suggested_pivots"] == ["pivot a", "pivot b"]

    assert len(warning_calls) == 1
    assert "could not be decoded as list[str]" in str(warning_calls[0]["msg"])
    assert warning_calls[0]["kwargs"]["extra"] == {"run_id": 102, "field": "new_since_last_run"}


@pytest.mark.asyncio
async def test_missing_finding_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _make_engine()
    await _setup_db(engine)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(settings, "orchestrator_api_key", "")

    with TestClient(app, raise_server_exceptions=True) as client:
        response = client.get("/runs/999/finding")

    assert response.status_code == 404
