"""GET /targets/{id}/chain/verify only verifies, and only counts, configured targets."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.api as api_mod
from orchestrator import metrics
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.models import Target


@pytest.fixture
async def client(monkeypatch: pytest.MonkeyPatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    known = Target(id="known", fqdn="example.com", authorization="self-owned", purpose="test")
    monkeypatch.setattr(api_mod, "get_session", _session)
    monkeypatch.setattr(api_mod, "_load_targets", lambda: [known])
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client


def _samples(target_id: str) -> dict[str, float | None]:
    return {
        outcome: metrics.sample(
            "osint_orchestrator_evidence_chain_verify_total",
            {"target_id": target_id, "outcome": outcome},
        )
        for outcome in ("ok", "broken", "error")
    }


async def test_unknown_target_is_404_and_creates_no_metric_series(client: TestClient) -> None:
    """The target id is a Prometheus label: an unchecked one lets any caller
    grow /metrics by one time series per request."""
    response = client.get("/targets/not-configured/chain/verify")

    assert response.status_code == 404
    assert "not-configured" in response.json()["detail"]
    assert _samples("not-configured") == {"ok": None, "broken": None, "error": None}


async def test_known_target_without_runs_verifies_ok_and_is_counted(client: TestClient) -> None:
    before = _samples("known")["ok"] or 0.0

    response = client.get("/targets/known/chain/verify")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["checked"] == 0
    assert _samples("known")["ok"] == before + 1
