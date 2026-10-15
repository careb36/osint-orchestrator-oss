"""GET /health is liveness (always 200); GET /ready is readiness (503 when the
service cannot do its job). A disabled OpenCTI sink is a configuration, not a
fault (ADR-008)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.api as api_mod
import orchestrator.scheduler as scheduler_mod
from orchestrator.api import app
from orchestrator.config import settings


def _fake_scheduler(*, running: bool) -> SimpleNamespace:
    """What /health reads (``running``) plus the no-ops the app lifespan calls."""
    return SimpleNamespace(running=running, start=lambda **_: None, shutdown=lambda **_: None)


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

    monkeypatch.setattr(api_mod, "get_session", _session)
    monkeypatch.setattr(scheduler_mod, "scheduler", _fake_scheduler(running=True))
    monkeypatch.setattr(settings, "opencti_enabled", True)
    with TestClient(app, raise_server_exceptions=True) as test_client:
        yield test_client
    await engine.dispose()


def test_everything_up_is_ok_and_ready(client: TestClient) -> None:
    health = client.get("/health")
    ready = client.get("/ready")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert ready.status_code == 200
    assert ready.json()["status"] == "ok"


def test_disabled_opencti_is_a_setting_not_a_fault(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The compose healthcheck used to fail forever with OPENCTI_ENABLED=false."""
    monkeypatch.setattr(settings, "opencti_enabled", False)

    payload = client.get("/health").json()

    assert payload["status"] == "ok"
    assert payload["checks"]["opencti"]["status"] == "disabled"
    assert "OPENCTI_ENABLED" in payload["checks"]["opencti"]["action"]
    assert client.get("/ready").status_code == 200


def test_stopped_scheduler_is_degraded_but_not_ready(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scheduler_mod, "scheduler", _fake_scheduler(running=False))

    health = client.get("/health")
    ready = client.get("/ready")

    assert health.status_code == 200  # liveness: the process still answers
    assert health.json()["status"] == "degraded"
    assert ready.status_code == 503
    assert ready.json()["checks"]["scheduler"]["status"] == "degraded"


def test_database_failure_is_offline_and_not_ready(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    @asynccontextmanager
    async def _broken():
        raise RuntimeError("database is locked")
        yield  # pragma: no cover

    monkeypatch.setattr(api_mod, "get_session", _broken)

    health = client.get("/health")
    ready = client.get("/ready")

    assert health.status_code == 200
    assert health.json()["status"] == "offline"
    assert ready.status_code == 503
    assert ready.json()["status"] == "offline"


def test_compose_healthcheck_polls_the_readiness_route() -> None:
    """/health always answers 200, so a healthcheck on it could never fail."""
    compose = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    services = yaml.safe_load(compose.read_text(encoding="utf-8"))["services"]
    test = " ".join(services["orchestrator"]["healthcheck"]["test"])
    assert "/ready" in test
    assert "/health" not in test
