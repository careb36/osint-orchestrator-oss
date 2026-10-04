"""
Tests for orchestrator.metrics and GET /metrics (Phase 5).

Counters live on the global registry and accumulate across tests, so every
assertion is on a delta, never an absolute value.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator import metrics
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Run,
    RunStatus,
    Target,
)
from orchestrator.pipeline import run_target_pipeline
from orchestrator.scheduler import register_targets, scheduler

PREFIX = metrics.PREFIX


def _value(name: str, **labels: str) -> float:
    return metrics.sample(name, labels) or 0.0


# ── Endpoint ─────────────────────────────────────────────────────────────────


def test_metrics_endpoint_serves_prometheus_exposition() -> None:
    client = TestClient(app)
    client.get("/health")
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert f"# TYPE {PREFIX}_http_requests_total counter" in body
    assert f"# TYPE {PREFIX}_runs_total counter" in body
    assert f'{PREFIX}_http_requests_total{{method="GET",path="/health",status="200"}}' in body


def test_metrics_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_metrics_enabled", False)
    monkeypatch.setattr(settings, "orchestrator_language", "en")
    resp = TestClient(app).get("/metrics")
    assert resp.status_code == 404
    assert "disabled" in resp.json()["detail"]


def test_build_info_is_published() -> None:
    metrics.set_build_info("9.9.9")
    assert metrics.sample(f"{PREFIX}_build_info", {"version": "9.9.9"}) == 1.0


# ── HTTP labels ──────────────────────────────────────────────────────────────


def test_http_metrics_use_route_template_not_resolved_path() -> None:
    client = TestClient(app)
    name = f"{PREFIX}_http_requests_total"
    # /targets/{id} 404s without touching the database (no targets.yaml here).
    before = _value(name, method="GET", path="/targets/{target_id}", status="404")
    client.get("/targets/nope-1")
    client.get("/targets/nope-2")
    after = _value(name, method="GET", path="/targets/{target_id}", status="404")
    assert after - before == 2
    assert (
        metrics.sample(name, {"method": "GET", "path": "/targets/nope-1", "status": "404"}) is None
    )


def test_unmatched_paths_collapse_into_one_label() -> None:
    client = TestClient(app)
    name = f"{PREFIX}_http_requests_total"
    before = _value(name, method="GET", path="<unmatched>", status="404")
    client.get("/wp-admin/one")
    client.get("/wp-admin/two")
    assert _value(name, method="GET", path="<unmatched>", status="404") - before == 2


def test_http_duration_histogram_observes() -> None:
    client = TestClient(app)
    name = f"{PREFIX}_http_request_duration_seconds_count"
    before = _value(name, method="GET", path="/health")
    client.get("/health")
    assert _value(name, method="GET", path="/health") - before == 1


# ── Scheduler ────────────────────────────────────────────────────────────────


def test_scheduled_jobs_gauge_tracks_registered_targets() -> None:
    try:
        register_targets(
            [
                Target(id="m1", fqdn="m1.example.com", authorization="a", purpose="p"),
                Target(id="m2", fqdn="m2.example.com", authorization="a", purpose="p"),
            ]
        )
        assert metrics.sample(f"{PREFIX}_scheduled_jobs") == 2.0
    finally:
        for job in scheduler.get_jobs():
            scheduler.remove_job(job.id)


# ── Pipeline instrumentation ────────────────────────────────────────────────


class _OkCollector:
    name = CollectorName.OPENOSINT

    def __init__(self, target: Target):
        self.target = target

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[Observable(type="domain-name", value="new.example.com")],
        )


class _RaisingCollector:
    name = CollectorName.SPIDERFOOT

    def __init__(self, target: Target):
        self.target = target

    async def collect(self) -> CollectorResult:
        raise RuntimeError("spiderfoot down")


def _session_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    return engine, _session


@pytest.mark.asyncio
async def test_pipeline_records_run_collector_ingest_and_synthesis_metrics(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    engine, session_ctx = _session_factory()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(
        pipeline_module, "_get_collectors", lambda t: [_OkCollector(t), _RaisingCollector(t)]
    )
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    async def _skip(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _skip)

    target = Target(
        id="metrics-target",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
        alerts={"enabled": False},
    )
    async with session_ctx() as session:
        run = Run(target_id=target.id, started_at=datetime.now(UTC), status=RunStatus.PENDING)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    tid = target.id
    before = {
        "partial": _value(f"{PREFIX}_runs_total", target_id=tid, status="partial"),
        "ok": _value(
            f"{PREFIX}_collector_runs_total",
            collector="openosint",
            target_id=tid,
            outcome="success",
        ),
        "err": _value(
            f"{PREFIX}_collector_runs_total", collector="spiderfoot", target_id=tid, outcome="error"
        ),
        "ingest": _value(f"{PREFIX}_opencti_ingest_total", target_id=tid, outcome="success"),
        "synth": _value(f"{PREFIX}_synthesis_total", target_id=tid, status="skipped"),
        "new": _value(f"{PREFIX}_new_observables_total", target_id=tid),
        "dur": _value(f"{PREFIX}_run_duration_seconds_count", target_id=tid),
        "cdur": _value(f"{PREFIX}_collector_duration_seconds_count", collector="openosint"),
    }

    await run_target_pipeline(target, run_id)
    await engine.dispose()

    assert _value(f"{PREFIX}_runs_total", target_id=tid, status="partial") - before["partial"] == 1
    assert (
        _value(
            f"{PREFIX}_collector_runs_total",
            collector="openosint",
            target_id=tid,
            outcome="success",
        )
        - before["ok"]
        == 1
    )
    assert (
        _value(
            f"{PREFIX}_collector_runs_total", collector="spiderfoot", target_id=tid, outcome="error"
        )
        - before["err"]
        == 1
    )
    assert (
        _value(f"{PREFIX}_opencti_ingest_total", target_id=tid, outcome="success")
        - before["ingest"]
        == 1
    )
    assert (
        _value(f"{PREFIX}_synthesis_total", target_id=tid, status="skipped") - before["synth"] == 1
    )
    assert _value(f"{PREFIX}_new_observables_total", target_id=tid) - before["new"] == 1
    assert _value(f"{PREFIX}_run_duration_seconds_count", target_id=tid) - before["dur"] == 1
    assert (
        _value(f"{PREFIX}_collector_duration_seconds_count", collector="openosint") - before["cdur"]
        == 1
    )
    assert _value(f"{PREFIX}_run_observables", target_id=tid, kind="total") == 1
    assert _value(f"{PREFIX}_run_observables", target_id=tid, kind="new") == 1
    assert _value(f"{PREFIX}_runs_in_progress", target_id=tid) == 0


@pytest.mark.asyncio
async def test_pipeline_counts_a_crash_as_failed_and_clears_in_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception escaping the pipeline must not leave the gauge stuck at 1."""

    @asynccontextmanager
    async def _broken_session():
        raise RuntimeError("database gone")
        yield  # pragma: no cover

    monkeypatch.setattr(pipeline_module, "get_session", _broken_session)
    target = Target(id="crash-target", fqdn="x.example.com", authorization="a", purpose="p")
    before = _value(f"{PREFIX}_runs_total", target_id=target.id, status="failed")

    with pytest.raises(RuntimeError):
        await run_target_pipeline(target, 1)

    assert _value(f"{PREFIX}_runs_total", target_id=target.id, status="failed") - before == 1
    assert _value(f"{PREFIX}_runs_in_progress", target_id=target.id) == 0


@pytest.mark.asyncio
async def test_pipeline_updates_last_success_timestamp_metric(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    engine, session_ctx = _session_factory()
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_OkCollector(t)])
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)

    async def _skip(*a, **kw):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _skip)

    target = Target(
        id="freshness-target",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
        alerts={"enabled": False},
    )
    async with session_ctx() as session:
        run = Run(target_id=target.id, started_at=datetime.now(UTC), status=RunStatus.PENDING)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    before = _value(f"{PREFIX}_target_last_success_timestamp_seconds", target_id=target.id)
    await run_target_pipeline(target, run_id)
    after = _value(f"{PREFIX}_target_last_success_timestamp_seconds", target_id=target.id)

    assert after > before
    await engine.dispose()
