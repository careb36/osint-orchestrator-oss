"""Error paths of the run endpoints, the manual-run trigger and the request middleware.

The run endpoints are driven through ``httpx.AsyncClient`` on the test's own
event loop rather than ``TestClient``: a handler that awaits inside the test
client's portal thread is not traced by coverage past its first ``await``.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.api as api_mod
from orchestrator import metrics
from orchestrator.api import app
from orchestrator.config import settings
from orchestrator.metrics import PREFIX
from orchestrator.models import Run, RunStatus, Target


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    return _session


@pytest.fixture
async def db(monkeypatch: pytest.MonkeyPatch):
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(api_mod, "get_session", session_ctx)
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    yield session_ctx
    await engine.dispose()


async def _add_run(db, **fields) -> int:
    async with db() as session:
        run = Run(target_id="t1", started_at=datetime.now(UTC), status=RunStatus.SUCCESS, **fields)
        session.add(run)
        await session.commit()
        await session.refresh(run)
        return int(run.id)


def _client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.parametrize(
    "suffix",
    ["", "/delta", "/report", "/finding", "/evidence", "/manifest", "/report.pdf", "/bundle"],
)
async def test_every_run_endpoint_answers_404_for_an_unknown_run(db, suffix: str) -> None:
    async with _client() as client:
        res = await client.get(f"/runs/424242{suffix}")
    assert res.status_code == 404
    assert "424242" in res.json()["detail"]


async def test_report_is_404_when_the_run_has_no_report_path(db) -> None:
    run_id = await _add_run(db, report_path=None)
    async with _client() as client:
        res = await client.get(f"/runs/{run_id}/report")
    assert res.status_code == 404


async def test_report_is_404_when_the_file_vanished_or_is_a_directory(db, tmp_path: Path) -> None:
    gone = await _add_run(db, report_path=str(tmp_path / "purged" / "report.md"))
    directory = await _add_run(db, report_path=str(tmp_path))
    async with _client() as client:
        res_gone = await client.get(f"/runs/{gone}/report")
        res_dir = await client.get(f"/runs/{directory}/report")
    assert (res_gone.status_code, res_dir.status_code) == (404, 404)


async def test_report_serves_the_markdown_as_text(db, tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Daily report\n", encoding="utf-8")
    run_id = await _add_run(db, report_path=str(report))
    async with _client() as client:
        res = await client.get(f"/runs/{run_id}/report")
    assert res.status_code == 200
    assert res.text == "# Daily report\n"
    assert res.headers["content-type"].startswith("text/plain")


async def test_pdf_and_manifest_are_404_when_the_run_has_no_files(db, tmp_path: Path) -> None:
    run_id = await _add_run(db, report_path=str(tmp_path / "report.md"), manifest_sha256="ab" * 32)
    async with _client() as client:
        pdf = await client.get(f"/runs/{run_id}/report.pdf")
        manifest = await client.get(f"/runs/{run_id}/manifest")
        bundle = await client.get(f"/runs/{run_id}/bundle")
    assert (pdf.status_code, manifest.status_code, bundle.status_code) == (404, 404, 404)


def _target(target_id: str, enabled: bool = True) -> Target:
    return Target(
        id=target_id,
        enabled=enabled,
        fqdn=f"{target_id}.example.com",
        authorization="self-owned",
        purpose="test",
    )


async def test_manual_run_answers_404_400_and_409(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    monkeypatch.setattr(api_mod, "_load_targets", lambda: [_target("on"), _target("off", False)])

    async def no_slot(target_id: str) -> int | None:
        return None

    monkeypatch.setattr(api_mod, "create_pending_run", no_slot)
    async with _client() as client:
        unknown = await client.post("/targets/nope/run")
        disabled = await client.post("/targets/off/run")
        busy = await client.post("/targets/on/run")
    assert unknown.status_code == 404
    assert disabled.status_code == 400
    assert busy.status_code == 409
    assert "on" in busy.json()["detail"]


def test_openapi_describes_every_tag_in_use() -> None:
    with TestClient(app) as client:
        schema = client.get("/openapi.json").json()
    described = {tag["name"] for tag in schema["tags"]}
    used = {
        tag
        for path in schema["paths"].values()
        for op in path.values()
        for tag in op.get("tags", [])
    }
    assert used <= described, used - described


def test_request_latency_stops_when_the_response_is_sent_not_after_background_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "orchestrator_api_key", "")
    monkeypatch.setattr(api_mod, "_load_targets", lambda: [_target("bg")])

    async def pending(target_id: str) -> int:
        return 7

    async def slow_pipeline(target: Target, run_id: int) -> None:
        await asyncio.sleep(0.4)

    monkeypatch.setattr(api_mod, "create_pending_run", pending)
    monkeypatch.setattr(api_mod, "run_target_pipeline", slow_pipeline)
    labels = {"method": "POST", "path": "/targets/{target_id}/run"}
    sum_before = metrics.sample(f"{PREFIX}_http_request_duration_seconds_sum", labels) or 0.0
    count_before = (
        metrics.sample(f"{PREFIX}_http_requests_total", {**labels, "status": "202"}) or 0.0
    )

    with TestClient(app, raise_server_exceptions=True) as client:
        started = perf_counter()
        res = client.post("/targets/bg/run")
        elapsed = perf_counter() - started

    assert res.status_code == 202
    assert elapsed >= 0.35, "the test client waits for the background task"
    observed = (
        metrics.sample(f"{PREFIX}_http_request_duration_seconds_sum", labels) or 0.0
    ) - sum_before
    assert observed < 0.25, f"latency included the background task: {observed:.3f}s"
    assert (
        metrics.sample(f"{PREFIX}_http_requests_total", {**labels, "status": "202"})
        == count_before + 1
    )
