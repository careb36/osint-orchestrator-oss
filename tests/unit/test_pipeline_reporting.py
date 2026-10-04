from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator.models import (
    CollectorName,
    CollectorResult,
    Observable,
    Run,
    RunObservable,
    RunStatus,
    Target,
)
from orchestrator.pipeline import run_target_pipeline


class _FakeCollector:
    name = CollectorName.OPENOSINT

    def __init__(self, target: Target) -> None:
        self.target = target

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[
                Observable(type="domain-name", value=self.target.fqdn),
                Observable(type="email-addr", value=f"admin@{self.target.fqdn}"),
            ],
            success=True,
        )


@pytest.mark.asyncio
async def test_run_target_pipeline_persists_report_and_delta_across_two_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    monkeypatch.setattr(pipeline_module, "get_session", _session)
    monkeypatch.setattr(
        pipeline_module,
        "_get_collectors",
        lambda target: [_FakeCollector(target)],
    )

    # Stub out the synthesizer: this test exercises collection and reporting,
    # not LLM synthesis.  Without the stub, synthesize tries to reach Ollama.
    async def _no_synthesize(*args, **kwargs):
        return None, "skipped"

    monkeypatch.setattr(pipeline_module, "synthesize", _no_synthesize)

    ingest_mock = MagicMock()

    class _FakeSink:
        def ingest(self, bundle, work_name: str = "osint-orchestrator", **_: object) -> None:
            ingest_mock(bundle, work_name)

        async def ingest_async(
            self, bundle, *, work_name: str = "osint-orchestrator", **_: object
        ) -> None:
            ingest_mock(bundle, work_name)

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _FakeSink)

    target = Target(
        id="pipeline-target",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )

    async def _create_run() -> int:
        async with _session() as session:
            run = Run(
                target_id=target.id,
                started_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
                status=RunStatus.PENDING,
            )
            session.add(run)
            await session.commit()
            await session.refresh(run)
            assert run.id is not None
            return run.id

    first_run_id = await _create_run()
    await run_target_pipeline(target, first_run_id)

    async with _session() as session:
        first_run = await session.get(Run, first_run_id)
        assert first_run is not None
        assert first_run.status == RunStatus.SUCCESS
        assert first_run.new_observables == 2
        assert first_run.report_path is not None
        first_report_path = Path(first_run.report_path)
        assert first_report_path.exists()

        first_rows = (
            await session.exec(select(RunObservable).where(RunObservable.run_id == first_run_id))
        ).all()
        assert len(first_rows) == 2
        assert all(row.is_new for row in first_rows)

    second_run_id = await _create_run()
    await run_target_pipeline(target, second_run_id)

    async with _session() as session:
        second_run = await session.get(Run, second_run_id)
        assert second_run is not None
        assert second_run.status == RunStatus.SUCCESS
        assert second_run.new_observables == 0
        assert second_run.report_path is not None
        second_report_path = Path(second_run.report_path)
        assert second_report_path.exists()
        delta = json.loads((second_report_path.parent / "delta.json").read_text(encoding="utf-8"))
        assert delta == []

        second_rows = (
            await session.exec(select(RunObservable).where(RunObservable.run_id == second_run_id))
        ).all()
        assert len(second_rows) == 2
        assert all(not row.is_new for row in second_rows)

    assert ingest_mock.call_count == 2


@pytest.mark.asyncio
async def test_pipeline_with_fake_synthesizer_persists_finding_and_fills_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When a fake synthesizer returns a Finding, it is persisted to the DB and
    the synthesis section in report.md contains the summary and risk level.
    """
    import orchestrator.synthesizer as synth_module
    from orchestrator.models import Finding, FindingRecord

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=True) as session:
            yield session

    monkeypatch.setattr(pipeline_module, "get_session", _session)
    monkeypatch.setattr(pipeline_module, "_get_collectors", lambda t: [_FakeCollector(t)])
    monkeypatch.setattr(pipeline_module, "OpenCTISink", AsyncMock)
    monkeypatch.setattr(synth_module, "get_session", _session)

    async def _fake_synthesize(target, run_id, report_data):
        f = Finding(
            target_id=target.id,
            run_id=run_id,
            summary="Superficie de ataque reducida.",
            risk_level="medium",
            risk_justification="Puerto 443 expuesto públicamente.",
            suggested_pivots=["Auditar certificado TLS"],
        )
        await synth_module._persist_finding(
            f, provider="fake", model="fake-model", duration_ms=0, raw_response="{}"
        )
        return f, "ok"

    monkeypatch.setattr(pipeline_module, "synthesize", _fake_synthesize)

    target = Target(
        id="synth-target",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
        report_dir=str(tmp_path),
    )

    async with _session() as session:
        run = Run(
            target_id=target.id,
            started_at=datetime(2026, 9, 8, 12, 0, tzinfo=UTC),
            status=RunStatus.PENDING,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        run_id = run.id

    await run_target_pipeline(target, run_id)

    # Finding is in the DB.
    async with _session() as session:
        result = await session.exec(select(FindingRecord).where(FindingRecord.run_id == run_id))
        record = result.first()
    assert record is not None
    assert record.risk_level == "medium"

    # Finding is in the report.
    async with _session() as session:
        run_db = await session.get(Run, run_id)
    assert run_db is not None and run_db.report_path is not None
    report_text = Path(run_db.report_path).read_text(encoding="utf-8")
    assert "## Síntesis" in report_text
    assert "Superficie de ataque reducida." in report_text
    assert "`medium`" in report_text
    assert "Auditar certificado TLS" in report_text
