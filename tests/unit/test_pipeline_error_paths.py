"""
Error and edge paths of the pipeline that the end-to-end suites do not reach.

Each test pins one guard: a row that vanished between select and update, a
claim lost to a concurrent drain, a bundle that is not bundle-shaped, a
report that could not be written. These are the branches that decide
whether a bad tick is logged and survived or leaves a run stuck RUNNING.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from pytest_httpx import HTTPXMock
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

import orchestrator.pipeline as pipeline_module
from orchestrator.alerts import AlertEvent
from orchestrator.config import settings
from orchestrator.models import (
    AlertDelivery,
    AlertDeliveryStatus,
    CollectorName,
    CollectorResult,
    EvidenceItem,
    Observable,
    OpenCTIOutbox,
    OpenCTIOutboxStatus,
    Run,
    RunObservable,
    RunStatus,
    Target,
)
from orchestrator.pipeline import (
    _artefacts_for_manifest,
    _backfill_ingested,
    _bundle_object_ids,
    _delivery_record_failure,
    _delivery_record_success,
    _mark_run_failed,
    _ollama_reachable,
    _outbox_record_failure,
    _outbox_record_success,
    _qualification_client,
    _write_qualified_evidence_file,
    drain_opencti_outbox,
    process_pending_alert_deliveries,
    replay_alert_dead_letters,
    replay_opencti_dead_letters,
    run_target_pipeline,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _session_factory(engine):
    @asynccontextmanager
    async def _session():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    return _session


@pytest.fixture
async def db(monkeypatch: pytest.MonkeyPatch):
    """In-memory database bound to the pipeline, retry delays zeroed."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    session_ctx = _session_factory(engine)
    monkeypatch.setattr(pipeline_module, "get_session", session_ctx)
    for name in ("opencti_outbox_base_delay_seconds", "opencti_outbox_jitter_ratio"):
        monkeypatch.setattr(settings, name, 0.0)
    yield session_ctx
    await engine.dispose()


def _target(**overrides) -> Target:
    fields: dict = dict(
        id="target-1",
        fqdn="example.com",
        authorization="self-owned",
        purpose="test",
    )
    fields.update(overrides)
    return Target(**fields)


def _event(run_id: int) -> AlertEvent:
    return AlertEvent(
        target_id="target-1",
        target_fqdn="example.com",
        run_id=run_id,
        run_status="success",
        risk_level="high",
        new_observables=[],
        new_observable_count=1,
        report_path=None,
        finding_summary="test",
        generated_at=datetime.now(UTC),
    )


def _delivery(run_id: int, **overrides) -> AlertDelivery:
    fields: dict = dict(
        run_id=run_id,
        target_id="target-1",
        channel="webhook",
        language="en",
        payload_json=_event(run_id).model_dump_json(),
        status=AlertDeliveryStatus.PENDING,
        attempts=1,
        max_attempts=4,
    )
    fields.update(overrides)
    return AlertDelivery(**fields)


def _outbox_row(run_id: int, **overrides) -> OpenCTIOutbox:
    fields: dict = dict(
        run_id=run_id,
        target_id="target-1",
        work_name=f"osint-orchestrator/target-1/{run_id}",
        bundle_json='{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000000","objects":[]}',
        status=OpenCTIOutboxStatus.PENDING,
        attempts=1,
        max_attempts=6,
    )
    fields.update(overrides)
    return OpenCTIOutbox(**fields)


async def _add(session_ctx, *rows) -> list[int]:
    async with session_ctx() as session:
        session.add_all(rows)
        await session.commit()
        for row in rows:
            await session.refresh(row)
    return [row.id for row in rows]


async def _create_run(session_ctx, status: RunStatus = RunStatus.PENDING, **fields) -> int:
    run = Run(target_id="target-1", started_at=datetime.now(UTC), status=status, **fields)
    (run_id,) = await _add(session_ctx, run)
    return run_id


# ── LLM qualification gating ──────────────────────────────────────────────────


async def test_ollama_is_reachable_when_tags_answers(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "llm_base_url", "http://ollama.test")
    httpx_mock.add_response(url="http://ollama.test/api/tags", json={"models": []})
    assert await _ollama_reachable() is True


async def test_ollama_is_unreachable_on_an_error_status(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "llm_base_url", "http://ollama.test")
    httpx_mock.add_response(url="http://ollama.test/api/tags", status_code=503)
    assert await _ollama_reachable() is False


async def test_ollama_is_unreachable_when_the_connection_fails(
    httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "llm_base_url", "http://ollama.test")
    httpx_mock.add_exception(httpx.ConnectError("refused"))
    assert await _ollama_reachable() is False


class _Client:
    def __init__(self, provider: str) -> None:
        self.provider = provider


_EVIDENCE = [EvidenceItem(url="https://example.com/a", title="t", snippet="s", query="q")]


@pytest.mark.parametrize(
    ("enabled", "max_items", "evidence"),
    [(False, 30, _EVIDENCE), (True, 0, _EVIDENCE), (True, 30, [])],
    ids=["disabled", "zero-budget", "no-evidence"],
)
async def test_qualification_is_skipped_before_building_a_client(
    monkeypatch: pytest.MonkeyPatch, enabled: bool, max_items: int, evidence: list
) -> None:
    monkeypatch.setattr(settings, "llm_qualify_enabled", enabled)
    monkeypatch.setattr(settings, "llm_qualify_max_items", max_items)

    def _must_not_build(target):
        raise AssertionError("no client may be built when qualification is off")

    monkeypatch.setattr(pipeline_module, "get_client", _must_not_build)
    assert await _qualification_client(_target(), evidence) is None


async def test_qualification_is_skipped_without_a_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_qualify_enabled", True)
    monkeypatch.setattr(pipeline_module, "get_client", lambda target: None)
    assert await _qualification_client(_target(), _EVIDENCE) is None


@pytest.mark.parametrize(("reachable", "expected"), [(False, False), (True, True)])
async def test_ollama_qualification_requires_a_reachable_server(
    monkeypatch: pytest.MonkeyPatch, reachable: bool, expected: bool
) -> None:
    monkeypatch.setattr(settings, "llm_qualify_enabled", True)
    client = _Client("ollama")
    monkeypatch.setattr(pipeline_module, "get_client", lambda target: client)

    async def _probe() -> bool:
        return reachable

    monkeypatch.setattr(pipeline_module, "_ollama_reachable", _probe)
    assert (await _qualification_client(_target(), _EVIDENCE) is client) is expected


async def test_remote_qualification_does_not_probe_ollama(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_qualify_enabled", True)
    client = _Client("anthropic")
    monkeypatch.setattr(pipeline_module, "get_client", lambda target: client)

    async def _must_not_probe() -> bool:
        raise AssertionError("a remote provider must not probe the local Ollama server")

    monkeypatch.setattr(pipeline_module, "_ollama_reachable", _must_not_probe)
    assert await _qualification_client(_target(), _EVIDENCE) is client


# ── Report-directory helpers ──────────────────────────────────────────────────


def test_artefacts_and_qualified_evidence_need_a_report_path(tmp_path: Path) -> None:
    assert _artefacts_for_manifest(None) == {}
    _write_qualified_evidence_file(None, [], attempted=True)
    report = tmp_path / "report.md"
    report.write_text("# r", encoding="utf-8")
    _write_qualified_evidence_file(str(report), [], attempted=False)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.md"]


# ── Bundle ids and backfill ───────────────────────────────────────────────────


def test_bundle_object_ids_tolerates_shapes_that_are_not_bundles() -> None:
    assert _bundle_object_ids(object()) == set()
    bundle = {"objects": [7, {"id": ""}, {"type": "note"}, {"id": "domain-name--1"}]}
    assert _bundle_object_ids(bundle) == {"domain-name--1"}


async def test_backfill_is_a_noop_without_matching_rows(db) -> None:
    run_id = await _create_run(db)
    await _add(
        db,
        RunObservable(
            run_id=run_id,
            target_id="target-1",
            stix_id="domain-name--1",
            stix_type="domain-name",
            value="example.com",
            is_new=True,
            ingested=False,
        ),
    )
    async with db() as session:
        assert await _backfill_ingested(session, run_id, "target-1", set()) == 0
        assert await _backfill_ingested(session, run_id, "target-1", {"domain-name--2"}) == 0


# ── Rows that vanished between select and update ──────────────────────────────


async def test_record_helpers_tolerate_a_row_deleted_meanwhile(db) -> None:
    """Retention can purge a row while a drain is sending it."""
    error = RuntimeError("boom")
    await _outbox_record_success(999, 1, {"objects": []})
    assert await _outbox_record_failure(999, 1, error, transient=True) is False
    await _delivery_record_success(999, 1)
    assert await _delivery_record_failure(999, 1, error, permanent=False) is False


async def test_transient_outbox_failure_below_the_limit_stays_pending(db) -> None:
    (row_id,) = await _add(db, _outbox_row(1, attempts=1, max_attempts=6))

    dead = await _outbox_record_failure(row_id, 2, RuntimeError("timeout"), transient=True)

    assert dead is False
    async with db() as session:
        row = await session.get(OpenCTIOutbox, row_id)
    assert row is not None
    assert row.status == OpenCTIOutboxStatus.PENDING
    assert row.attempts == 2
    assert row.last_error == "timeout"
    assert row.next_retry_at is not None


# ── Drains ────────────────────────────────────────────────────────────────────


async def test_outbox_row_without_a_bundle_is_dead_lettered(db, monkeypatch) -> None:
    class _SinkMustNotBeCalled:
        async def ingest_async(self, *_args, **_kwargs) -> None:
            raise AssertionError("an empty row must not reach OpenCTI")

    monkeypatch.setattr(pipeline_module, "OpenCTISink", _SinkMustNotBeCalled)
    (row_id,) = await _add(db, _outbox_row(1, bundle_json=None))

    counts = await drain_opencti_outbox()

    assert counts == {"processed": 1, "sent": 0, "failed": 1, "dead_letter": 1}
    async with db() as session:
        row = await session.get(OpenCTIOutbox, row_id)
    assert row is not None
    assert row.status == OpenCTIOutboxStatus.DEAD_LETTER
    assert row.last_error == "outbox row carries no bundle"


async def test_drains_skip_rows_claimed_by_a_concurrent_drain(db, monkeypatch) -> None:
    await _add(db, _outbox_row(1), _delivery(1))

    async def _lost_claim(*_args) -> bool:
        return False

    monkeypatch.setattr(pipeline_module, "_claim_row", _lost_claim)

    assert (await drain_opencti_outbox())["processed"] == 0
    assert (await process_pending_alert_deliveries())["processed"] == 0
    async with db() as session:
        outbox = (await session.exec(select(OpenCTIOutbox))).one()
        delivery = (await session.exec(select(AlertDelivery))).one()
    assert outbox.status == OpenCTIOutboxStatus.PENDING
    assert delivery.status == AlertDeliveryStatus.PENDING


# ── Dead-letter replay ────────────────────────────────────────────────────────


async def test_outbox_replay_filters_by_run_and_resets_the_row(db) -> None:
    dead = dict(status=OpenCTIOutboxStatus.DEAD_LETTER, attempts=6, last_error="401")
    first, second = await _add(db, _outbox_row(1, **dead), _outbox_row(2, **dead))

    assert await replay_opencti_dead_letters(run_id=1) == {"moved": 1}

    async with db() as session:
        replayed = await session.get(OpenCTIOutbox, first)
        untouched = await session.get(OpenCTIOutbox, second)
    assert replayed is not None and untouched is not None
    assert (replayed.status, replayed.attempts, replayed.last_error) == (
        OpenCTIOutboxStatus.PENDING,
        0,
        None,
    )
    assert untouched.status == OpenCTIOutboxStatus.DEAD_LETTER


async def test_outbox_replay_limit_is_clamped_to_at_least_one(db) -> None:
    dead = dict(status=OpenCTIOutboxStatus.DEAD_LETTER)
    await _add(db, _outbox_row(1, **dead), _outbox_row(2, **dead))
    assert await replay_opencti_dead_letters(limit=0) == {"moved": 1}


async def test_alert_replay_filters_by_channel_and_run(db) -> None:
    dead = dict(status=AlertDeliveryStatus.DEAD_LETTER, attempts=4, last_error="410")
    await _add(
        db,
        _delivery(1, **dead),
        _delivery(1, channel="email", **dead),
        _delivery(2, **dead),
    )

    assert await replay_alert_dead_letters(channel="webhook", run_id=1) == {"moved": 1}

    async with db() as session:
        rows = (await session.exec(select(AlertDelivery))).all()
    states = {(r.run_id, r.channel): (r.status, r.attempts, r.last_error) for r in rows}
    assert states == {
        (1, "webhook"): (AlertDeliveryStatus.PENDING, 0, None),
        (1, "email"): (AlertDeliveryStatus.DEAD_LETTER, 4, "410"),
        (2, "webhook"): (AlertDeliveryStatus.DEAD_LETTER, 4, "410"),
    }


# ── Marking a run failed ──────────────────────────────────────────────────────


async def test_mark_run_failed_seals_an_open_run(db) -> None:
    run_id = await _create_run(db, status=RunStatus.RUNNING)

    await _mark_run_failed(run_id, "pipeline: boom", {})

    async with db() as session:
        run = await session.get(Run, run_id)
    assert run is not None
    assert run.status == RunStatus.FAILED
    assert run.error == "pipeline: boom"
    assert run.finished_at is not None


async def test_mark_run_failed_keeps_a_sealed_status_and_appends_the_error(db) -> None:
    run_id = await _create_run(db, status=RunStatus.SUCCESS, error="tavily: quota")

    await _mark_run_failed(run_id, "alerts: boom", {})

    async with db() as session:
        run = await session.get(Run, run_id)
    assert run is not None
    assert run.status == RunStatus.SUCCESS
    assert run.error == "tavily: quota; alerts: boom"


async def test_mark_run_failed_tolerates_a_missing_run(db) -> None:
    await _mark_run_failed(999, "pipeline: boom", {})


async def test_mark_run_failed_never_masks_the_original_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    @asynccontextmanager
    async def _broken_session():
        raise RuntimeError("database is locked")
        yield  # pragma: no cover

    monkeypatch.setattr(pipeline_module, "get_session", _broken_session)

    with caplog.at_level(logging.ERROR, logger="orchestrator.pipeline"):
        await _mark_run_failed(7, "pipeline: boom", {"run_id": 7})

    record = next(r for r in caplog.records if "Could not mark run 7" in r.message)
    assert record.run_id == 7


# ── Whole-run edge paths ──────────────────────────────────────────────────────


async def test_pipeline_returns_quietly_when_the_run_row_is_gone(
    db, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="orchestrator.pipeline"):
        await run_target_pipeline(_target(), 999)

    assert any(r.message == "Run 999 not found" for r in caplog.records)


class _Collector:
    def __init__(self, name: CollectorName, target: Target) -> None:
        self.name = name
        self.target = target

    async def collect(self) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target_fqdn=self.target.fqdn,
            observables=[Observable(type="domain-name", value=self.target.fqdn)],
            success=True,
        )


async def test_report_failure_keeps_the_status_and_records_the_error(
    db, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """
    Two collectors report the same domain; it must be stored once. The report
    then fails to render: the run keeps its collection status, records why
    there is no report, and is left unsealed instead of stuck RUNNING.
    """
    monkeypatch.setattr(settings, "opencti_enabled", False)
    monkeypatch.setattr(
        pipeline_module,
        "_get_collectors",
        lambda t: [_Collector(CollectorName.OPENOSINT, t), _Collector(CollectorName.AMASS, t)],
    )

    async def _skip_synthesize(*_args, **_kwargs):
        return None, "skipped"

    async def _broken_report(*_args, **_kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr(pipeline_module, "synthesize", _skip_synthesize)
    monkeypatch.setattr(pipeline_module, "generate_report", _broken_report)

    target = _target(report_dir=str(tmp_path))
    run_id = await _create_run(db)
    await run_target_pipeline(target, run_id)

    async with db() as session:
        run = await session.get(Run, run_id)
        observables = (
            await session.exec(select(RunObservable).where(RunObservable.run_id == run_id))
        ).all()
    assert run is not None
    assert run.status == RunStatus.SUCCESS
    assert run.error == "report-generation: read-only file system"
    assert run.report_path is None
    assert run.manifest_sha256 is None
    assert [o.value for o in observables] == ["example.com"]
