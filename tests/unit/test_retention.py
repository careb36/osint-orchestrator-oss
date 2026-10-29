"""
Unit tests for orchestrator/retention.py — Issue #16.
"""

from __future__ import annotations

import shutil
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.models import (
    AlertCase,
    AlertDelivery,
    AlertDeliveryStatus,
    AlertRecord,
    AlertStatus,
    Dossier,
    DossierRun,
    EvidenceQualification,
    FindingRecord,
    OpenCTIOutbox,
    OpenCTIOutboxStatus,
    Run,
    RunObservable,
    RunStatus,
    SeenObservable,
)
from orchestrator.retention import purge_expired
from orchestrator.scheduler import (
    register_alert_retry_job,
    register_opencti_outbox_job,
    register_retention_job,
    scheduler,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


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


NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=UTC)
OLD = NOW - timedelta(days=100)  # older than 90 days
RECENT = NOW - timedelta(days=10)  # newer than 90 days


# ─── Database purge tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_deletes_old_run_and_dependents(tmp_path, monkeypatch):
    """Old run (100 days) is purged with its dependents; recent run survives."""
    engine = _make_engine()
    await _setup_db(engine)

    async with AsyncSession(engine, expire_on_commit=False) as session:
        # Old run and its dependents
        old_run = Run(
            target_id="t1",
            started_at=OLD,
            finished_at=OLD,
            status=RunStatus.SUCCESS,
        )
        session.add(old_run)
        await session.commit()
        await session.refresh(old_run)

        session.add(
            RunObservable(
                run_id=old_run.id,
                stix_id="stix-old",
                stix_type="domain-name",
                value="old.example.com",
                is_new=True,
            )
        )
        session.add(
            FindingRecord(
                run_id=old_run.id,
                target_id="t1",
                summary="old",
                new_since_last_run="[]",
                suggested_pivots="[]",
            )
        )
        session.add(
            AlertRecord(
                run_id=old_run.id,
                channel="webhook",
                status=AlertStatus.SENT,
            )
        )
        session.add(
            AlertDelivery(
                run_id=old_run.id,
                target_id="t1",
                channel="webhook",
                payload_json="{}",
                status=AlertDeliveryStatus.PENDING,
            )
        )
        session.add(
            OpenCTIOutbox(
                run_id=old_run.id,
                target_id="t1",
                work_name="osint-orchestrator/t1/1",
                bundle_json='{"type":"bundle","id":"bundle--00000000-0000-4000-8000-000000000000","objects":[]}',
                status=OpenCTIOutboxStatus.PENDING,
            )
        )
        session.add(
            EvidenceQualification(run_id=old_run.id, target_id="t1", url="https://old.example/news")
        )

        # Recent run and its dependents
        recent_run = Run(
            target_id="t1",
            started_at=RECENT,
            finished_at=RECENT,
            status=RunStatus.SUCCESS,
        )
        session.add(recent_run)
        await session.commit()
        await session.refresh(recent_run)

        session.add(
            RunObservable(
                run_id=recent_run.id,
                stix_id="stix-new",
                stix_type="domain-name",
                value="new.example.com",
                is_new=False,
            )
        )
        session.add(
            FindingRecord(
                run_id=recent_run.id,
                target_id="t1",
                summary="new",
                new_since_last_run="[]",
                suggested_pivots="[]",
            )
        )
        session.add(
            EvidenceQualification(
                run_id=recent_run.id, target_id="t1", url="https://new.example/news"
            )
        )
        session.add(AlertCase(run_id=recent_run.id, target_id="t1", run_status="success"))

        # SeenObservable must survive
        session.add(
            SeenObservable(target_id="t1", stix_id="stix-delta", first_seen_run_id=old_run.id)
        )
        await session.commit()

    # Patch the database session used by retention
    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 90)
    monkeypatch.setattr(
        "orchestrator.retention.settings.targets_file", str(tmp_path / "notfound.yaml")
    )

    summary = await purge_expired(now=NOW)

    assert summary.runs_deleted == 1
    assert summary.run_observables_deleted == 1
    assert summary.findings_deleted == 1
    assert summary.alerts_deleted == 1
    assert summary.alert_deliveries_deleted == 1
    assert summary.opencti_outbox_deleted == 1
    assert summary.evidence_qualifications_deleted == 1
    assert summary.runs_retained_protected == 0

    # Verify DB state
    async with AsyncSession(engine, expire_on_commit=False) as session:
        runs = (await session.exec(select(Run))).all()
        assert len(runs) == 1
        assert runs[0].id == recent_run.id

        observables = (await session.exec(select(RunObservable))).all()
        assert len(observables) == 1
        assert observables[0].run_id == recent_run.id

        findings = (await session.exec(select(FindingRecord))).all()
        assert len(findings) == 1

        alerts = (await session.exec(select(AlertRecord))).all()
        assert len(alerts) == 0  # old alert gone
        alert_deliveries = (await session.exec(select(AlertDelivery))).all()
        assert len(alert_deliveries) == 0  # old queue rows gone
        outbox_rows = (await session.exec(select(OpenCTIOutbox))).all()
        assert len(outbox_rows) == 0
        evidence = (await session.exec(select(EvidenceQualification))).all()
        assert [row.run_id for row in evidence] == [recent_run.id]
        cases = (await session.exec(select(AlertCase))).all()
        assert [row.run_id for row in cases] == [recent_run.id]

        # seen_observables untouched
        seen = (await session.exec(select(SeenObservable))).all()
        assert len(seen) == 1, "seen_observables must not be deleted by retention"


@pytest.mark.asyncio
async def test_purge_keeps_runs_that_opened_an_alert_case(tmp_path, monkeypatch):
    """A run with an alert case is the compliance file: it survives the cutoff
    with its dependents and its report directory, while a case-less run of the
    same age is purged."""
    engine = _make_engine()
    await _setup_db(engine)

    reports = tmp_path / "daily_reports"
    kept_day = reports / "2026-06-01"  # the filed run started here
    purged_day = reports / "2026-05-01"  # only the case-less run started here
    kept_day.mkdir(parents=True)
    purged_day.mkdir(parents=True)
    filed_started = datetime(2026, 6, 1, 8, 0, tzinfo=UTC)
    plain_started = datetime(2026, 5, 1, 8, 0, tzinfo=UTC)

    async with AsyncSession(engine, expire_on_commit=False) as session:
        filed_run = Run(
            target_id="t1",
            started_at=filed_started,
            finished_at=filed_started,
            status=RunStatus.SUCCESS,
        )
        plain_run = Run(
            target_id="t1",
            started_at=plain_started,
            finished_at=plain_started,
            status=RunStatus.SUCCESS,
        )
        session.add(filed_run)
        session.add(plain_run)
        await session.commit()
        await session.refresh(filed_run)
        await session.refresh(plain_run)
        for run in (filed_run, plain_run):
            session.add(
                FindingRecord(
                    run_id=run.id,
                    target_id="t1",
                    summary="s",
                    new_since_last_run="[]",
                    suggested_pivots="[]",
                )
            )
            session.add(
                EvidenceQualification(
                    run_id=run.id, target_id="t1", url=f"https://e.example/{run.id}"
                )
            )
        session.add(
            AlertCase(
                run_id=filed_run.id,
                target_id="t1",
                run_status="success",
                acknowledged_by="Ana",
                note="falso positivo documentado",
            )
        )
        await session.commit()

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 30)
    monkeypatch.setattr(
        "orchestrator.retention.settings.targets_file", str(tmp_path / "notfound.yaml")
    )
    monkeypatch.setattr("orchestrator.retention._collect_report_dirs", lambda: {str(reports)})

    summary = await purge_expired(now=NOW)

    assert summary.runs_deleted == 1
    assert summary.runs_retained_protected == 1
    assert summary.findings_deleted == 1
    assert summary.evidence_qualifications_deleted == 1
    assert summary.report_dirs_deleted == 1
    assert kept_day.is_dir(), "the filed run's report directory must survive"
    assert not purged_day.exists()

    async with AsyncSession(engine, expire_on_commit=False) as session:
        runs = (await session.exec(select(Run))).all()
        assert [run.id for run in runs] == [filed_run.id]
        cases = (await session.exec(select(AlertCase))).all()
        assert len(cases) == 1 and cases[0].note == "falso positivo documentado"
        findings = (await session.exec(select(FindingRecord))).all()
        assert [row.run_id for row in findings] == [filed_run.id]
        evidence = (await session.exec(select(EvidenceQualification))).all()
        assert [row.run_id for row in evidence] == [filed_run.id]


@pytest.mark.asyncio
async def test_dossier_citation_keeps_a_contiguous_chain_prefix(tmp_path, monkeypatch):
    """A dossier-cited run must not leave a hole in the evidence chain.

    Excluding the cited runs from the purge one by one deletes the older
    uncited run and keeps the cited one, so verification reads the surviving
    chain as tampered (a gap in the middle is indistinguishable from a
    deleted manifest). Everything from the oldest protected run onward has to
    survive instead, exactly as the alert-case floor already does.
    """
    engine = _make_engine()
    await _setup_db(engine)

    reports = tmp_path / "daily_reports"
    days = [reports / f"2026-06-{day:02d}" for day in (1, 2, 3)]
    for day in days:
        day.mkdir(parents=True)

    started = [datetime(2026, 6, day, 8, 0, tzinfo=UTC) for day in (1, 2, 3)]
    async with AsyncSession(engine, expire_on_commit=False) as session:
        runs = [
            Run(target_id="t1", started_at=moment, finished_at=moment, status=RunStatus.SUCCESS)
            for moment in started
        ]
        for run in runs:
            session.add(run)
        await session.commit()
        for run in runs:
            await session.refresh(run)
        session.add(
            Dossier(id=1, title="d", entity_name="e", entity_type="org", purpose="p", owner_id=1)
        )
        # The middle run is cited: the purge may drop the older run, never the
        # newer one, or the chain loses its tail.
        session.add(DossierRun(dossier_id=1, run_id=runs[1].id))
        await session.commit()
        ids = [run.id for run in runs]

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 30)
    monkeypatch.setattr(
        "orchestrator.retention.settings.targets_file", str(tmp_path / "notfound.yaml")
    )
    monkeypatch.setattr("orchestrator.retention._collect_report_dirs", lambda: {str(reports)})

    summary = await purge_expired(now=datetime(2026, 8, 1, tzinfo=UTC))

    assert summary.runs_deleted == 1
    assert summary.runs_retained_protected == 2
    async with AsyncSession(engine, expire_on_commit=False) as session:
        survived = sorted(row.id for row in (await session.exec(select(Run))).all())
    assert survived == ids[1:], "the cited run and everything after it must survive"
    assert days[2].is_dir(), "the surviving newer run keeps its report directory"


@pytest.mark.asyncio
async def test_alert_case_and_dossier_citation_share_one_contiguous_floor(tmp_path, monkeypatch):
    """Both protections must collapse into the *earliest* of the two.

    Keeping each clause as its own exclusion is the bug this guards: the
    dossier clause alone would purge the runs that back an already-opened
    alert case, and the alert-case clause alone would purge runs a finalized
    dossier cites.

    Two targets, with the two protections in opposite order, so that dropping
    either clause changes the surviving set. A single target where one
    protection always sits first would pass under either mutant.
    """
    engine = _make_engine()
    await _setup_db(engine)

    reports = tmp_path / "daily_reports"
    days = [
        reports / f"2026-05-{day:02d}-{target}" for target in ("a", "b") for day in (1, 2, 3, 4)
    ]
    for day in days:
        day.mkdir(parents=True)

    async with AsyncSession(engine, expire_on_commit=False) as session:
        per_target: dict[str, list[Run]] = {}
        for target in ("a", "b"):
            runs = []
            for day in (1, 2, 3, 4):
                moment = datetime(2026, 5, day, 8, 0, tzinfo=UTC)
                run = Run(
                    target_id=target,
                    started_at=moment,
                    finished_at=moment,
                    status=RunStatus.SUCCESS,
                )
                session.add(run)
                runs.append(run)
            per_target[target] = runs
        await session.commit()
        for runs in per_target.values():
            for run in runs:
                await session.refresh(run)
        session.add(
            Dossier(id=1, title="d", entity_name="e", entity_type="org", purpose="p", owner_id=1)
        )
        # target "a": alert case on the oldest run, dossier cites the middle one.
        session.add(DossierRun(dossier_id=1, run_id=per_target["a"][1].id))
        session.add(
            AlertCase(
                run_id=per_target["a"][0].id,
                target_id="a",
                run_status="success",
                acknowledged_by="Ana",
                note="caso abierto a",
            )
        )
        # target "b": the mirror image -- dossier on the oldest, alert case on the middle.
        session.add(DossierRun(dossier_id=1, run_id=per_target["b"][0].id))
        session.add(
            AlertCase(
                run_id=per_target["b"][1].id,
                target_id="b",
                run_status="success",
                acknowledged_by="Ana",
                note="caso abierto b",
            )
        )
        await session.commit()
        ids = {target: [run.id for run in runs] for target, runs in per_target.items()}

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 30)
    monkeypatch.setattr(
        "orchestrator.retention.settings.targets_file", str(tmp_path / "notfound.yaml")
    )
    monkeypatch.setattr("orchestrator.retention._collect_report_dirs", lambda: {str(reports)})

    summary = await purge_expired(now=datetime(2026, 8, 1, tzinfo=UTC))

    # Both floors are the oldest run of their target, so nothing expires.
    assert summary.runs_deleted == 0
    assert summary.runs_retained_protected == 8
    async with AsyncSession(engine, expire_on_commit=False) as session:
        survived = sorted(row.id for row in (await session.exec(select(Run))).all())
        cases = {row.target_id: row.run_id for row in (await session.exec(select(AlertCase))).all()}
        cited = {row.run_id for row in (await session.exec(select(DossierRun))).all()}
    assert survived == sorted(ids["a"] + ids["b"]), "neither protection may purge the other"
    assert cases == {"a": ids["a"][0], "b": ids["b"][1]}, "an alert case lost its run"
    assert cited == {ids["a"][1], ids["b"][0]}, "a dossier lost its cited run"
    assert all(day.is_dir() for day in days), "every surviving run keeps its report directory"


def test_retention_is_disabled_by_default(monkeypatch):
    """A fresh Settings() never purges: evidence is kept until an operator
    sets a period on purpose."""
    from orchestrator.config import Settings

    monkeypatch.delenv("ORCHESTRATOR_RETENTION_DAYS", raising=False)
    assert Settings().orchestrator_retention_days == 0


# ─── Report directory purge tests ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_deletes_old_report_dirs_and_leaves_recent(tmp_path, monkeypatch):
    """Only directories whose ISO date is before the cutoff are deleted."""
    engine = _make_engine()
    await _setup_db(engine)

    reports = tmp_path / "daily_reports"
    old_dir = reports / "2026-01-01"
    recent_dir = reports / "2026-09-01"
    notes_dir = reports / "notes"

    for d in (old_dir, recent_dir, notes_dir):
        d.mkdir(parents=True)
        (d / "report.md").write_text("x")

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 90)
    monkeypatch.setattr(
        "orchestrator.retention.settings.targets_file", str(tmp_path / "notfound.yaml")
    )
    # Override _collect_report_dirs to return our tmp path
    monkeypatch.setattr(
        "orchestrator.retention._collect_report_dirs",
        lambda: {str(reports)},
    )

    summary = await purge_expired(now=NOW)

    assert summary.report_dirs_deleted == 1
    assert not old_dir.exists(), "old directory should be deleted"
    assert recent_dir.exists(), "recent directory must survive"
    assert notes_dir.exists(), "non-date directory must survive"


@pytest.mark.asyncio
async def test_retention_disabled_when_zero(tmp_path, monkeypatch):
    """retention_days=0 disables all purging."""
    engine = _make_engine()
    await _setup_db(engine)

    async with AsyncSession(engine, expire_on_commit=False) as session:
        run = Run(target_id="t1", started_at=OLD, finished_at=OLD, status=RunStatus.SUCCESS)
        session.add(run)
        await session.commit()

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 0)

    summary = await purge_expired(now=NOW)

    assert summary.runs_deleted == 0
    assert summary.report_dirs_deleted == 0

    async with AsyncSession(engine, expire_on_commit=False) as session:
        runs = (await session.exec(select(Run))).all()
        assert len(runs) == 1


@pytest.mark.asyncio
async def test_batch_delete_large_number_of_runs(tmp_path, monkeypatch):
    """1500 expired runs are all deleted even though each batch is only 500."""
    engine = _make_engine()
    await _setup_db(engine)

    n = 1500
    async with AsyncSession(engine, expire_on_commit=False) as session:
        for _i in range(n):
            session.add(
                Run(
                    target_id="t1",
                    started_at=OLD,
                    finished_at=OLD,
                    status=RunStatus.SUCCESS,
                )
            )
        await session.commit()

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 90)
    monkeypatch.setattr(
        "orchestrator.retention.settings.targets_file", str(tmp_path / "notfound.yaml")
    )

    summary = await purge_expired(now=NOW)

    assert summary.runs_deleted == n

    async with AsyncSession(engine, expire_on_commit=False) as session:
        remaining = (await session.exec(select(Run))).all()
        assert len(remaining) == 0


@pytest.mark.asyncio
async def test_filesystem_error_does_not_stop_other_dirs(tmp_path, monkeypatch):
    """An error deleting one directory does not prevent deletion of others."""
    engine = _make_engine()
    await _setup_db(engine)

    reports = tmp_path / "daily_reports"
    dir_a = reports / "2026-01-01"
    dir_b = reports / "2026-02-01"
    dir_a.mkdir(parents=True)
    dir_b.mkdir(parents=True)

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 90)
    monkeypatch.setattr(
        "orchestrator.retention.settings.targets_file", str(tmp_path / "notfound.yaml")
    )
    monkeypatch.setattr(
        "orchestrator.retention._collect_report_dirs",
        lambda: {str(reports)},
    )

    call_count = {"n": 0}

    def _failing_rmtree(path, *args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise OSError("permission denied")
        shutil.rmtree(path)

    monkeypatch.setattr("orchestrator.retention.shutil.rmtree", _failing_rmtree)

    # Must not raise
    summary = await purge_expired(now=NOW)

    # At least one dir should have been attempted
    assert call_count["n"] >= 1
    assert len(summary.errors) >= 1


async def _purge_with_runs(tmp_path, monkeypatch, runs: list[Run], dir_names: list[str]):
    engine = _make_engine()
    await _setup_db(engine)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        session.add_all(runs)
        await session.commit()

    reports = tmp_path / "daily_reports"
    for name in dir_names:
        (reports / name).mkdir(parents=True)
        (reports / name / "report.md").write_text("x")

    monkeypatch.setattr("orchestrator.retention.get_session", _session_factory(engine))
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 90)
    monkeypatch.setattr(
        "orchestrator.retention._collect_report_dirs",
        lambda: {str(reports)},
    )
    summary = await purge_expired(now=NOW)
    async with AsyncSession(engine, expire_on_commit=False) as session:
        kept = (await session.exec(select(Run))).all()
    return summary, reports, kept


@pytest.mark.asyncio
async def test_cutoff_day_directory_survives_while_its_later_runs_are_kept(tmp_path, monkeypatch):
    """The run row expires by finished_at, so its directory must not go by date alone."""
    cutoff = NOW - timedelta(days=90)  # 2026-06-11 12:00 UTC
    before = Run(
        target_id="t1",
        started_at=cutoff - timedelta(hours=2),
        finished_at=cutoff - timedelta(hours=1),
        status=RunStatus.SUCCESS,
    )
    after = Run(
        target_id="t1",
        started_at=cutoff + timedelta(hours=1),
        finished_at=cutoff + timedelta(hours=2),
        status=RunStatus.SUCCESS,
    )
    day = cutoff.strftime("%Y-%m-%d")
    previous_day = (cutoff - timedelta(days=1)).strftime("%Y-%m-%d")

    summary, reports, kept = await _purge_with_runs(
        tmp_path, monkeypatch, [before, after], [previous_day, day]
    )

    assert [run.started_at.hour for run in kept] == [13]
    assert (reports / day).exists(), "a kept run's report directory must survive"
    assert not (reports / previous_day).exists()
    assert summary.report_dirs_deleted == 1


@pytest.mark.asyncio
async def test_directory_of_a_surviving_old_run_is_not_deleted(tmp_path, monkeypatch):
    """A run that started long ago but finished inside the window keeps its directory."""
    long_run = Run(
        target_id="t1",
        started_at=NOW - timedelta(days=95),
        finished_at=NOW - timedelta(days=10),
        status=RunStatus.SUCCESS,
    )
    day = long_run.started_at.strftime("%Y-%m-%d")

    summary, reports, kept = await _purge_with_runs(tmp_path, monkeypatch, [long_run], [day])

    assert len(kept) == 1
    assert (reports / day).exists()
    assert summary.report_dirs_deleted == 0


@pytest.mark.asyncio
async def test_report_dirs_are_kept_when_surviving_runs_cannot_be_read(tmp_path, monkeypatch):
    reports = tmp_path / "daily_reports"
    old_dir = reports / "2026-01-01"
    old_dir.mkdir(parents=True)

    @asynccontextmanager
    async def _broken_session():
        raise RuntimeError("database is locked")
        yield  # pragma: no cover

    monkeypatch.setattr("orchestrator.retention.get_session", _broken_session)
    monkeypatch.setattr("orchestrator.retention.settings.orchestrator_retention_days", 90)
    monkeypatch.setattr(
        "orchestrator.retention._collect_report_dirs",
        lambda: {str(reports)},
    )

    summary = await purge_expired(now=NOW)

    assert old_dir.exists()
    assert summary.report_dirs_deleted == 0
    assert summary.errors == ["database", "report_dirs"]


# ─── Scheduler registration tests ─────────────────────────────────────────────


@pytest.fixture()
def clean_retention_job():
    yield
    if scheduler.get_job("retention"):
        scheduler.remove_job("retention")
    if scheduler.get_job("alert-retry"):
        scheduler.remove_job("alert-retry")
    if scheduler.get_job("opencti-outbox"):
        scheduler.remove_job("opencti-outbox")


def test_register_retention_job_registers_when_enabled(monkeypatch, clean_retention_job):
    monkeypatch.setattr("orchestrator.scheduler.settings.orchestrator_retention_days", 90)
    monkeypatch.setattr("orchestrator.scheduler.settings.orchestrator_retention_cron", "30 3 * * *")
    register_retention_job()
    assert scheduler.get_job("retention") is not None


def test_register_retention_job_skips_when_disabled(monkeypatch, clean_retention_job):
    monkeypatch.setattr("orchestrator.scheduler.settings.orchestrator_retention_days", 0)
    register_retention_job()
    assert scheduler.get_job("retention") is None


def test_register_alert_retry_job_registers_when_enabled(monkeypatch, clean_retention_job):
    monkeypatch.setattr("orchestrator.scheduler.settings.alert_retry_cron", "*/5 * * * *")
    register_alert_retry_job()
    assert scheduler.get_job("alert-retry") is not None


def test_register_opencti_outbox_job_registers_when_enabled(monkeypatch, clean_retention_job):
    monkeypatch.setattr("orchestrator.scheduler.settings.opencti_outbox_cron", "*/5 * * * *")
    register_opencti_outbox_job()
    assert scheduler.get_job("opencti-outbox") is not None
