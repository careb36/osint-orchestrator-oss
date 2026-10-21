"""
Scheduler job bodies and worker registration.

``test_scheduler_lifecycle.py`` covers target job registration. This module
covers what runs when a job fires: the scheduled run itself and the three
worker jobs (retention, alert retry, OpenCTI outbox), whose bodies must
never let an exception escape into APScheduler, where it would only reach
the scheduler's own logger and the next tick would look healthy.
"""

from __future__ import annotations

import logging

import pytest

import orchestrator.scheduler as scheduler_module
from orchestrator.config import settings
from orchestrator.models import Target
from orchestrator.scheduler import (
    preview_reload_targets,
    register_alert_retry_job,
    register_opencti_outbox_job,
    register_retention_job,
    register_targets,
    scheduler,
)


def _target(target_id: str, enabled: bool = True) -> Target:
    return Target(
        id=target_id,
        enabled=enabled,
        fqdn=f"{target_id}.example.com",
        authorization="self-owned",
        purpose="test",
    )


@pytest.fixture(autouse=True)
def clean_scheduler():
    yield
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)


# ── Scheduled target run ──────────────────────────────────────────────────────


async def test_scheduled_run_skips_when_target_already_has_an_active_run(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def _conflict(target_id: str) -> None:
        return None

    async def _pipeline_must_not_run(*_args) -> None:
        raise AssertionError("the pipeline must not start while a run is active")

    monkeypatch.setattr(scheduler_module, "create_pending_run", _conflict)
    monkeypatch.setattr(scheduler_module, "run_target_pipeline", _pipeline_must_not_run)

    with caplog.at_level(logging.INFO, logger="orchestrator.scheduler"):
        await scheduler_module._scheduled_run(_target("busy"))

    record = next(r for r in caplog.records if "Skipping scheduled run" in r.message)
    assert record.target_id == "busy"
    assert record.status == "conflict"


async def test_scheduled_run_executes_the_pipeline_with_the_new_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    async def _pending(target_id: str) -> int:
        return 42

    async def _pipeline(target: Target, run_id: int) -> None:
        calls.append((target.id, run_id))

    monkeypatch.setattr(scheduler_module, "create_pending_run", _pending)
    monkeypatch.setattr(scheduler_module, "run_target_pipeline", _pipeline)

    await scheduler_module._scheduled_run(_target("alpha"))

    assert calls == [("alpha", 42)]


def test_disabling_a_target_removes_its_existing_job() -> None:
    register_targets([_target("alpha")])
    assert scheduler.get_job("target-alpha") is not None

    register_targets([_target("alpha", enabled=False)])

    assert scheduler.get_job("target-alpha") is None


def test_preview_keeps_current_jobs_when_the_targets_file_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    register_targets([_target("alpha"), _target("beta")])
    monkeypatch.setattr(settings, "targets_file", str(tmp_path / "absent.yaml"))

    summary = preview_reload_targets()

    assert summary.as_dict() == {
        "added": 0,
        "updated": 0,
        "removed": 0,
        "unchanged": 2,
        "active_targets": 2,
        "invalid_targets": ["<targets-file>"],
        "targets_loaded": 0,
    }
    assert {j.id for j in scheduler.get_jobs()} == {"target-alpha", "target-beta"}


# ── Retention job ─────────────────────────────────────────────────────────────


def test_retention_job_is_not_registered_when_retention_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "orchestrator_retention_days", 0)
    register_retention_job()
    assert scheduler.get_job("retention") is None


def test_retention_job_is_not_registered_with_an_invalid_cron(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(settings, "orchestrator_retention_days", 30)
    monkeypatch.setattr(settings, "orchestrator_retention_cron", "every night")

    with caplog.at_level(logging.ERROR, logger="orchestrator.scheduler"):
        register_retention_job()

    assert scheduler.get_job("retention") is None
    record = next(r for r in caplog.records if "Invalid cron" in r.message)
    assert record.job == "retention"


def test_reregistering_the_retention_job_replaces_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "orchestrator_retention_days", 30)
    monkeypatch.setattr(settings, "orchestrator_retention_cron", "0 3 * * *")
    register_retention_job()
    monkeypatch.setattr(settings, "orchestrator_retention_cron", "30 4 * * *")
    register_retention_job()

    jobs = [j for j in scheduler.get_jobs() if j.id == "retention"]
    assert len(jobs) == 1
    assert str(jobs[0].trigger.fields[jobs[0].trigger.FIELD_NAMES.index("hour")]) == "4"


async def test_retention_job_body_runs_the_purge_and_swallows_its_errors(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import orchestrator.retention as retention_module

    calls: list[str] = []

    async def _purge() -> None:
        calls.append("purge")
        raise RuntimeError("disk full")

    monkeypatch.setattr(retention_module, "purge_expired", _purge)
    monkeypatch.setattr(settings, "orchestrator_retention_days", 30)
    monkeypatch.setattr(settings, "orchestrator_retention_cron", "0 3 * * *")
    register_retention_job()
    job = scheduler.get_job("retention")
    assert job is not None

    with caplog.at_level(logging.ERROR, logger="orchestrator.scheduler"):
        await job.func()

    assert calls == ["purge"]
    assert any("Retention job raised" in r.message for r in caplog.records)


# ── Alert retry job ───────────────────────────────────────────────────────────


def test_alert_retry_job_is_not_registered_with_an_invalid_cron(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "alert_retry_cron", "*/5 * * *")
    register_alert_retry_job()
    assert scheduler.get_job("alert-retry") is None


async def test_alert_retry_job_logs_only_when_it_processed_deliveries(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    summaries = [
        {"processed": 0, "sent": 0, "failed": 0},
        {"processed": 2, "sent": 1, "failed": 1},
    ]

    async def _process() -> dict[str, int]:
        return summaries.pop(0)

    monkeypatch.setattr(scheduler_module, "process_pending_alert_deliveries", _process)
    monkeypatch.setattr(settings, "alert_retry_cron", "*/5 * * * *")
    register_alert_retry_job()
    register_alert_retry_job()  # re-registration replaces, never duplicates
    assert [j.id for j in scheduler.get_jobs()].count("alert-retry") == 1
    job = scheduler.get_job("alert-retry")
    assert job is not None

    with caplog.at_level(logging.INFO, logger="orchestrator.scheduler"):
        await job.func()
        assert not any("processed deliveries" in r.message for r in caplog.records)
        await job.func()

    record = next(r for r in caplog.records if "processed deliveries" in r.message)
    assert record.component == "alerts-retry"
    assert record.processed == 2


async def test_alert_retry_job_body_swallows_errors(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def _process() -> dict[str, int]:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(scheduler_module, "process_pending_alert_deliveries", _process)
    monkeypatch.setattr(settings, "alert_retry_cron", "*/5 * * * *")
    register_alert_retry_job()
    job = scheduler.get_job("alert-retry")
    assert job is not None

    with caplog.at_level(logging.ERROR, logger="orchestrator.scheduler"):
        await job.func()

    assert any("Alert retry worker raised" in r.message for r in caplog.records)


# ── OpenCTI outbox job ────────────────────────────────────────────────────────


def test_outbox_job_is_not_registered_with_an_invalid_cron(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "opencti_enabled", True)
    monkeypatch.setattr(settings, "opencti_outbox_cron", "61 * * * *")
    register_opencti_outbox_job()
    assert scheduler.get_job("opencti-outbox") is None


async def test_outbox_job_logs_only_when_it_processed_bundles(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    summaries = [
        {"processed": 0, "sent": 0, "failed": 0, "dead_letter": 0},
        {"processed": 1, "sent": 1, "failed": 0, "dead_letter": 0},
    ]

    async def _drain() -> dict[str, int]:
        return summaries.pop(0)

    monkeypatch.setattr(scheduler_module, "drain_opencti_outbox", _drain)
    monkeypatch.setattr(settings, "opencti_enabled", True)
    monkeypatch.setattr(settings, "opencti_outbox_cron", "*/5 * * * *")
    register_opencti_outbox_job()
    register_opencti_outbox_job()
    assert [j.id for j in scheduler.get_jobs()].count("opencti-outbox") == 1
    job = scheduler.get_job("opencti-outbox")
    assert job is not None

    with caplog.at_level(logging.INFO, logger="orchestrator.scheduler"):
        await job.func()
        assert not any("processed bundles" in r.message for r in caplog.records)
        await job.func()

    record = next(r for r in caplog.records if "processed bundles" in r.message)
    assert record.component == "opencti-outbox"
    assert record.sent == 1


async def test_outbox_job_body_swallows_errors(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def _drain() -> dict[str, int]:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(scheduler_module, "drain_opencti_outbox", _drain)
    monkeypatch.setattr(settings, "opencti_enabled", True)
    monkeypatch.setattr(settings, "opencti_outbox_cron", "*/5 * * * *")
    register_opencti_outbox_job()
    job = scheduler.get_job("opencti-outbox")
    assert job is not None

    with caplog.at_level(logging.ERROR, logger="orchestrator.scheduler"):
        await job.func()

    assert any("OpenCTI outbox worker raised" in r.message for r in caplog.records)
