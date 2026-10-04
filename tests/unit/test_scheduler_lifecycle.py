"""
Tests that the scheduler is actually wired into the application lifespan.

`scheduler.py` was fully implemented but `start_scheduler()` was never called
from anywhere, so the cron in targets.yaml was never registered and the
orchestrator only ran when POST /targets/{id}/run was invoked by hand. These
tests fail if that regresses.
"""

from __future__ import annotations

import asyncio

import pytest

from orchestrator.api import app, lifespan
from orchestrator.models import Target
from orchestrator.scheduler import register_targets, scheduler


async def _wait_until_stopped(timeout: float = 2.0) -> bool:
    """
    AsyncIOScheduler.shutdown(wait=False) completes on a later loop iteration.

    That is the behaviour we want inside an async lifespan — a blocking
    shutdown would stall application teardown — so poll rather than assert
    on the state immediately after the call.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if not scheduler.running:
            return True
        await asyncio.sleep(0.01)
    return not scheduler.running


async def test_lifespan_starts_and_stops_the_scheduler() -> None:
    assert not scheduler.running, "scheduler leaked from an earlier test"
    async with lifespan(app):
        assert scheduler.running, "lifespan must start the scheduler"
    assert await _wait_until_stopped(), "lifespan must stop the scheduler on exit"


def _target(target_id: str, cron: str = "0 8 * * *", enabled: bool = True) -> Target:
    t = Target(
        id=target_id,
        enabled=enabled,
        fqdn=f"{target_id}.example.com",
        authorization="self-owned",
        purpose="test",
    )
    t.schedule.cron = cron
    return t


@pytest.fixture
def clean_scheduler():
    yield
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)


def test_enabled_targets_get_a_job(clean_scheduler) -> None:
    register_targets([_target("alpha"), _target("beta")])
    assert {j.id for j in scheduler.get_jobs()} == {"target-alpha", "target-beta"}


def test_disabled_targets_get_no_job(clean_scheduler) -> None:
    register_targets([_target("gamma", enabled=False)])
    assert scheduler.get_jobs() == []


def test_invalid_cron_is_skipped_not_raised(clean_scheduler) -> None:
    """A malformed cron in one target must not stop the others registering."""
    register_targets([_target("bad", cron="not a cron"), _target("good")])
    assert {j.id for j in scheduler.get_jobs()} == {"target-good"}


def test_invalid_cron_removes_any_preexisting_job(clean_scheduler) -> None:
    """A target that used to be valid must not keep its old cron after it becomes invalid."""
    register_targets([_target("stale", cron="0 8 * * *")])
    register_targets([_target("stale", cron="not a cron")])
    assert scheduler.get_jobs() == []


def test_invalid_numeric_cron_values_are_rejected(clean_scheduler) -> None:
    """Cron expressions with out-of-range fields must not register a broken trigger."""
    register_targets([_target("bad-range", cron="00 25 * * *"), _target("good")])
    assert {j.id for j in scheduler.get_jobs()} == {"target-good"}


def test_reregistering_replaces_rather_than_duplicates(clean_scheduler) -> None:
    register_targets([_target("delta", cron="0 8 * * *")])
    register_targets([_target("delta", cron="0 9 * * *")])
    jobs = scheduler.get_jobs()
    assert len(jobs) == 1
    assert str(jobs[0].trigger).find("hour='9'") != -1


def test_removed_targets_are_pruned_from_scheduler(clean_scheduler) -> None:
    register_targets([_target("alpha"), _target("beta")])
    register_targets([_target("alpha")])

    assert {j.id for j in scheduler.get_jobs()} == {"target-alpha"}


async def test_start_scheduler_is_idempotent(clean_scheduler) -> None:
    assert not scheduler.running
    from orchestrator.scheduler import shutdown_scheduler, start_scheduler

    start_scheduler()
    assert scheduler.running
    start_scheduler()
    assert scheduler.running

    shutdown_scheduler()
    assert await _wait_until_stopped(), "shutdown_scheduler must stop the scheduler"


def test_missing_or_malformed_targets_file_is_a_load_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """
    reload_targets() keeps the current jobs when loading fails and replaces
    them when it succeeds. A missing file used to count as "zero targets",
    so a ConfigMap remount or an editor's atomic rename during a reload
    removed every schedule.
    """
    from orchestrator.config import settings
    from orchestrator.scheduler import _load_targets

    monkeypatch.setattr(settings, "targets_file", str(tmp_path / "absent.yaml"))
    assert _load_targets() == ([], ["<targets-file>"], True)

    bad = tmp_path / "list.yaml"
    bad.write_text("- not\n- a mapping\n", encoding="utf-8")
    monkeypatch.setattr(settings, "targets_file", str(bad))
    assert _load_targets() == ([], ["<targets-file>"], True)
