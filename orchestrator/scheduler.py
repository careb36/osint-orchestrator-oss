"""
APScheduler-based scheduler that reads targets.yaml and schedules cron jobs.

Rules:
  - max_instances=1 per target: never run the same target twice in parallel.
  - coalesce=True: if a run was missed, run once on recovery (not multiple times).
  - misfire_grace_time: from target config (default 1 h).
  - Jobs are re-scheduled on startup from targets.yaml.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from orchestrator import metrics
from orchestrator.config import settings
from orchestrator.models import Target
from orchestrator.pipeline import (
    drain_opencti_outbox,
    process_pending_alert_deliveries,
    run_target_pipeline,
)
from orchestrator.run_control import create_pending_run
from orchestrator.targets import load_targets

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone="UTC")


@dataclass
class TargetReloadSummary:
    """Diff between the scheduler's current jobs and targets.yaml.

    Returned by both ``preview_reload_targets`` (no mutation) and
    ``reload_targets`` (applied); the API serialises it verbatim.
    """

    added: int
    updated: int
    removed: int
    unchanged: int
    active_targets: int
    invalid_targets: list[str]
    targets_loaded: int

    def as_dict(self) -> dict[str, object]:
        """Return the summary as a JSON-serialisable dict."""
        return asdict(self)


def _build_cron_trigger(cron_expr: str, *, context: str, job_id: str) -> CronTrigger | None:
    """Build a cron trigger, returning None for invalid expressions without crashing the loop."""
    parts = cron_expr.strip().split()
    if len(parts) != 5:
        logger.error("Invalid cron for %s %s: %s", context, job_id, cron_expr)
        return None

    try:
        return CronTrigger(
            minute=parts[0],
            hour=parts[1],
            day=parts[2],
            month=parts[3],
            day_of_week=parts[4],
            timezone="UTC",
        )
    except ValueError:
        logger.error("Invalid cron for %s %s: %s", context, job_id, cron_expr)
        return None


def _target_schedule_signature(trigger: CronTrigger, grace: int) -> tuple[str, int]:
    """Fingerprint a job's schedule so reloads can detect real changes only."""
    return (str(trigger), grace)


def _load_targets() -> tuple[list[Target], list[str], bool]:
    """Load targets centrally and report whether the targets file itself failed."""
    loaded_targets, invalid_targets = load_targets(settings.targets_file)
    load_failed = "<targets-file>" in invalid_targets
    if load_failed:
        return [], ["<targets-file>"], True
    return loaded_targets, invalid_targets, False


async def _scheduled_run(target: Target) -> None:
    """Create a Run record (if allowed) and execute the pipeline."""
    run_id = await create_pending_run(target.id)
    if run_id is None:
        logger.info(
            "Skipping scheduled run due to active run",
            extra={"target_id": target.id, "trigger": "scheduler", "status": "conflict"},
        )
        return

    logger.info(
        "Scheduled run started: target=%s run_id=%d",
        target.id,
        run_id,
        extra={"target_id": target.id, "run_id": run_id, "trigger": "scheduler"},
    )
    await run_target_pipeline(target, run_id)


def register_targets(targets: list[Target]) -> None:
    """Register or replace jobs for enabled targets and remove stale ones."""
    desired_ids = {target.id for target in targets if target.enabled}

    for target in targets:
        job_id = f"target-{target.id}"
        if not target.enabled:
            logger.debug("Skipping disabled target: %s", target.id)
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)
            continue

        cron_expr = target.schedule.cron
        grace = target.schedule.misfire_grace_time_seconds

        trigger = _build_cron_trigger(cron_expr, context="target", job_id=target.id)
        if trigger is None:
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)
            continue

        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)

        scheduler.add_job(
            _scheduled_run,
            trigger=trigger,
            args=[target],
            id=job_id,
            name=f"OSINT run: {target.id}",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=grace,
            replace_existing=True,
        )
        logger.info(
            "Scheduled target '%s' with cron '%s' (grace=%ds)",
            target.id,
            cron_expr,
            grace,
            extra={"target_id": target.id, "cron": cron_expr},
        )

    for job in list(scheduler.get_jobs()):
        if job.id.startswith("target-") and job.id.removeprefix("target-") not in desired_ids:
            scheduler.remove_job(job.id)

    metrics.scheduled_jobs.set(len(scheduler.get_jobs()))


def _current_target_signatures() -> dict[str, tuple[str, int]]:
    """Snapshot the schedule signature of every registered target job."""
    current_jobs = {
        job.id.removeprefix("target-"): job
        for job in scheduler.get_jobs()
        if job.id.startswith("target-")
    }
    return {
        target_id: _target_schedule_signature(job.trigger, int(job.misfire_grace_time or 0))
        for target_id, job in current_jobs.items()
    }


def _desired_target_signatures(
    targets: list[Target], invalid_targets: list[str]
) -> dict[str, tuple[str, int]]:
    """Compute the schedule signatures targets.yaml wants; collect invalid ones."""
    desired_signatures: dict[str, tuple[str, int]] = {}
    for target in targets:
        if not target.enabled:
            continue
        trigger = _build_cron_trigger(target.schedule.cron, context="target", job_id=target.id)
        if trigger is None:
            invalid_targets.append(target.id)
            continue
        desired_signatures[target.id] = _target_schedule_signature(
            trigger, target.schedule.misfire_grace_time_seconds
        )
    return desired_signatures


def _build_reload_summary(
    *,
    before_signatures: dict[str, tuple[str, int]],
    desired_signatures: dict[str, tuple[str, int]],
    invalid_targets: list[str],
    targets_loaded: int,
) -> TargetReloadSummary:
    """Classify targets as added/updated/removed/unchanged from the two snapshots."""
    before_ids = set(before_signatures.keys())
    desired_ids = set(desired_signatures.keys())
    added = len(desired_ids - before_ids)
    removed = len(before_ids - desired_ids)
    updated = sum(
        1
        for target_id in desired_ids & before_ids
        if before_signatures.get(target_id) != desired_signatures.get(target_id)
    )
    unchanged = len(desired_ids & before_ids) - updated
    return TargetReloadSummary(
        added=added,
        updated=updated,
        removed=removed,
        unchanged=unchanged,
        active_targets=len(desired_ids),
        invalid_targets=sorted(set(invalid_targets)),
        targets_loaded=targets_loaded,
    )


def preview_reload_targets() -> TargetReloadSummary:
    """Return the target reload summary without mutating scheduler jobs."""
    before_signatures = _current_target_signatures()
    targets, invalid_targets, load_failed = _load_targets()
    if load_failed:
        return TargetReloadSummary(
            added=0,
            updated=0,
            removed=0,
            unchanged=len(before_signatures),
            active_targets=len(before_signatures),
            invalid_targets=sorted(set(invalid_targets)),
            targets_loaded=0,
        )

    desired_signatures = _desired_target_signatures(targets, invalid_targets)
    return _build_reload_summary(
        before_signatures=before_signatures,
        desired_signatures=desired_signatures,
        invalid_targets=invalid_targets,
        targets_loaded=len(targets),
    )


def reload_targets() -> TargetReloadSummary:
    """Reload targets from settings.targets_file and update scheduler target jobs."""
    before_signatures = _current_target_signatures()
    targets, invalid_targets, load_failed = _load_targets()
    if load_failed:
        return TargetReloadSummary(
            added=0,
            updated=0,
            removed=0,
            unchanged=len(before_signatures),
            active_targets=len(before_signatures),
            invalid_targets=sorted(set(invalid_targets)),
            targets_loaded=0,
        )

    desired_signatures = _desired_target_signatures(targets, invalid_targets)
    summary = _build_reload_summary(
        before_signatures=before_signatures,
        desired_signatures=desired_signatures,
        invalid_targets=invalid_targets,
        targets_loaded=len(targets),
    )
    register_targets(targets)
    return summary


def register_retention_job() -> None:
    """Register the nightly retention/purge job (id ``retention``).

    No-op when ``orchestrator_retention_days`` is 0 (retention disabled).
    """
    retention_days = settings.orchestrator_retention_days
    if retention_days <= 0:
        logger.info("Retention disabled — purge job not registered")
        return

    from orchestrator.retention import purge_expired

    cron_expr = settings.orchestrator_retention_cron
    trigger = _build_cron_trigger(cron_expr, context="retention", job_id="retention")
    if trigger is None:
        return

    async def _run_purge() -> None:
        try:
            await purge_expired()
        except Exception:
            logger.exception("Retention job raised an unexpected exception")

    job_id = "retention"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        _run_purge,
        trigger=trigger,
        id=job_id,
        name="Retention: purge old runs and reports",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    logger.info(
        "Retention job registered (cron='%s', retention_days=%d)",
        cron_expr,
        retention_days,
    )


def register_alert_retry_job() -> None:
    """Register the alert retry worker job (id ``alert-retry``)."""
    cron_expr = settings.alert_retry_cron
    trigger = _build_cron_trigger(cron_expr, context="alerts-retry", job_id="alert-retry")
    if trigger is None:
        return

    async def _run_retries() -> None:
        try:
            summary = await process_pending_alert_deliveries()
            if summary["processed"] > 0:
                logger.info(
                    "Alert retry worker processed deliveries",
                    extra={"component": "alerts-retry", **summary},
                )
        except Exception:
            logger.exception("Alert retry worker raised an unexpected exception")

    job_id = "alert-retry"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        _run_retries,
        trigger=trigger,
        id=job_id,
        name="Alerts: retry pending deliveries",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    logger.info("Alert retry job registered (cron='%s')", cron_expr)


def register_opencti_outbox_job() -> None:
    """Register the OpenCTI outbox drain worker (id ``opencti-outbox``)."""
    if not settings.opencti_enabled:
        logger.info("OpenCTI sink disabled (OPENCTI_ENABLED=false); outbox job not registered")
        return

    cron_expr = settings.opencti_outbox_cron
    trigger = _build_cron_trigger(cron_expr, context="opencti-outbox", job_id="opencti-outbox")
    if trigger is None:
        return

    async def _run_outbox() -> None:
        try:
            summary = await drain_opencti_outbox()
            if summary["processed"] > 0:
                logger.info(
                    "OpenCTI outbox worker processed bundles",
                    extra={"component": "opencti-outbox", **summary},
                )
        except Exception:
            logger.exception("OpenCTI outbox worker raised an unexpected exception")

    job_id = "opencti-outbox"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        _run_outbox,
        trigger=trigger,
        id=job_id,
        name="OpenCTI outbox: retry pending ingests",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    logger.info("OpenCTI outbox job registered (cron='%s')", cron_expr)


def start_scheduler() -> None:
    """Load targets.yaml, register all jobs and start the scheduler.

    Called once from the FastAPI lifespan (APScheduler must bind to the
    running event loop). Idempotent: reuses a running instance.
    """
    if scheduler.running:
        logger.info("Scheduler already running; reusing existing instance")
        return

    targets, invalid_targets, _ = _load_targets()
    if invalid_targets:
        logger.warning("Skipped invalid targets at startup: %s", ", ".join(invalid_targets))
    register_targets(targets)
    register_retention_job()
    register_alert_retry_job()
    register_opencti_outbox_job()
    scheduler.start()
    logger.info("Scheduler started with %d target(s)", len(targets))


def shutdown_scheduler() -> None:
    """Stop the scheduler if it is running (called on application shutdown)."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
