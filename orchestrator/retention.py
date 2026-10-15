"""
Retention — purge old run rows and daily_reports directories.

Called nightly by APScheduler (see scheduler.py).  Never raises: any error is
logged with logger.exception and the job exits cleanly so the scheduler can
retry on the next cron tick.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import delete, select
from sqlmodel import col

from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.models import (
    AlertCase,
    AlertDelivery,
    AlertRecord,
    EvidenceQualification,
    FindingRecord,
    OpenCTIOutbox,
    Run,
    RunObservable,
)
from orchestrator.reports import _bundle_date

logger = logging.getLogger(__name__)

# Maximum number of run ids sent in a single IN (...) clause.  Keeping this
# well below SQLITE_MAX_VARIABLE_NUMBER (999 on old builds, 32766 on new ones)
# ensures the first purge of a long-running installation never hits an
# OperationalError regardless of how many expired runs have accumulated.
_BATCH_SIZE = 500


@dataclass
class RetentionSummary:
    """Row/directory counts deleted by one purge, plus non-fatal errors."""

    runs_deleted: int = 0
    run_observables_deleted: int = 0
    findings_deleted: int = 0
    alerts_deleted: int = 0
    alert_deliveries_deleted: int = 0
    opencti_outbox_deleted: int = 0
    evidence_qualifications_deleted: int = 0
    alert_cases_deleted: int = 0
    report_dirs_deleted: int = 0
    errors: list[str] = field(default_factory=list)


async def purge_expired(now: datetime | None = None) -> RetentionSummary:
    """
    Delete run rows older than ``retention_days`` and their dependent rows,
    then remove matching ``daily_reports/YYYY-MM-DD`` directories.

    ``seen_observables`` is intentionally left untouched — it is the delta
    memory between runs and must survive a purge cycle.

    Returns a :class:`RetentionSummary` and logs a single structured line.
    """
    summary = RetentionSummary()
    retention_days = settings.orchestrator_retention_days

    if retention_days <= 0:
        logger.debug("Retention disabled (retention_days=%d)", retention_days)
        return summary

    if now is None:
        now = datetime.now(UTC)

    cutoff = now - timedelta(days=retention_days)

    # ── Database purge ────────────────────────────────────────────────────────
    try:
        async with get_session() as session:
            # Identify expired run ids.  Use finished_at when available,
            # fall back to started_at for runs that never completed.
            stmt = select(Run.id).where(
                col(Run.finished_at).isnot(None) & (col(Run.finished_at) < cutoff)
                | col(Run.finished_at).is_(None) & (col(Run.started_at) < cutoff)
            )
            result = await session.exec(stmt)
            expired_ids = [row[0] if not isinstance(row, int) else row for row in result.all()]

            if expired_ids:
                # Delete dependents first to satisfy FK constraints (SQLite
                # may not enforce them, but we do it correctly anyway).
                # Process in batches to stay within SQLITE_MAX_VARIABLE_NUMBER
                # — an installation that ran for years without purging can have
                # tens of thousands of expired runs.
                for model, id_column, counter_attr in [
                    (OpenCTIOutbox, OpenCTIOutbox.run_id, "opencti_outbox_deleted"),
                    (AlertDelivery, AlertDelivery.run_id, "alert_deliveries_deleted"),
                    (AlertRecord, AlertRecord.run_id, "alerts_deleted"),
                    (AlertCase, AlertCase.run_id, "alert_cases_deleted"),
                    (FindingRecord, FindingRecord.run_id, "findings_deleted"),
                    (RunObservable, RunObservable.run_id, "run_observables_deleted"),
                    (
                        EvidenceQualification,
                        EvidenceQualification.run_id,
                        "evidence_qualifications_deleted",
                    ),
                ]:
                    deleted = 0
                    for i in range(0, len(expired_ids), _BATCH_SIZE):
                        batch = expired_ids[i : i + _BATCH_SIZE]
                        res = await session.exec(delete(model).where(id_column.in_(batch)))
                        deleted += res.rowcount
                    setattr(summary, counter_attr, deleted)

                runs_deleted = 0
                for i in range(0, len(expired_ids), _BATCH_SIZE):
                    batch = expired_ids[i : i + _BATCH_SIZE]
                    res = await session.exec(delete(Run).where(Run.id.in_(batch)))
                    runs_deleted += res.rowcount
                summary.runs_deleted = runs_deleted

                await session.commit()

    except Exception:
        logger.exception("Retention: database purge failed")
        summary.errors.append("database")

    # ── Report directory purge ────────────────────────────────────────────────
    # A directory is named after the UTC start date of its runs, while a run row
    # expires by its exact finished_at. Deleting by date alone would remove the
    # directory of a run kept in the database (any run of the cutoff day that
    # finished after the purge time), leaving its report and manifest missing
    # and the evidence chain broken. So only whole days before the cutoff are
    # removed, and never a day that a surviving run still points to.
    try:
        kept_dates = await _surviving_run_dates(cutoff)
    except Exception:
        logger.exception("Retention: could not read surviving runs; report directories kept")
        summary.errors.append("report_dirs")
        report_dirs: set[str] = set()
    else:
        # Collect the distinct report_dir values from settings / targets.
        report_dirs = _collect_report_dirs()

    for root in report_dirs:
        root_path = Path(root)
        if not root_path.is_dir():
            continue

        for entry in sorted(root_path.iterdir()):
            if not entry.is_dir():
                continue
            # Accept only ISO date directories: YYYY-MM-DD
            try:
                dir_date = datetime.strptime(entry.name, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                continue  # leave non-date directories untouched

            if dir_date + timedelta(days=1) > cutoff:
                continue  # part of the day is within the retention window
            if entry.name in kept_dates:
                continue  # a run kept in the database still points here

            try:
                shutil.rmtree(entry)
                summary.report_dirs_deleted += 1
            except Exception as exc:
                logger.error("Retention: failed to remove %s: %s", entry, exc)
                summary.errors.append(str(entry))

    logger.info(
        "Retention purge complete",
        extra={
            "retention_days": retention_days,
            "cutoff": cutoff.isoformat(),
            "runs_deleted": summary.runs_deleted,
            "run_observables_deleted": summary.run_observables_deleted,
            "findings_deleted": summary.findings_deleted,
            "alerts_deleted": summary.alerts_deleted,
            "alert_deliveries_deleted": summary.alert_deliveries_deleted,
            "opencti_outbox_deleted": summary.opencti_outbox_deleted,
            "evidence_qualifications_deleted": summary.evidence_qualifications_deleted,
            "alert_cases_deleted": summary.alert_cases_deleted,
            "report_dirs_deleted": summary.report_dirs_deleted,
            "errors": summary.errors,
        },
    )
    return summary


async def _surviving_run_dates(cutoff: datetime) -> set[str]:
    """Directory names (UTC start dates) of runs still in the database that
    started before *cutoff*; later dates are never purge candidates."""
    async with get_session() as session:
        result = await session.exec(select(Run.started_at).where(col(Run.started_at) < cutoff))
        return {_bundle_date(started_at) for started_at in result.scalars().all()}


def _collect_report_dirs() -> set[str]:
    """Return distinct report_dir values from the configured targets file."""
    from orchestrator.targets import load_targets

    dirs: set[str] = set()
    targets, _errors = load_targets(settings.targets_file)
    for target in targets:
        dirs.add(target.report_dir)
    # Always include the default report_dir so that standalone usage and tests
    # work without a targets.yaml.  In the Docker container the cwd is /app,
    # so this resolves to /app/daily_reports — the same path the pipeline uses.
    dirs.add("daily_reports")
    return dirs
