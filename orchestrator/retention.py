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
from typing import Any, cast

from sqlalchemy import delete, select
from sqlalchemy.engine import Result
from sqlmodel import col

from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.models import (
    AlertCase,
    AlertDelivery,
    AlertRecord,
    DossierRun,
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
    # Runs past the cutoff kept because their target has a protected run (an
    # alert case or a dossier citation) at or before them, in the chain's
    # order (a snapshot taken at each purge, not a delta).
    runs_retained_protected: int = 0
    report_dirs_deleted: int = 0
    errors: list[str] = field(default_factory=list)


async def purge_expired(now: datetime | None = None) -> RetentionSummary:
    """
    Delete run rows older than ``retention_days`` and their dependent rows,
    then remove matching ``daily_reports/YYYY-MM-DD`` directories.

    Two kinds of rows survive every purge on purpose:

    - ``seen_observables``, the delta memory between runs;
    - for every target, the oldest run that must be kept for a professional
      reason -- it opened an alert case, or a finalized dossier cites it --
      and every run after it, with all their dependents and report
      directories. A case is where the operator records who reviewed the run
      and what they decided, and a dossier is the reviewed file a conclusion
      is signed into; both belong to the compliance record. Keeping
      everything after the oldest of them, not just the protected runs, keeps
      the purged runs a contiguous prefix of the target's evidence chain,
      which chain verification accepts (a gap in the middle reads as
      tampering).

    Returns a :class:`RetentionSummary` and logs a single structured line.
    """
    summary = RetentionSummary()
    purged_run_dirs: list[tuple[str, Path]] = []
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
            expired_by_age = col(Run.finished_at).isnot(None) & (
                col(Run.finished_at) < cutoff
            ) | col(Run.finished_at).is_(None) & (col(Run.started_at) < cutoff)
            result = await session.exec(  # type: ignore[call-overload]  # SQLModel's exec stubs exclude SQLAlchemy Select, which it supports at runtime.
                select(col(Run.id), col(Run.target_id), col(Run.started_at)).where(expired_by_age)
            )
            candidates = [(row[0], row[1], row[2]) for row in result.all()]

            # A run is kept when it must survive for a professional reason:
            # it opened an alert case, or a dossier cites it. Neither kind may
            # be purged on its own, and neither may be purged while an older
            # run of the same target survives either -- so both collapse into
            # one per-target floor.
            #
            # The floor is the oldest run of the target that is protected, in
            # the evidence chain's own order (started_at, id), and everything
            # from it on is kept: purging only a contiguous prefix of a
            # target's runs is what verify_target_chain accepts as "retention
            # removed the oldest runs". Excluding the protected runs alone
            # instead would punch a hole in the middle of the chain, which
            # verification reads as tampering.
            protected_rows = await session.exec(  # type: ignore[call-overload]  # Same SQLModel stub gap as above.
                select(col(Run.target_id), col(Run.started_at), col(Run.id)).where(
                    col(Run.id).in_(select(col(AlertCase.run_id)))
                    | col(Run.id).in_(select(col(DossierRun.run_id)))
                )
            )
            first_protected: dict[str, tuple[datetime, int]] = {}
            for target_id, started_at, run_id in protected_rows.all():
                key = (_ensure_aware(started_at), run_id)
                if target_id not in first_protected or key < first_protected[target_id]:
                    first_protected[target_id] = key

            expired_ids: list[int] = []
            for run_id, target_id, started_at in candidates:
                floor = first_protected.get(target_id)
                if floor is not None and (_ensure_aware(started_at), run_id) >= floor:
                    summary.runs_retained_protected += 1
                    continue
                expired_ids.append(run_id)

            # The purged runs' own directories go too: the day directory is
            # only removed when no surviving run started that day, so a kept
            # run would otherwise leave its purged neighbours' files on disk.
            path_rows = await session.exec(  # type: ignore[call-overload]  # Same SQLModel stub gap as above.
                select(col(Run.id), col(Run.target_id), col(Run.report_path)).where(
                    col(Run.id).in_(expired_ids or [-1])
                )
            )
            purged_run_dirs = [(row[1], Path(row[2]).parent) for row in path_rows.all() if row[2]]

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
                        res = await session.exec(delete(model).where(col(id_column).in_(batch)))
                        deleted += res.rowcount
                    setattr(summary, counter_attr, deleted)

                runs_deleted = 0
                for i in range(0, len(expired_ids), _BATCH_SIZE):
                    batch = expired_ids[i : i + _BATCH_SIZE]
                    res = await session.exec(delete(Run).where(col(Run.id).in_(batch)))
                    runs_deleted += res.rowcount
                summary.runs_deleted = runs_deleted

                await session.commit()

    except Exception:
        logger.exception("Retention: database purge failed")
        summary.errors.append("database")

    for target_id, run_dir in purged_run_dirs:
        # Only a run directory laid out by the report generator
        # (<report_dir>/<date>/<target_id>/run-<id>) is removed.
        if not (run_dir.name.startswith("run-") and run_dir.parent.name == target_id):
            continue
        try:
            if run_dir.is_dir():
                shutil.rmtree(run_dir)
        except OSError as exc:
            logger.error("Retention: failed to remove %s: %s", run_dir, exc)
            summary.errors.append(str(run_dir))

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
        if _is_filesystem_root(root_path):
            # A root that resolves to "/" would make the date filter below the
            # only thing between this job and arbitrary deletion.
            logger.warning("Retention: refusing to purge from filesystem root %s", root_path)
            summary.errors.append(f"unsafe root: {root}")
            continue
        resolved_root = root_path.resolve()

        for entry in sorted(root_path.iterdir()):
            if entry.is_symlink():
                # Checked before is_dir(): is_dir() follows the link, and rmtree
                # refusing a symlink is CPython behaviour, not a promise we make.
                logger.warning("Retention: skipping symlinked report entry %s", entry)
                continue
            if not entry.is_dir():
                continue
            if not _resolves_inside(resolved_root, entry):
                logger.warning(
                    "Retention: skipping %s, outside report root %s", entry, resolved_root
                )
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
            "runs_retained_protected": summary.runs_retained_protected,
            "report_dirs_deleted": summary.report_dirs_deleted,
            "errors": summary.errors,
        },
    )
    return summary


async def _surviving_run_dates(cutoff: datetime) -> set[str]:
    """Directory names (UTC start dates) of runs still in the database that
    started before *cutoff*; later dates are never purge candidates."""
    async with get_session() as session:
        # SQLAlchemy select returns Result here; SQLModel's exec stub declares TupleResult.
        result = cast(
            Result[Any],
            await session.exec(  # type: ignore[call-overload]  # SQLModel's exec stubs exclude SQLAlchemy Select, which it supports at runtime.
                select(col(Run.started_at)).where(col(Run.started_at) < cutoff)
            ),
        )
        return {_bundle_date(started_at) for started_at in result.scalars().all()}


def _ensure_aware(value: datetime) -> datetime:
    """SQLite returns naive datetimes; compare everything as UTC-aware."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _is_filesystem_root(path: Path) -> bool:
    """True when ``path`` resolves to a filesystem root (`/`, `C:\\`, ...)."""
    resolved = path.resolve()
    return resolved == Path(resolved.anchor)


def _resolves_inside(root: Path, entry: Path) -> bool:
    """True when ``entry`` resolves under the already-resolved ``root``."""
    try:
        entry.resolve().relative_to(root)
    except ValueError:
        return False
    return True


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
