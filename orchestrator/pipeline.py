"""
Orchestration pipeline: runs all enabled collectors for a target,
normalizes to STIX 2.1, ingests into OpenCTI, and persists run state.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from typing import TYPE_CHECKING, Any, Literal, cast

import httpx
import stix2
from sqlalchemy import func, update
from sqlmodel import col, select

from orchestrator import metrics
from orchestrator.backoff import backoff_delay
from orchestrator.collectors.amass import AmassCollector
from orchestrator.collectors.base import BaseCollector
from orchestrator.collectors.openosint import OpenOSINTCollector
from orchestrator.collectors.socialosint import SocialOSINTCollector
from orchestrator.collectors.spiderfoot import SpiderFootCollector
from orchestrator.collectors.tavily import TavilyCollector
from orchestrator.config import settings
from orchestrator.database import get_session
from orchestrator.evidence import build_manifest, canonical_json, sha256_file, write_manifest_file
from orchestrator.models import (
    AlertDelivery,
    AlertDeliveryStatus,
    AlertRecord,
    AlertStatus,
    CollectorName,
    CollectorResult,
    EvidenceItem,
    EvidenceQualification,
    OpenCTIOutbox,
    OpenCTIOutboxStatus,
    Run,
    RunObservable,
    RunStatus,
    SeenObservable,
    Target,
)
from orchestrator.normalizer.stix import _IDENTITIES, normalize
from orchestrator.reports import (
    CollectorReportResult,
    ReportObservable,
    RunReportData,
    generate_report,
    stix_object_value,
)
from orchestrator.sinks import OpenCTIIngestError, is_transient
from orchestrator.sinks.opencti import OpenCTISink
from orchestrator.synthesizer import synthesize
from orchestrator.synthesizer.providers import LLMClient, effective_provider, get_client
from orchestrator.synthesizer.qualify import persist_qualifications, qualify_evidence

if TYPE_CHECKING:
    from orchestrator.alerts import AlertEvent

logger = logging.getLogger(__name__)


def _artefacts_for_manifest(report_path: str | None) -> dict[str, str]:
    """Return every generated file in the run directory, excluding the manifest itself."""
    if not report_path:
        return {}
    base = Path(report_path).parent
    artefacts: dict[str, str] = {}
    for path in sorted(base.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.name == "manifest.json":
            continue
        artefacts[path.name] = sha256_file(path)
    return artefacts


# Bundle scaffolding that must not be counted as a net-new finding.
_COLLECTOR_IDENTITY_IDS = frozenset(i.id for i in _IDENTITIES.values())
_NON_FINDING_TYPES = frozenset({"note", "relationship"})


def _get_collectors(target: Target) -> list[BaseCollector]:
    """Instantiate the collectors enabled for a target, in pipeline order."""
    collectors: list[BaseCollector] = []
    if target.collectors.openosint.enabled:
        collectors.append(OpenOSINTCollector(target))
    if target.collectors.spiderfoot.enabled:
        collectors.append(SpiderFootCollector(target))
    if target.collectors.socialosint.enabled:
        collectors.append(SocialOSINTCollector(target))
    if target.collectors.amass.enabled:
        collectors.append(AmassCollector(target))
    if target.collectors.tavily.enabled:
        if settings.tavily_max_calls_per_run > 0:
            collectors.append(TavilyCollector(target))
        else:
            # TAVILY_MAX_CALLS_PER_RUN=0 is the operator's off switch: skip the
            # collector instead of recording a failure on every run.
            logger.info(
                "Tavily skipped: TAVILY_MAX_CALLS_PER_RUN=0 target=%s",
                target.id,
                extra={"target_id": target.id, "collector": CollectorName.TAVILY.value},
            )
    return collectors


async def _ollama_reachable() -> bool:
    try:
        timeout = max(1.0, min(float(settings.llm_timeout_seconds), 5.0))
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{settings.llm_base_url}/api/tags")
            response.raise_for_status()
    except Exception:
        return False
    return True


async def _qualification_client(
    target: Target, evidence_items: list[EvidenceItem], *, client: LLMClient | None = None
) -> LLMClient | None:
    """The client that qualifies this run's evidence, or None when the step is off.

    *client* stands in for the target's provider (the showcase replay); the
    operator's switches still apply to it, LLM_PROVIDER=none included.
    """
    if not settings.llm_qualify_enabled:
        return None
    if settings.llm_qualify_max_items <= 0:
        return None
    if not evidence_items:
        return None
    if settings.llm_provider == "none":
        return None
    if client is None:
        client = get_client(target)
    if client is None:
        return None
    if client.provider == "ollama" and not await _ollama_reachable():
        return None
    return client


def _qualification_payload(row: EvidenceQualification) -> dict[str, Any]:
    return row.model_dump(mode="json")


def _write_qualified_evidence_file(
    report_path: str | None, rows: list[EvidenceQualification], *, attempted: bool
) -> None:
    if not report_path:
        return
    if not rows and not attempted:
        return
    base = Path(report_path).parent
    ordered = sorted(
        (_qualification_payload(row) for row in rows),
        key=lambda item: (str(item.get("url", "")), int(item.get("id") or 0)),
    )
    (base / "qualified_evidence.json").write_text(canonical_json(ordered), encoding="utf-8")


def _select_best_qualifications(
    rows: list[EvidenceQualification], *, run_id: int, target_id: str
) -> dict[str, EvidenceQualification]:
    best: dict[str, EvidenceQualification] = {}
    for row in rows:
        existing = best.get(row.url)
        if existing is None or row.confidence > existing.confidence:
            if existing is not None:
                logger.info(
                    "Evidence qualification duplicate URL resolved by confidence target=%s run_id=%d url=%s old=%.3f new=%.3f",
                    target_id,
                    run_id,
                    row.url,
                    existing.confidence,
                    row.confidence,
                    extra={"target_id": target_id, "run_id": run_id},
                )
            best[row.url] = row
    return best


async def get_run_delta(run_id: int) -> list[dict]:
    """
    Return the net-new, successfully ingested observables for a completed run.

    Each item is a dict with keys: stix_id, stix_type, value.
    Filters is_new=True AND ingested=True so this is the authoritative single
    source for both the GET /runs/{id}/delta endpoint (Issue #10) and alert
    payloads — the two definitions of "delta" are identical.
    """
    async with get_session() as session:
        result = await session.exec(
            select(RunObservable)
            .where(RunObservable.run_id == run_id)
            .where(RunObservable.is_new == True)  # noqa: E712
            .where(RunObservable.ingested == True)  # noqa: E712
        )
        rows = result.all()
    return [{"stix_id": r.stix_id, "stix_type": r.stix_type, "value": r.value} for r in rows]


# ─── Retry scheduling ─────────────────────────────────────────────────────────


def _alert_next_attempt_at(attempts: int) -> datetime:
    """When to try again after ``attempts`` sends (>= 1) have failed."""
    delay = backoff_delay(
        attempts - 1,
        base=settings.alert_retry_base_delay_seconds,
        jitter_ratio=settings.alert_retry_jitter_ratio,
    )
    return datetime.now(UTC) + timedelta(seconds=delay)


def _outbox_next_retry_at(attempts: int) -> datetime:
    """When to try again after ``attempts`` ingests (>= 1) have failed."""
    delay = backoff_delay(
        attempts - 1,
        base=settings.opencti_outbox_base_delay_seconds,
        jitter_ratio=settings.opencti_outbox_jitter_ratio,
    )
    return datetime.now(UTC) + timedelta(seconds=delay)


# ─── Queue plumbing shared by the alert retry queue and the OpenCTI outbox ───
#
# Both queues used to load every due row, call the external service for each,
# and commit once at the end. A crash on row N re-delivered rows 1..N-1 on the
# next tick — duplicate webhooks and e-mails for the operator — and two drains
# running at once (the cron job and the replay endpoint) sent everything twice.
#
# Now a row is *claimed* with a conditional UPDATE (PENDING → IN_PROGRESS) that
# is committed before the external call, and its final state is committed right
# after. One row, one transaction: a crash costs at most one duplicate, and a
# concurrent drain finds nothing to claim.


async def _claim_row(session, model, row_id: int, pending, in_progress) -> bool:
    """Atomically move ``row_id`` from ``pending`` to ``in_progress``."""
    result = await session.exec(
        update(model)
        .where(model.id == row_id)
        .where(model.status == pending)
        .values(status=in_progress, updated_at=datetime.now(UTC))
    )
    await session.commit()
    return result.rowcount == 1


async def requeue_interrupted_deliveries() -> dict[str, int]:
    """
    Return rows a previous process left IN_PROGRESS to PENDING.

    Called once at startup: a process that has just started cannot be sending
    anything, so an IN_PROGRESS row is one whose drain died between the claim
    and the final commit. Re-sending it is the intended outcome (at most one
    duplicate), and far better than a row parked forever.
    """
    now = datetime.now(UTC)
    async with get_session() as session:
        alerts = await session.exec(
            update(AlertDelivery)
            .where(col(AlertDelivery.status) == AlertDeliveryStatus.IN_PROGRESS)
            .values(status=AlertDeliveryStatus.PENDING, next_attempt_at=now, updated_at=now)
        )
        outbox = await session.exec(
            update(OpenCTIOutbox)
            .where(col(OpenCTIOutbox.status) == OpenCTIOutboxStatus.IN_PROGRESS)
            .values(status=OpenCTIOutboxStatus.PENDING, next_retry_at=now, updated_at=now)
        )
        await session.commit()
    return {"alert_deliveries": alerts.rowcount, "opencti_outbox": outbox.rowcount}


async def _count_by_status(session, model, status) -> int:
    result = await session.exec(
        select(func.count()).select_from(model).where(model.status == status)
    )
    return int(result.one())


async def _update_opencti_outbox_metrics() -> None:
    """Refresh the outbox gauges (pending count, oldest pending age)."""
    now = datetime.now(UTC)
    async with get_session() as session:
        result = await session.exec(
            select(OpenCTIOutbox.created_at)
            .where(
                col(OpenCTIOutbox.status).in_(
                    [OpenCTIOutboxStatus.PENDING, OpenCTIOutboxStatus.IN_PROGRESS]
                )
            )
            .order_by(col(OpenCTIOutbox.created_at).asc())
        )
        pending = result.all()
        dead = await _count_by_status(session, OpenCTIOutbox, OpenCTIOutboxStatus.DEAD_LETTER)

    metrics.opencti_outbox_pending.set(len(pending))
    metrics.opencti_outbox_dead_letter.set(dead)
    if not pending:
        metrics.opencti_outbox_oldest_age_seconds.set(0)
        return
    oldest = pending[0]
    if oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=UTC)
    metrics.opencti_outbox_oldest_age_seconds.set(max(0.0, (now - oldest).total_seconds()))


async def _update_alert_queue_metrics() -> None:
    async with get_session() as session:
        pending = await _count_by_status(session, AlertDelivery, AlertDeliveryStatus.PENDING)
        dead = await _count_by_status(session, AlertDelivery, AlertDeliveryStatus.DEAD_LETTER)
    metrics.alert_deliveries_pending.set(pending)
    metrics.alert_deliveries_dead_letter.set(dead)


# ─── OpenCTI outbox ───────────────────────────────────────────────────────────


async def enqueue_opencti_outbox(
    *,
    run_id: int,
    target_id: str,
    work_name: str,
    bundle: stix2.Bundle,
    first_error: str,
    transient: bool = True,
) -> None:
    """
    Persist a bundle whose ingest failed, for the drain worker to retry.

    ``transient`` is the sink's classification of the failure. A permanent
    one — invalid token, rejected bundle — goes straight to the dead-letter
    queue: retrying it six times over half an hour cannot fix it, and the
    operator needs to see it, not wait for it. ``POST /opencti/outbox/replay``
    re-queues it once the cause is fixed.
    """
    max_attempts = max(1, settings.opencti_outbox_max_attempts)
    now = datetime.now(UTC)
    status = OpenCTIOutboxStatus.PENDING
    next_retry_at = _outbox_next_retry_at(1)
    if not transient or max_attempts <= 1:
        status = OpenCTIOutboxStatus.DEAD_LETTER
        next_retry_at = now
        metrics.opencti_outbox_deliveries_total.labels("dead_letter").inc()
        logger.warning(
            "OpenCTI bundle for run %d parked in the dead-letter queue: %s (%s)",
            run_id,
            first_error,
            "permanent error" if not transient else "retries disabled",
            extra={"target_id": target_id, "run_id": run_id, "component": "opencti-outbox"},
        )

    async with get_session() as session:
        session.add(
            OpenCTIOutbox(
                run_id=run_id,
                target_id=target_id,
                work_name=work_name,
                bundle_json=bundle.serialize(pretty=False),
                status=status,
                attempts=1,
                max_attempts=max_attempts,
                next_retry_at=next_retry_at,
                last_error=first_error,
                updated_at=now,
            )
        )
        await session.commit()
    await _update_opencti_outbox_metrics()


def _bundle_object_ids(bundle: object) -> set[str]:
    """STIX ids in a parsed bundle; empty when the object is not bundle-shaped."""
    try:
        objects = bundle.get("objects", [])  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return set()
    ids: set[str] = set()
    for obj in objects:
        try:
            stix_id = obj.get("id", "")
        except Exception:  # noqa: BLE001
            continue
        if stix_id:
            ids.add(stix_id)
    return ids


async def _backfill_ingested(session, run_id: int, target_id: str, stix_ids: set[str]) -> int:
    """
    Record that a deferred bundle finally landed in OpenCTI.

    The pipeline wrote the run's RunObservable rows with ``ingested=False``
    and skipped SeenObservable for them, so that the next run would re-report
    them as new if the bundle never arrived. Now that it has, flip them to
    ingested, register the new ones as seen, and refresh the run's new-
    observable count — otherwise ``GET /runs/{id}/delta`` and every later
    run's "new since last run" stay wrong for these observables.
    """
    if not stix_ids:
        return 0
    rows = (
        await session.exec(
            select(RunObservable)
            .where(RunObservable.run_id == run_id)
            .where(RunObservable.ingested == False)  # noqa: E712
            .where(col(RunObservable.stix_id).in_(stix_ids))
        )
    ).all()
    if not rows:
        return 0
    already_seen = set(
        (
            await session.exec(
                select(SeenObservable.stix_id)
                .where(SeenObservable.target_id == target_id)
                .where(col(SeenObservable.stix_id).in_([r.stix_id for r in rows]))
            )
        ).all()
    )
    for row in rows:
        row.ingested = True
        session.add(row)
        if row.is_new and row.stix_id not in already_seen:
            session.add(
                SeenObservable(target_id=target_id, stix_id=row.stix_id, first_seen_run_id=run_id)
            )
            already_seen.add(row.stix_id)
    run = await session.get(Run, run_id)
    if run is not None:
        new_count = await session.exec(
            select(func.count())
            .select_from(RunObservable)
            .where(RunObservable.run_id == run_id)
            .where(RunObservable.is_new == True)  # noqa: E712
            .where(RunObservable.ingested == True)  # noqa: E712
        )
        run.new_observables = int(new_count.one())
        session.add(run)
    return len(rows)


async def _outbox_record_success(row_id: int, attempt: int, bundle: object) -> None:
    now = datetime.now(UTC)
    ingested_ids = _bundle_object_ids(bundle)
    async with get_session() as session:
        item = await session.get(OpenCTIOutbox, row_id)
        if item is None:
            return
        item.status = OpenCTIOutboxStatus.SENT
        item.sent_at = now
        item.updated_at = now
        item.attempts = attempt
        item.last_error = None
        # The bundle is in OpenCTI now; SQLite keeps the audit row, not the STIX.
        item.bundle_json = None
        session.add(item)
        backfilled = await _backfill_ingested(session, item.run_id, item.target_id, ingested_ids)
        await session.commit()
    metrics.opencti_outbox_deliveries_total.labels("sent").inc()
    logger.info(
        "OpenCTI outbox row %d sent on attempt %d; %d observable(s) marked ingested",
        row_id,
        attempt,
        backfilled,
        extra={"component": "opencti-outbox", "outbox_id": row_id, "attempt": attempt},
    )


async def _outbox_record_failure(
    row_id: int, attempt: int, exc: BaseException, transient: bool
) -> bool:
    """Persist a failed attempt; return True when the row went to the dead-letter queue."""
    now = datetime.now(UTC)
    async with get_session() as session:
        item = await session.get(OpenCTIOutbox, row_id)
        if item is None:
            return False
        item.attempts = attempt
        item.last_error = str(exc)
        item.updated_at = now
        dead = not transient or attempt >= item.max_attempts
        if dead:
            item.status = OpenCTIOutboxStatus.DEAD_LETTER
            item.next_retry_at = now
        else:
            item.status = OpenCTIOutboxStatus.PENDING
            item.next_retry_at = _outbox_next_retry_at(attempt)
        session.add(item)
        run_id, target_id, max_attempts = item.run_id, item.target_id, item.max_attempts
        await session.commit()
    metrics.opencti_outbox_deliveries_total.labels("failed").inc()
    if dead:
        metrics.opencti_outbox_deliveries_total.labels("dead_letter").inc()
        logger.warning(
            "OpenCTI outbox row %d (run %d) parked in the dead-letter queue after "
            "%d/%d attempt(s): %s (%s)",
            row_id,
            run_id,
            attempt,
            max_attempts,
            exc,
            "permanent error" if not transient else "retries exhausted",
            extra={"target_id": target_id, "run_id": run_id, "component": "opencti-outbox"},
        )
    return dead


async def drain_opencti_outbox(limit: int = 100) -> dict[str, int]:
    """
    Retry due OpenCTI outbox rows, one transaction per row (see _claim_row).

    ``stix2.parse`` runs in a worker thread: a large bundle takes long enough
    to parse that doing it on the event loop stalls the scheduler and the API.
    """
    now = datetime.now(UTC)
    counts = {"processed": 0, "sent": 0, "failed": 0, "dead_letter": 0}
    capped_limit = min(max(1, limit), 1000)

    async with get_session() as session:
        due_ids = (
            await session.exec(
                select(OpenCTIOutbox.id)
                .where(OpenCTIOutbox.status == OpenCTIOutboxStatus.PENDING)
                .where(col(OpenCTIOutbox.next_retry_at) <= now)
                .order_by(col(OpenCTIOutbox.id).asc())
                .limit(capped_limit)
            )
        ).all()

    for row_id in due_ids:
        # IDs selected from persisted rows are non-null primary keys.
        assert row_id is not None
        async with get_session() as session:
            claimed = await _claim_row(
                session,
                OpenCTIOutbox,
                row_id,
                OpenCTIOutboxStatus.PENDING,
                OpenCTIOutboxStatus.IN_PROGRESS,
            )
            if not claimed:
                continue  # another drain took it, or it was replayed meanwhile
            # The claim matched an existing row; preserve the failure if retention removes it.
            item = cast(OpenCTIOutbox, await session.get(OpenCTIOutbox, row_id))
            target_id, work_name = item.target_id, item.work_name
            bundle_json, attempt = item.bundle_json, item.attempts + 1

        counts["processed"] += 1
        metrics.opencti_outbox_retries_total.labels(target_id).inc()
        try:
            if not bundle_json:
                raise OpenCTIIngestError("outbox row carries no bundle", transient=False)
            bundle = await asyncio.to_thread(stix2.parse, bundle_json, allow_custom=True)
            await OpenCTISink().ingest_async(bundle, work_name=work_name, target_id=target_id)
        except Exception as exc:  # noqa: BLE001
            counts["failed"] += 1
            if await _outbox_record_failure(row_id, attempt, exc, is_transient(exc)):
                counts["dead_letter"] += 1
            continue
        await _outbox_record_success(row_id, attempt, bundle)
        counts["sent"] += 1

    await _update_opencti_outbox_metrics()
    return counts


async def replay_opencti_dead_letters(
    *, run_id: int | None = None, limit: int = 100
) -> dict[str, int]:
    """Move dead-letter outbox rows back to pending so the next drain retries them."""
    moved = 0
    now = datetime.now(UTC)
    capped_limit = min(max(1, limit), 1000)
    async with get_session() as session:
        stmt = (
            select(OpenCTIOutbox)
            .where(OpenCTIOutbox.status == OpenCTIOutboxStatus.DEAD_LETTER)
            .order_by(col(OpenCTIOutbox.id).asc())
            .limit(capped_limit)
        )
        if run_id is not None:
            stmt = stmt.where(OpenCTIOutbox.run_id == run_id)
        for item in (await session.exec(stmt)).all():
            moved += 1
            item.status = OpenCTIOutboxStatus.PENDING
            item.attempts = 0
            item.last_error = None
            item.next_retry_at = now
            item.updated_at = now
            session.add(item)
        await session.commit()
    await _update_opencti_outbox_metrics()
    return {"moved": moved}


async def run_target_pipeline(
    target: Target,
    run_id: int,
    *,
    collectors: Sequence[BaseCollector] | None = None,
    llm_client: LLMClient | None = None,
) -> None:
    """Full collection → normalize → ingest → synthesize → report → alert pipeline.

    *collectors* and *llm_client* replace the target's own collectors and LLM
    provider; the showcase replay (``orchestrator/showcase.py``) uses them to
    run a recorded sample through this same code. Left unset, the target
    decides, as for every scheduled or manual run.
    """
    log_ctx = {"target_id": target.id, "run_id": run_id}
    logger.info("Pipeline start: target=%s run_id=%d", target.id, run_id, extra=log_ctx)
    started = perf_counter()
    metrics.runs_in_progress.labels(target.id).inc()
    final_status: RunStatus | None = None
    try:
        final_status = await _run_target_pipeline(
            target, run_id, log_ctx, collectors=collectors, llm_client=llm_client
        )
    except Exception as exc:
        # The per-target guard is the persisted Run.status; a row left RUNNING
        # here would block every later run of this target until edited by hand.
        await _mark_run_failed(run_id, f"pipeline: {exc}", log_ctx)
        raise
    finally:
        metrics.runs_in_progress.labels(target.id).dec()
        elapsed = perf_counter() - started
        metrics.run_duration_seconds.labels(target.id).observe(elapsed)
        # A run that raised out of the pipeline (not a collector failure, which
        # is caught inside) is counted as failed so it is not invisible.
        metrics.runs_total.labels(
            target.id, final_status.value if final_status else RunStatus.FAILED.value
        ).inc()


async def _mark_run_failed(run_id: int, error: str, log_ctx: dict) -> None:
    """Best-effort: record a run as FAILED after an unhandled pipeline error."""
    try:
        async with get_session() as session:
            run = await session.get(Run, run_id)
            if run is None:
                return
            if run.status in (RunStatus.PENDING, RunStatus.RUNNING):
                run.status = RunStatus.FAILED
                run.finished_at = datetime.now(UTC)
                run.error = error
            else:
                # Already sealed with its final status (a late step such as
                # the alert bookkeeping failed): keep the status and the
                # earlier errors that the signed manifest refers to.
                run.error = f"{run.error}; {error}" if run.error else error
            session.add(run)
            await session.commit()
    except Exception:  # noqa: BLE001 — never mask the original failure
        logger.exception("Could not mark run %d as failed", run_id, extra=log_ctx)


async def _run_target_pipeline(
    target: Target,
    run_id: int,
    log_ctx: dict,
    *,
    collectors: Sequence[BaseCollector] | None = None,
    llm_client: LLMClient | None = None,
) -> RunStatus | None:
    """Execute one run end to end and return its final status.

    Sequence: mark RUNNING → run enabled collectors sequentially (each
    failure isolated) → normalise to STIX with in-memory delta detection →
    ingest to OpenCTI (failures go to the outbox) → persist observables and
    mark seen only after ingest (Issue #8) → LLM synthesis → write report
    artifacts → evaluate and dispatch alerts → mark the Run terminal.
    Returns None only when the Run row vanished mid-flight.
    """
    async with get_session() as session:
        run = await session.get(Run, run_id)
        if run is None:
            logger.error("Run %d not found", run_id, extra=log_ctx)
            return None
        run.status = RunStatus.RUNNING
        session.add(run)
        await session.commit()

    collectors_run: list[str] = []
    results: list[CollectorResult] = []
    errors: list[str] = []

    for collector in _get_collectors(target) if collectors is None else collectors:
        name = collector.name.value
        collector_started = perf_counter()
        try:
            result = await collector.collect()
            results.append(result)
            collectors_run.append(name)
            outcome = "success" if result.success else "failure"
            if not result.success:
                # The collector contract says "never raise, return success=False".
                # That path must weigh on the run status exactly like a raise
                # does, or a target whose only collector is down is recorded
                # SUCCESS with zero findings and a green freshness SLO.
                errors.append(f"{name}: {result.error or 'collector reported failure'}")
            logger.info(
                "Collector %s %s: %d observables for %s",
                name,
                "OK" if result.success else "reported failure",
                len(result.observables),
                target.fqdn,
                extra={**log_ctx, "collector": name, "observables": len(result.observables)},
            )
        except Exception as exc:  # noqa: BLE001
            outcome = "error"
            logger.exception(
                "Collector %s failed for target %s",
                name,
                target.id,
                extra={**log_ctx, "collector": name},
            )
            errors.append(f"{name}: {exc}")
            results.append(
                CollectorResult(
                    collector=CollectorName(name),
                    target_fqdn=target.fqdn,
                    success=False,
                    error=str(exc),
                )
            )
        metrics.collector_runs_total.labels(name, target.id, outcome).inc()
        metrics.collector_duration_seconds.labels(name).observe(perf_counter() - collector_started)

    evidence_items = [item for result in results for item in result.evidence]
    qualifications: list[EvidenceQualification] = []
    qualification_client = await _qualification_client(target, evidence_items, client=llm_client)
    qualification_attempted = qualification_client is not None
    if qualification_attempted:
        qualifications = await qualify_evidence(
            target, run_id, evidence_items, client=qualification_client
        )
        qualifications = [row for row in qualifications if row.url]
        await persist_qualifications(qualifications)
        for row in qualifications:
            metrics.evidence_qualified_total.labels(target.id, row.category).inc()

    qualification_by_url = _select_best_qualifications(
        qualifications, run_id=run_id, target_id=target.id
    )

    # Normalize all results to STIX bundles, computing is_new in memory
    # BEFORE any DB write (Issue #8: only persist SeenObservable after
    # successful ingestion so a second run re-reports un-ingested observables).
    bundles: list[tuple[stix2.Bundle, list[tuple[str, str, str, bool]]]] = []
    # Each bundle is paired with its list of (stix_id, stix_type, value, is_new).

    seen_run_stix_ids: set[str] = set()
    all_run_observables: list[tuple[str, str, str, bool]] = []  # (stix_id, type, value, is_new)
    report_observables: list[ReportObservable] = []

    async with get_session() as session:
        for result in results:
            if not result.success:
                continue
            bundle = normalize(result, qualification_by_url=qualification_by_url)
            bundle_observables: list[tuple[str, str, str, bool]] = []

            for stix_obj in bundle.get("objects", []):
                stix_id = stix_obj.get("id", "")
                stix_type = stix_obj.get("type", "")
                if not stix_id or stix_id in _COLLECTOR_IDENTITY_IDS:
                    continue
                if stix_type in _NON_FINDING_TYPES:
                    continue
                value = stix_object_value(stix_obj)
                if not value:
                    continue
                if stix_id in seen_run_stix_ids:
                    continue

                existing = await session.exec(
                    select(SeenObservable)
                    .where(SeenObservable.target_id == target.id)
                    .where(SeenObservable.stix_id == stix_id)
                )
                is_new = existing.first() is None

                seen_run_stix_ids.add(stix_id)
                bundle_observables.append((stix_id, stix_type, value, is_new))
                all_run_observables.append((stix_id, stix_type, value, is_new))
                report_observables.append(
                    ReportObservable(
                        stix_id=stix_id,
                        stix_type=stix_type,
                        value=value,
                        is_new=is_new,
                        collector=result.collector.value,
                    )
                )

            bundles.append((bundle, bundle_observables))
        # No commit yet — SeenObservable inserts happen after successful ingest.

    # Ingest into OpenCTI; track which bundles succeeded for Issue #8.
    successful_bundle_observables: list[tuple[str, str, str, bool]] = []
    if not settings.opencti_enabled:
        logger.info("OpenCTI ingest skipped (OPENCTI_ENABLED=false)", extra=log_ctx)
        for _, bundle_obs in bundles:
            successful_bundle_observables.extend(bundle_obs)
    elif bundles:
        sink = OpenCTISink()
        for bundle, bundle_obs in bundles:
            work_name = f"osint-orchestrator/{target.id}/{run_id}"
            try:
                await sink.ingest_async(
                    bundle,
                    work_name=work_name,
                    target_id=target.id,
                )
                successful_bundle_observables.extend(bundle_obs)
                metrics.opencti_ingest_total.labels(target.id, "success").inc()
            except Exception as exc:  # noqa: BLE001
                logger.exception("OpenCTI ingest failed for run %d", run_id, extra=log_ctx)
                errors.append(f"opencti-sink: {exc}")
                metrics.opencti_ingest_total.labels(target.id, "failure").inc()
                await enqueue_opencti_outbox(
                    run_id=run_id,
                    target_id=target.id,
                    work_name=work_name,
                    bundle=bundle,
                    first_error=str(exc),
                    transient=is_transient(exc),
                )

    # Persist RunObservable for ALL observables (ingested or not), but only
    # insert SeenObservable for those whose bundle was successfully ingested.
    # This ensures the next run re-marks un-ingested observables as new.
    successfully_ingested_ids: set[str] = {obs[0] for obs in successful_bundle_observables}
    new_stix_ids: list[str] = []

    async with get_session() as session:
        for stix_id, stix_type, value, is_new in all_run_observables:
            ingested = stix_id in successfully_ingested_ids
            session.add(
                RunObservable(
                    run_id=run_id,
                    stix_id=stix_id,
                    stix_type=stix_type,
                    value=value,
                    is_new=is_new,
                    ingested=ingested,
                )
            )
            if is_new and ingested:
                new_stix_ids.append(stix_id)
                session.add(
                    SeenObservable(
                        target_id=target.id,
                        stix_id=stix_id,
                        first_seen_run_id=run_id,
                    )
                )
        await session.commit()

    metrics.run_observables.labels(target.id, "total").set(len(all_run_observables))
    metrics.run_observables.labels(target.id, "new").set(len(new_stix_ids))
    metrics.new_observables_total.labels(target.id).inc(len(new_stix_ids))

    # Update run record
    final_status = RunStatus.SUCCESS
    if errors and not any(r.success for r in results):
        final_status = RunStatus.FAILED
    elif errors:
        final_status = RunStatus.PARTIAL

    run_started_at = datetime.now(UTC)
    run_finished_at = datetime.now(UTC)
    async with get_session() as session:
        run = await session.get(Run, run_id)
        if run:
            run_started_at = run.started_at
            run.finished_at = datetime.now(UTC)
            run_finished_at = run.finished_at
            # The status stays RUNNING until the run is sealed below. It is the
            # per-target admission guard (run_control.create_pending_run): a
            # final status written here would admit a second run of this target
            # during synthesis, and whichever sealed first would make the other
            # chain to the wrong predecessor (a false "chain_link" break).
            run.collectors_run = ",".join(collectors_run)
            run.new_observables = len(new_stix_ids)
            run.error = "; ".join(errors) or None
            session.add(run)
            await session.commit()
    if final_status == RunStatus.SUCCESS:
        metrics.target_last_success_timestamp_seconds.labels(target.id).set(
            run_finished_at.timestamp()
        )

    report_data = RunReportData(
        target_id=target.id,
        target_fqdn=target.fqdn,
        authorization=target.authorization,
        purpose=target.purpose,
        classification=target.classification,
        processing=effective_provider(target),
        run_id=run_id,
        run_status=final_status.value,
        run_started_at=run_started_at,
        run_finished_at=run_finished_at,
        collector_results=[
            CollectorReportResult(
                collector=result.collector.value,
                success=result.success,
                error=result.error,
                observable_count=len(result.observables),
            )
            for result in results
        ],
        bundles=[b for b, _ in bundles],
        observables=report_observables,
        evidence=[_qualification_payload(row) for row in qualifications],
        errors=errors,
        language=target.language,
    )

    # Synthesize: collect → normalize → ingest → SYNTHESIZE → report.
    finding, synthesis_status = await synthesize(target, run_id, report_data, client=llm_client)
    metrics.synthesis_total.labels(target.id, synthesis_status or "unknown").inc()

    report_error: str | None = None
    report_path: str | None = None
    try:
        report_md = await generate_report(
            report_data,
            report_dir=target.report_dir,
            language=target.language,
            finding=finding,
            # synthesize returns only these three statuses, despite its str annotation.
            synthesis_status=cast(Literal["ok", "skipped", "failed"], synthesis_status),
        )
        report_path = str(report_md.resolve())
    except Exception as exc:  # noqa: BLE001
        report_error = f"report-generation: {exc}"
        logger.exception("Report generation failed for run %d", run_id, extra=log_ctx)

    async with get_session() as session:
        run = await session.get(Run, run_id)
        if run:
            if report_path is not None:
                run.report_path = report_path
            if report_error:
                run.error = f"{run.error}; {report_error}" if run.error else report_error
            if report_path is not None:
                # ADR-007: the manifest is the run's last file and its hash is
                # stored in the same commit as the final status. A failure here
                # leaves the run unsealed (counted, never read as tampering)
                # instead of losing the final status.
                try:
                    # Before the manifest, so the signed chain covers it.
                    _write_qualified_evidence_file(
                        report_path, qualifications, attempted=qualification_attempted
                    )
                    previous = await session.exec(
                        select(Run.manifest_sha256)
                        .where(Run.target_id == target.id)
                        .where(col(Run.manifest_sha256).is_not(None))
                        .where(Run.id != run_id)
                        .order_by(col(Run.started_at).desc(), col(Run.id).desc())
                        .limit(1)
                    )
                    manifest = build_manifest(
                        run_id=run_id,
                        target_id=target.id,
                        started_at=run_started_at,
                        finished_at=run_finished_at,
                        status=final_status.value,
                        collectors_run=collectors_run,
                        artefacts=_artefacts_for_manifest(report_path),
                        previous_manifest_sha256=previous.first(),
                        secret_key=settings.orchestrator_secret_key,
                    )
                    run.manifest_sha256 = write_manifest_file(
                        report_path=report_path, manifest=manifest
                    )
                except Exception:  # noqa: BLE001
                    logger.exception(
                        "Evidence manifest not written; run left unsealed run_id=%d",
                        run_id,
                        extra=log_ctx,
                    )
            run.status = final_status
            # Read before the commit: a session that expires attributes on
            # commit would otherwise lazy-load here, which is sync IO.
            manifest_sha256 = run.manifest_sha256
            session.add(run)
            await session.commit()
            if manifest_sha256:
                logger.info(
                    "Run sealed run_id=%d target=%s report=%s manifest_sha256=%s",
                    run_id,
                    target.id,
                    report_path,
                    manifest_sha256,
                    extra={
                        **log_ctx,
                        "report_path": report_path,
                        "manifest_sha256": manifest_sha256,
                    },
                )

    # Alert: final pipeline step — never changes run status.
    try:
        await _dispatch_alerts(
            target=target,
            run_id=run_id,
            run_status=final_status,
            finding=finding,
            report_path=report_path,
        )
    except Exception as exc:  # noqa: BLE001
        alert_err = f"alerts: {exc}"
        logger.exception("Alert dispatch setup failed for run %d: %s", run_id, exc, extra=log_ctx)
        async with get_session() as session:
            run = await session.get(Run, run_id)
            if run:
                run.error = f"{run.error}; {alert_err}" if run.error else alert_err
                session.add(run)
                await session.commit()

    logger.info(
        "Pipeline done: target=%s run_id=%d status=%s new_observables=%d",
        target.id,
        run_id,
        final_status.value,
        len(new_stix_ids),
        extra={
            **log_ctx,
            "status": final_status.value,
            "new_observables": len(new_stix_ids),
            "collectors": collectors_run,
        },
    )
    return final_status


async def _dispatch_alerts(
    *,
    target: Target,
    run_id: int,
    run_status: RunStatus,
    finding: object,
    report_path: str | None,
) -> None:
    """Evaluate alert rules and dispatch configured channels."""
    from orchestrator.alert_cases import open_case
    from orchestrator.alerts import AlertEvent, AlertObservable, alert_case_reason, build_notifiers
    from orchestrator.models import Finding as FindingModel

    cfg = target.alerts
    if not cfg.enabled:
        return

    risk_level = "unknown"
    finding_summary: str | None = None
    if isinstance(finding, FindingModel):
        risk_level = finding.risk_level
        finding_summary = finding.summary

    # Use the authoritative delta source (is_new AND ingested) so alert
    # payloads and GET /runs/{id}/delta are always consistent.
    delta_rows = await get_run_delta(run_id)
    new_observable_count = len(delta_rows)

    reason = alert_case_reason(
        new_observable_count=new_observable_count,
        risk_level=risk_level,
        run_status=run_status,
        cfg=cfg,
    )
    if reason is None:
        if run_status == RunStatus.FAILED:
            logger.info("Run %d FAILED without findings — no alert dispatched.", run_id)
        return

    # The case first: it is what the operator triages, and it must exist even
    # when no channel is configured or every channel fails.
    await open_case(
        run_id=run_id,
        target_id=target.id,
        run_status=run_status.value,
        risk_level=risk_level,
        new_observable_count=new_observable_count,
        reason=reason.value,
        session_factory=get_session,
    )

    new_obs_for_event: list[AlertObservable] = []
    if cfg.include_values:
        new_obs_for_event = [
            AlertObservable(
                stix_type=row["stix_type"],
                value=row["value"],
                stix_id=row["stix_id"],
            )
            for row in delta_rows
        ]

    event = AlertEvent(
        target_id=target.id,
        target_fqdn=target.fqdn,
        run_id=run_id,
        run_status=run_status.value,
        risk_level=risk_level,
        new_observables=new_obs_for_event,
        new_observable_count=new_observable_count,
        report_path=report_path,
        finding_summary=finding_summary,
        generated_at=datetime.now(UTC),
    )

    max_attempts = max(1, settings.alert_retry_max_attempts)
    notifiers = build_notifiers(language=target.language)
    for notifier in notifiers:
        alert_status = AlertStatus.SENT
        alert_error: str | None = None
        sent_at: datetime | None = None
        try:
            await notifier.send(event)
            sent_at = datetime.now(UTC)
            logger.info(
                "Alert sent via %s for run %d target %s",
                notifier.channel,
                run_id,
                target.id,
                extra={"target_id": target.id, "run_id": run_id, "channel": notifier.channel},
            )
        except Exception as exc:  # noqa: BLE001
            alert_status = AlertStatus.FAILED
            alert_error = str(exc)
            logger.exception(
                "Alert dispatch failed via %s for run %d: %s",
                notifier.channel,
                run_id,
                exc,
            )
            # Also annotate the run's error field (non-fatal).
            async with get_session() as session:
                run = await session.get(Run, run_id)
                if run:
                    suffix = f"alert-{notifier.channel}: {exc}"
                    run.error = f"{run.error}; {suffix}" if run.error else suffix
                    session.add(run)
                    await session.commit()
            await _queue_failed_alert_delivery(
                run_id=run_id,
                target_id=target.id,
                channel=notifier.channel,
                language=target.language,
                event=event,
                first_error=alert_error,
                max_attempts=max_attempts,
                permanent=_is_permanent_delivery_error(exc),
            )

        metrics.alerts_total.labels(notifier.channel, alert_status.value).inc()
        async with get_session() as session:
            session.add(
                AlertRecord(
                    run_id=run_id,
                    channel=notifier.channel,
                    status=alert_status,
                    error=alert_error,
                    sent_at=sent_at,
                )
            )
            await session.commit()


class _PermanentDeliveryError(RuntimeError):
    """A delivery failure no retry can fix (e.g. the channel is not configured)."""


# 4xx from a webhook (except 429) and an SMTP refusal are the receiver saying
# "not like this": the same request will be refused again. Everything else —
# timeouts, connection errors, 5xx, 429 — is the receiver saying "not now".
_PERMANENT_SMTP_ERRORS = (
    smtplib.SMTPAuthenticationError,
    smtplib.SMTPRecipientsRefused,
    smtplib.SMTPSenderRefused,
)


def _is_permanent_delivery_error(exc: BaseException) -> bool:
    if isinstance(exc, (_PermanentDeliveryError, *_PERMANENT_SMTP_ERRORS)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return 400 <= status < 500 and status != 429
    return False


async def _queue_failed_alert_delivery(
    *,
    run_id: int,
    target_id: str,
    channel: str,
    language: str | None,
    event: AlertEvent,
    first_error: str | None,
    max_attempts: int,
    permanent: bool = False,
) -> None:
    """Persist a failed alert delivery for retry, or dead-letter it outright."""
    now = datetime.now(UTC)
    status = AlertDeliveryStatus.PENDING
    next_attempt_at = _alert_next_attempt_at(1)
    if permanent or max_attempts <= 1:
        status = AlertDeliveryStatus.DEAD_LETTER
        next_attempt_at = now
        metrics.alerts_total.labels(channel, "dlq").inc()
        logger.warning(
            "Alert via %s for run %d parked in the dead-letter queue: %s (%s)",
            channel,
            run_id,
            first_error,
            "permanent error" if permanent else "retries disabled",
            extra={"target_id": target_id, "run_id": run_id, "channel": channel},
        )

    async with get_session() as session:
        session.add(
            AlertDelivery(
                run_id=run_id,
                target_id=target_id,
                channel=channel,
                language=language,
                payload_json=json.dumps(event.model_dump(mode="json")),
                status=status,
                attempts=1,
                max_attempts=max_attempts,
                next_attempt_at=next_attempt_at,
                last_error=first_error,
                updated_at=now,
            )
        )
        await session.commit()
    await _update_alert_queue_metrics()


async def _delivery_record_success(row_id: int, attempt: int) -> None:
    now = datetime.now(UTC)
    async with get_session() as session:
        delivery = await session.get(AlertDelivery, row_id)
        if delivery is None:
            return
        delivery.status = AlertDeliveryStatus.SENT
        delivery.sent_at = now
        delivery.updated_at = now
        delivery.attempts = attempt
        delivery.last_error = None
        session.add(delivery)
        session.add(
            AlertRecord(
                run_id=delivery.run_id,
                channel=delivery.channel,
                status=AlertStatus.SENT,
                error=None,
                sent_at=now,
            )
        )
        channel = delivery.channel
        await session.commit()
    metrics.alerts_total.labels(channel, AlertStatus.SENT.value).inc()


async def _delivery_record_failure(
    row_id: int, attempt: int, exc: BaseException, permanent: bool
) -> bool:
    """Persist a failed attempt; return True when the row went to the dead-letter queue."""
    now = datetime.now(UTC)
    async with get_session() as session:
        delivery = await session.get(AlertDelivery, row_id)
        if delivery is None:
            return False
        delivery.attempts = attempt
        delivery.last_error = str(exc)
        delivery.updated_at = now
        dead = permanent or attempt >= delivery.max_attempts
        if dead:
            delivery.status = AlertDeliveryStatus.DEAD_LETTER
            delivery.next_attempt_at = now
        else:
            delivery.status = AlertDeliveryStatus.PENDING
            delivery.next_attempt_at = _alert_next_attempt_at(attempt)
        session.add(delivery)
        session.add(
            AlertRecord(
                run_id=delivery.run_id,
                channel=delivery.channel,
                status=AlertStatus.FAILED,
                error=str(exc),
                sent_at=None,
            )
        )
        channel, run_id, target_id = delivery.channel, delivery.run_id, delivery.target_id
        max_attempts = delivery.max_attempts
        await session.commit()
    metrics.alerts_total.labels(channel, AlertStatus.FAILED.value).inc()
    if dead:
        metrics.alerts_total.labels(channel, "dlq").inc()
        logger.warning(
            "Alert via %s for run %d parked in the dead-letter queue after %d/%d attempt(s): "
            "%s (%s)",
            channel,
            run_id,
            attempt,
            max_attempts,
            exc,
            "permanent error" if permanent else "retries exhausted",
            extra={"target_id": target_id, "run_id": run_id, "channel": channel},
        )
    return dead


async def process_pending_alert_deliveries(limit: int = 100) -> dict[str, int]:
    """Retry due alert deliveries, one transaction per row (see _claim_row)."""
    from orchestrator.alerts import AlertEvent, build_notifiers

    counts = {"processed": 0, "sent": 0, "failed": 0, "retried": 0, "dlq": 0}
    now = datetime.now(UTC)
    capped_limit = min(max(1, limit), 1000)

    async with get_session() as session:
        due_ids = (
            await session.exec(
                select(AlertDelivery.id)
                .where(AlertDelivery.status == AlertDeliveryStatus.PENDING)
                .where(col(AlertDelivery.next_attempt_at) <= now)
                .order_by(col(AlertDelivery.id).asc())
                .limit(capped_limit)
            )
        ).all()

    for row_id in due_ids:
        # IDs selected from persisted rows are non-null primary keys.
        assert row_id is not None
        async with get_session() as session:
            claimed = await _claim_row(
                session,
                AlertDelivery,
                row_id,
                AlertDeliveryStatus.PENDING,
                AlertDeliveryStatus.IN_PROGRESS,
            )
            if not claimed:
                continue
            # The claim matched an existing row; preserve the failure if retention removes it.
            delivery = cast(AlertDelivery, await session.get(AlertDelivery, row_id))
            channel, language = delivery.channel, delivery.language
            payload_json, attempt = delivery.payload_json, delivery.attempts + 1

        counts["processed"] += 1
        counts["retried"] += 1
        metrics.alerts_total.labels(channel, "retried").inc()
        notifier = next(
            (n for n in build_notifiers(language=language) if n.channel == channel),
            None,
        )
        try:
            if notifier is None:
                raise _PermanentDeliveryError(f"Channel not configured: {channel}")
            event = AlertEvent.model_validate_json(payload_json)
            await notifier.send(event)
        except Exception as exc:  # noqa: BLE001
            counts["failed"] += 1
            permanent = _is_permanent_delivery_error(exc)
            if await _delivery_record_failure(row_id, attempt, exc, permanent):
                counts["dlq"] += 1
            continue
        await _delivery_record_success(row_id, attempt)
        counts["sent"] += 1

    await _update_alert_queue_metrics()
    return counts


async def replay_alert_dead_letters(
    *,
    channel: str | None = None,
    run_id: int | None = None,
    limit: int = 100,
) -> dict[str, int]:
    """Move dead-letter deliveries back to pending for retry processing."""
    moved = 0
    now = datetime.now(UTC)
    capped_limit = min(max(1, limit), 1000)
    async with get_session() as session:
        stmt = (
            select(AlertDelivery)
            .where(AlertDelivery.status == AlertDeliveryStatus.DEAD_LETTER)
            .order_by(col(AlertDelivery.id).asc())
            .limit(capped_limit)
        )
        if channel:
            stmt = stmt.where(AlertDelivery.channel == channel)
        if run_id is not None:
            stmt = stmt.where(AlertDelivery.run_id == run_id)

        result = await session.exec(stmt)
        deliveries = result.all()
        for delivery in deliveries:
            moved += 1
            delivery.status = AlertDeliveryStatus.PENDING
            delivery.attempts = 0
            delivery.last_error = None
            delivery.next_attempt_at = now
            delivery.updated_at = now
            session.add(delivery)
        await session.commit()
    return {"moved": moved}
