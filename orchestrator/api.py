"""
FastAPI application: health, metrics, targets CRUD, run trigger, run status.

Data/control endpoints sit behind the API-key dependency
(orchestrator/auth.py). Public routes are mounted on `app` by design
(/, /docs, /openapi.json, /redoc, /health, /metrics).
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from enum import StrEnum
from pathlib import Path
from time import perf_counter
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlmodel import select

from orchestrator import metrics
from orchestrator.auth import log_auth_status, require_api_key
from orchestrator.config import settings
from orchestrator.database import create_db_and_tables, get_session
from orchestrator.i18n import console_i18n_catalogue, resolve_language, t
from orchestrator.logging_config import configure_logging, request_id_var
from orchestrator.models import AlertRecord, FindingRecord, Run, Target
from orchestrator.pipeline import (
    drain_opencti_outbox,
    get_run_delta,
    process_pending_alert_deliveries,
    replay_alert_dead_letters,
    replay_opencti_dead_letters,
    requeue_interrupted_deliveries,
    run_target_pipeline,
)
from orchestrator.run_control import create_pending_run, mark_interrupted_runs
from orchestrator.scheduler import (
    preview_reload_targets,
    reload_targets,
    shutdown_scheduler,
    start_scheduler,
)
from orchestrator.targets import load_targets

logger = logging.getLogger(__name__)

# Keep in sync with [project].version in pyproject.toml (surfaced via
# GET /health and the build_info metric).
VERSION = "0.1.0"
REQUEST_ID_HEADER = "X-Request-ID"
# A caller-supplied request id is echoed into a response header and every log
# line, so it is reduced to printable ASCII without whitespace: no CR/LF
# (header/log injection), no control or non-ASCII bytes, and a hard cap so a
# hostile client cannot push kilobytes into each record.
_REQUEST_ID_UNSAFE = re.compile(r"[^\x21-\x7e]")
REQUEST_ID_MAX_LEN = 64


def sanitize_request_id(raw: bytes | None) -> str:
    """Return a safe request id: the caller's, cleaned, or a fresh one."""
    if raw:
        cleaned = _REQUEST_ID_UNSAFE.sub("", raw.decode("ascii", errors="ignore"))
        if cleaned:
            return cleaned[:REQUEST_ID_MAX_LEN]
    return uuid.uuid4().hex[:16]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Configure logging/metrics, create the schema and run the scheduler.

    Startup order matters: logging first (so every later step is traceable),
    then the database schema (Alembic upgrade inside ``create_db_and_tables``),
    then APScheduler bound to the running event loop. Shutdown stops the
    scheduler before the loop goes away.
    """
    configure_logging()
    log_auth_status()
    metrics.set_build_info(VERSION)
    await create_db_and_tables()
    interrupted = await mark_interrupted_runs()
    if interrupted:
        logger.warning(
            "Marked %d run(s) interrupted by the previous shutdown as failed", interrupted
        )
    # Same reasoning for the queues: a row claimed IN_PROGRESS by a process
    # that no longer exists is a row whose drain died mid-send.
    requeued = await requeue_interrupted_deliveries()
    if any(requeued.values()):
        logger.warning(
            "Returned %d alert delivery(ies) and %d OpenCTI outbox row(s) left in progress "
            "by the previous shutdown to the queue",
            requeued["alert_deliveries"],
            requeued["opencti_outbox"],
        )
    # APScheduler's AsyncIOScheduler binds to the running event loop, so it
    # has to be started here rather than at import time. Without this the
    # cron in targets.yaml is never registered and the orchestrator only ever
    # runs when POST /targets/{id}/run is called by hand.
    start_scheduler()
    try:
        yield
    finally:
        shutdown_scheduler()


_OPENAPI_TAGS = [
    {"name": "public", "description": "Unauthenticated health/landing endpoints."},
    {
        "name": "targets",
        "description": "Target registry loaded from targets.yaml (read-only at runtime).",
    },
    {"name": "runs", "description": "Collection runs: trigger, status, delta, report and finding."},
    {"name": "scheduler", "description": "Runtime reload of cron jobs from targets.yaml."},
    {"name": "alerts", "description": "Alert delivery operations (DLQ replay)."},
    {"name": "analytics", "description": "Aggregated views for the operator console."},
    {"name": "console", "description": "Minimal read-only operator web console."},
]

app = FastAPI(
    title="OSINT Orchestrator",
    version=VERSION,
    summary="Orchestrates OSINT collectors, normalises findings to STIX 2.1 and ingests them into OpenCTI.",
    description=(
        "Every endpoint except `GET /`, `GET /health` and `GET /metrics` requires an API key "
        "(`X-API-Key: <key>` or `Authorization: Bearer <key>`). Error `detail` strings are "
        "localised per ADR-004. See the repository README for the full operator guide."
    ),
    openapi_tags=_OPENAPI_TAGS,
    contact={
        "name": "OSINT Orchestrator maintainers",
        "url": "https://github.com/careb36/osint-orchestrator-oss/issues",
    },
    license_info={
        "name": "MIT",
        "url": "https://github.com/careb36/osint-orchestrator-oss/blob/main/LICENSE",
    },
    lifespan=lifespan,
)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


# ─── Request context middleware ──────────────────────────────────────────────


class RequestContextMiddleware:
    """
    Pure-ASGI middleware: bind a request id for logging, echo it back in the
    response, and record HTTP metrics keyed by the *route template*.

    Pure ASGI rather than BaseHTTPMiddleware so BackgroundTasks (used by
    POST /targets/{id}/run) and streaming responses behave exactly as
    without the middleware.
    """

    def __init__(self, app):  # noqa: ANN001 - ASGI app
        self.app = app

    async def __call__(self, scope, receive, send):  # noqa: ANN001 - ASGI signature
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Honour a caller-supplied id (a reverse proxy or a SOAR playbook
        # correlating its own trace), sanitised — see sanitize_request_id.
        incoming = next((v for k, v in scope.get("headers", []) if k == b"x-request-id"), None)
        request_id = sanitize_request_id(incoming)
        token = request_id_var.set(request_id)
        status_code = 500
        started = perf_counter()

        async def send_wrapper(message):  # noqa: ANN001 - ASGI message
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((REQUEST_ID_HEADER.lower().encode(), request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            request_id_var.reset(token)
            route = scope.get("route")
            # Unmatched paths (404s, probes for /wp-admin) collapse into one
            # label value so they cannot blow up cardinality.
            path = getattr(route, "path", None) or "<unmatched>"
            method = scope.get("method", "")
            metrics.http_requests_total.labels(method, path, str(status_code)).inc()
            metrics.http_request_duration_seconds.labels(method, path).observe(
                perf_counter() - started
            )


app.add_middleware(RequestContextMiddleware)


# ─── Public: health & metrics ────────────────────────────────────────────────


@app.get("/health", tags=["public"])
async def health() -> dict[str, str]:
    """Liveness probe: returns the service status and version. No API key."""
    return {"status": "ok", "version": VERSION}


@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics() -> Response:
    """Prometheus exposition. Unauthenticated: scrapers are not API clients."""
    if not settings.orchestrator_metrics_enabled:
        raise HTTPException(status_code=404, detail=t("metrics_disabled"))
    payload, content_type = metrics.render()
    return Response(content=payload, media_type=content_type)


@app.get("/", include_in_schema=False)
async def root(request: Request) -> HTMLResponse:
    """Public landing page with the main entry points for the service."""
    language = resolve_language(None)
    return templates.TemplateResponse(
        request=request,
        name="landing.html",
        context={
            "language": language,
            "landing_title": t("landing_title", language=language),
            "landing_heading": t("landing_heading", language=language),
            "landing_intro": t("landing_intro", language=language),
            "landing_docs": t("landing_docs", language=language),
            "landing_health": t("landing_health", language=language),
            "landing_console": t("landing_console", language=language),
        },
    )


# ─── Protected API ───────────────────────────────────────────────────────────

router = APIRouter(dependencies=[Depends(require_api_key)])


def _load_targets() -> list[Target]:
    """Load valid targets from targets.yaml (read-only at runtime)."""
    targets, _errors = load_targets(settings.targets_file)
    return targets


class AlertChannel(StrEnum):
    WEBHOOK = "webhook"
    EMAIL = "email"


_DLQ_CHANNEL_QUERY = Query(default=None)
_DLQ_LIMIT_QUERY = Query(default=100, ge=1, le=1000)


@router.get("/targets", response_model=list[dict[str, Any]], tags=["targets"])
async def list_targets() -> list[dict[str, Any]]:
    """List all configured targets from targets.yaml."""
    targets = _load_targets()
    return [target.model_dump() for target in targets]


@router.get("/targets/{target_id}", response_model=dict[str, Any], tags=["targets"])
async def get_target(target_id: str) -> dict[str, Any]:
    """Return a single configured target, or 404 if the id is unknown."""
    targets = _load_targets()
    for target in targets:
        if target.id == target_id:
            return target.model_dump()
    raise HTTPException(status_code=404, detail=t("target_not_found", target_id=target_id))


@router.post("/targets/{target_id}/run", status_code=202, tags=["runs"])
async def trigger_run(target_id: str, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Manually trigger a collection run for a target."""
    targets = _load_targets()
    target = next((c for c in targets if c.id == target_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail=t("target_not_found", target_id=target_id))
    if not target.enabled:
        # The target exists here, so honour its per-target language override.
        raise HTTPException(
            status_code=400,
            detail=t("target_disabled", language=target.language, target_id=target_id),
        )

    run_id = await create_pending_run(target_id)
    if run_id is None:
        raise HTTPException(
            status_code=409,
            detail=t("run_already_in_progress", language=target.language, target_id=target_id),
        )

    logger.info(
        "Manual run accepted", extra={"target_id": target_id, "run_id": run_id, "trigger": "api"}
    )
    background_tasks.add_task(run_target_pipeline, target, run_id)
    return {"run_id": run_id, "status": "accepted", "target_id": target_id}


@router.post("/scheduler/reload", response_model=dict[str, Any], tags=["scheduler"])
async def reload_scheduler_targets() -> dict[str, Any]:
    """
    Reload targets.yaml into APScheduler without restarting the API process.
    """
    summary = reload_targets().as_dict()
    status = "reloaded" if not summary["invalid_targets"] else "reloaded_with_errors"
    return {"status": status, **summary}


@router.post("/scheduler/reload/preview", response_model=dict[str, Any], tags=["scheduler"])
async def preview_scheduler_reload_targets() -> dict[str, Any]:
    """
    Preview scheduler changes from targets.yaml without mutating existing jobs.
    """
    summary = preview_reload_targets().as_dict()
    status = "preview_ok" if not summary["invalid_targets"] else "preview_with_errors"
    return {"status": status, **summary}


@router.post("/alerts/dlq/replay", response_model=dict[str, Any], tags=["alerts"])
async def replay_alert_dlq(
    channel: AlertChannel | None = _DLQ_CHANNEL_QUERY,
    run_id: int | None = None,
    limit: int = _DLQ_LIMIT_QUERY,
) -> dict[str, Any]:
    """Move dead-letter alert deliveries back to pending and process due retries."""
    replayed = await replay_alert_dead_letters(
        channel=channel.value if channel is not None else None,
        run_id=run_id,
        limit=limit,
    )
    processed = await process_pending_alert_deliveries(limit=limit)
    return {"status": "replayed", **replayed, "processed_now": processed}


@router.post("/opencti/outbox/replay", response_model=dict[str, Any], tags=["opencti"])
async def replay_opencti_outbox(
    run_id: int | None = None,
    limit: int = _DLQ_LIMIT_QUERY,
) -> dict[str, Any]:
    """Move dead-letter OpenCTI bundles back to pending and drain the due ones now."""
    replayed = await replay_opencti_dead_letters(run_id=run_id, limit=limit)
    processed = await drain_opencti_outbox(limit=limit)
    return {"status": "replayed", **replayed, "processed_now": processed}


@app.get("/console", response_class=HTMLResponse, include_in_schema=False)
async def operator_console(request: Request) -> HTMLResponse:
    """
    Minimal read-only operator console backed by existing API endpoints.

    Mounted on ``app``, not ``router``: the shell carries no target or run
    data — every fetch it makes (/runs, /targets, /analytics/...) goes through
    the protected router with the key the operator types into it. Behind the
    key, a browser could never reach the page that asks for the key.
    """
    # The console renders API data — including run.error, which quotes
    # collector and OpenCTI exception text that can carry internet-derived
    # strings — into the same origin that holds the operator's API key. The
    # template escapes every interpolation; the CSP is the second line: only
    # this response's inline script/style (by nonce) may execute, nothing may
    # be fetched from elsewhere, and the page cannot be framed.
    nonce = secrets.token_urlsafe(16)
    csp = (
        f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    )
    return templates.TemplateResponse(
        request=request,
        name="console.html",
        context={"default_language": resolve_language(None), "csp_nonce": nonce},
        headers={
            "Content-Security-Policy": csp,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        },
    )


@app.get("/console/i18n.json", include_in_schema=False)
async def operator_console_i18n() -> JSONResponse:
    """Translations used by the operator console frontend."""
    return JSONResponse(console_i18n_catalogue())


@router.get("/analytics/risk-trends", response_model=list[dict[str, Any]], tags=["analytics"])
async def risk_trends() -> list[dict[str, Any]]:
    """Return per-target risk/new-observable trends for the last 20 runs each."""
    risk_rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    rank_to_risk = {v: k for k, v in risk_rank.items()}
    history_limit = 20

    runs_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    findings_by_run_id: dict[int, FindingRecord] = {}
    async with get_session() as session:
        ranked_runs = select(
            Run.id.label("id"),
            Run.target_id.label("target_id"),
            Run.status.label("status"),
            Run.started_at.label("started_at"),
            Run.new_observables.label("new_observables"),
            func.row_number()
            .over(partition_by=Run.target_id, order_by=Run.started_at.desc())
            .label("rank"),
        ).subquery()
        runs_result = await session.exec(
            select(
                ranked_runs.c.id,
                ranked_runs.c.target_id,
                ranked_runs.c.status,
                ranked_runs.c.started_at,
                ranked_runs.c.new_observables,
            )
            .where(ranked_runs.c.rank <= history_limit)
            .order_by(ranked_runs.c.target_id.asc(), ranked_runs.c.started_at.desc())
        )
        runs = runs_result.all()
        run_ids = [int(run.id) for run in runs if run.id is not None]
        for run in runs:
            if run.id is None:
                continue
            runs_by_target[str(run.target_id)].append(
                {
                    "id": int(run.id),
                    "status": run.status,
                    "new_observables": run.new_observables,
                }
            )

        if run_ids:
            findings_result = await session.exec(
                select(FindingRecord).where(FindingRecord.run_id.in_(run_ids))
            )
            findings_by_run_id.update({record.run_id: record for record in findings_result.all()})

    trends: list[dict[str, Any]] = []
    for target_id, target_runs in sorted(runs_by_target.items()):
        scoped_runs = target_runs[:history_limit]
        risk_history = []
        new_observables_history = []
        for run in reversed(scoped_runs):
            finding = findings_by_run_id.get(run["id"])
            risk_level = finding.risk_level if finding else "unknown"
            risk_history.append(risk_level)
            new_observables_history.append(run["new_observables"])

        latest_run = scoped_runs[0]
        latest_risk = risk_history[-1] if risk_history else "unknown"
        peak_risk = (
            rank_to_risk[max(risk_rank.get(level, 0) for level in risk_history)]
            if risk_history
            else "unknown"
        )
        trends.append(
            {
                "target_id": target_id,
                "runs_considered": len(scoped_runs),
                "latest_run_id": latest_run["id"],
                "latest_status": latest_run["status"],
                "latest_risk_level": latest_risk,
                "peak_risk_level": peak_risk,
                "risk_history": risk_history,
                "new_observables_history": new_observables_history,
            }
        )
    return trends


@router.get("/runs", response_model=list[dict[str, Any]], tags=["runs"])
async def list_runs(target_id: str | None = None) -> list[dict[str, Any]]:
    """List recent runs, optionally filtered by target."""
    async with get_session() as session:
        stmt = select(Run).order_by(Run.started_at.desc()).limit(100)  # type: ignore[arg-type]
        if target_id:
            stmt = stmt.where(Run.target_id == target_id)
        result = await session.exec(stmt)
        runs = result.all()
    return [r.model_dump() for r in runs]


@router.get("/runs/{run_id}", response_model=dict[str, Any], tags=["runs"])
async def get_run(run_id: int) -> dict[str, Any]:
    """Return a run's status and counts, plus its alert dispatch audit trail."""
    async with get_session() as session:
        run = await session.get(Run, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=t("run_not_found", run_id=run_id))
        result = await session.exec(select(AlertRecord).where(AlertRecord.run_id == run_id))
        alert_records = result.all()
    data = run.model_dump()
    data["alerts"] = [a.model_dump() for a in alert_records]
    return data


@router.get("/runs/{run_id}/delta", response_model=list[dict[str, Any]], tags=["runs"])
async def get_run_delta_endpoint(run_id: int) -> list[dict[str, Any]]:
    """Return the net-new observables for a run (Issue #10)."""
    async with get_session() as session:
        run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=t("run_not_found", run_id=run_id))
    return await get_run_delta(run_id)


@router.get("/runs/{run_id}/report", response_class=PlainTextResponse, tags=["runs"])
async def get_run_report(run_id: int) -> PlainTextResponse:
    """Serve the Markdown operator report of a completed run as text/plain."""
    async with get_session() as session:
        run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=t("run_not_found", run_id=run_id))
    if not run.report_path:
        raise HTTPException(status_code=404, detail=t("report_not_found", run_id=run_id))
    if not os.path.exists(run.report_path):
        raise HTTPException(status_code=404, detail=t("report_not_found", run_id=run_id))
    return PlainTextResponse(Path(run.report_path).read_text(encoding="utf-8"))


@router.get("/runs/{run_id}/finding", response_model=dict[str, Any], tags=["runs"])
async def get_run_finding(run_id: int) -> dict[str, Any]:
    """Return the synthesized Finding for a completed run, or 404."""
    async with get_session() as session:
        result = await session.exec(select(FindingRecord).where(FindingRecord.run_id == run_id))
        record = result.first()
    if record is None:
        raise HTTPException(status_code=404, detail=t("finding_not_found", run_id=run_id))
    return record.to_api_dict()


app.include_router(router)


def main() -> None:
    """Run the API with uvicorn (container/bare-metal entry point)."""
    import uvicorn

    # log_config=None: uvicorn must not install its own handlers; lifespan()
    # configures the root logger and routes uvicorn's loggers through it.
    uvicorn.run("orchestrator.api:app", host="0.0.0.0", port=8000, reload=False, log_config=None)


if __name__ == "__main__":
    main()
