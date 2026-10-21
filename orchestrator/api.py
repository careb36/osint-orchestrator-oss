"""
FastAPI application: health, metrics, targets CRUD, run trigger, run status.

Data/control endpoints sit behind the API-key dependency
(orchestrator/auth.py). Public routes are mounted on `app` by design
(/, /docs, /openapi.json, /redoc, /health, /metrics).
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import secrets
import uuid
import zipfile
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from time import perf_counter
from typing import Any

import jsonschema
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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy import select as sa_select
from sqlmodel import col, select

from orchestrator import alert_cases, metrics
from orchestrator.auth import log_auth_status, log_secret_key_status, require_api_key
from orchestrator.config import NEBIUS_DEFAULT_BASE_URL, settings
from orchestrator.contracts import load_schema
from orchestrator.database import create_db_and_tables, get_session
from orchestrator.evidence import (
    load_manifest_file,
    manifest_path_for_report,
    split_keys,
    verify_target_chain,
)
from orchestrator.i18n import resolve_language, t
from orchestrator.logging_config import configure_logging, request_id_var
from orchestrator.models import (
    AlertCase,
    AlertCaseState,
    AlertRecord,
    EvidenceQualification,
    FindingRecord,
    Run,
    Target,
)
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
from orchestrator.sinks import OpenCTIIngestError, OpenCTISink
from orchestrator.synthesizer.providers.openai_compat import preflight_configured_models
from orchestrator.synthesizer.qualify import load_run_qualifications
from orchestrator.targets import load_targets

logger = logging.getLogger(__name__)

# Keep in sync with [project].version in pyproject.toml (surfaced via
# GET /health and the build_info metric).
VERSION = "0.1.0"
REQUEST_ID_HEADER = "X-Request-ID"
_LLM_MODEL_PREFLIGHT_TIMEOUT_SECONDS = 10.0
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
    log_secret_key_status()
    await _run_llm_model_preflight()
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
    await alert_cases.refresh_metrics()
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


async def _run_llm_model_preflight() -> None:
    provider = settings.llm_provider.strip().lower()
    if provider == "openai":
        api_key = settings.openai_api_key.strip()
        base_url = settings.openai_base_url.strip()
    elif provider == "nebius":
        api_key = settings.nebius_api_key.strip()
        base_url = settings.nebius_base_url.strip() or NEBIUS_DEFAULT_BASE_URL
    else:
        return
    if not api_key:
        return
    try:
        await asyncio.wait_for(
            preflight_configured_models(
                provider_name=provider,
                api_key=api_key,
                base_url=base_url,
            ),
            timeout=_LLM_MODEL_PREFLIGHT_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        logger.warning(
            "LLM model preflight timed out; continuing startup provider=%s",
            provider,
            extra={"provider": provider},
        )


_OPENAPI_TAGS = [
    {"name": "public", "description": "Unauthenticated health/landing endpoints."},
    {
        "name": "targets",
        "description": "Target registry loaded from targets.yaml (read-only at runtime).",
    },
    {"name": "runs", "description": "Collection runs: trigger, status, delta, report and finding."},
    {"name": "scheduler", "description": "Runtime reload of cron jobs from targets.yaml."},
    {"name": "alerts", "description": "Alert delivery operations (DLQ replay)."},
    {"name": "opencti", "description": "OpenCTI outbox operations (DLQ replay)."},
    {
        "name": "bundles",
        "description": "Intake of STIX 2.1 bundles from external producers (ADR-011).",
    },
    {"name": "analytics", "description": "Aggregated views for the operator console."},
    {"name": "console", "description": "Minimal read-only operator web console."},
]

app = FastAPI(
    title="OSINT Orchestrator",
    version=VERSION,
    summary="Orchestrates OSINT collectors, normalises findings to STIX 2.1 and ingests them into OpenCTI.",
    description=(
        "Every endpoint except `GET /`, `GET /health`, `GET /metrics`, the documentation pages, "
        "and the console shell requires an API key "
        "(`X-API-Key: <key>` or `Authorization: Bearer <key>`). Error `detail` strings are "
        "localised per ADR-004. See docs/operations.md in the repository for the operator guide."
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

# Production build of the React dashboard (ui/, `npm run build`). The Docker
# images copy ui/dist here; a source checkout without the build gets a 503
# page from /console that says how to build it.
UI_DIST_DIR = Path(__file__).parent / "static" / "ui-dist"


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
        recorded = False

        def record() -> None:
            # Once per request: when the last body chunk is sent, or in the
            # finally below for a request that never produced a response.
            nonlocal recorded
            if recorded:
                return
            recorded = True
            route = scope.get("route")
            # Unmatched paths (404s, probes for /wp-admin) collapse into one
            # label value so they cannot blow up cardinality.
            path = getattr(route, "path", None) or "<unmatched>"
            method = scope.get("method", "")
            metrics.http_requests_total.labels(method, path, str(status_code)).inc()
            metrics.http_request_duration_seconds.labels(method, path).observe(
                perf_counter() - started
            )

        async def send_wrapper(message):  # noqa: ANN001 - ASGI message
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((REQUEST_ID_HEADER.lower().encode(), request_id.encode()))
                message["headers"] = headers
            await send(message)
            # Starlette runs BackgroundTasks inside the same app call, after
            # the response: timing the whole call would charge a manual run's
            # collectors (minutes) to a 202 that was served in milliseconds.
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                record()

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            request_id_var.reset(token)
            record()


app.add_middleware(RequestContextMiddleware)


# ─── Public: health & metrics ────────────────────────────────────────────────


def _health_hint(component: str, status: str, detail: str) -> tuple[str, str]:
    """Return a user-facing recovery hint plus a compact action label."""
    hints = {
        "api": {
            "ok": (
                "API is responding normally.",
                "Monitor the endpoint and keep the API key current.",
            ),
            "degraded": (
                "The API is unhealthy; check the process logs and recent errors.",
                "Review service logs and restart the API if needed.",
            ),
            "offline": (
                "The API is not responding.",
                "Restart the orchestrator process and confirm it is listening on the configured port.",
            ),
        },
        "database": {
            "ok": (
                "Database connection is healthy.",
                "Continue monitoring for slow queries or lock contention.",
            ),
            "degraded": (
                "Database latency or availability is degraded.",
                "Check connectivity and review the database service for lock contention.",
            ),
            "offline": (
                "Database connectivity check failed.",
                "Verify the database URI, credentials, and service availability before retrying.",
            ),
        },
        "scheduler": {
            "ok": (
                "Scheduler is running and dispatching jobs.",
                "Keep the target schedule and job reloads under observation.",
            ),
            "degraded": (
                "The scheduler is not active.",
                "Restart the scheduler or reload the target schedule from the control plane.",
            ),
            "offline": (
                "The scheduler is unavailable.",
                "Inspect the scheduler process and restart it before triggering runs.",
            ),
        },
        "opencti": {
            "ok": (
                "OpenCTI ingestion is enabled.",
                "Continue monitoring for sink lag or ingestion errors.",
            ),
            "disabled": (
                "OpenCTI ingestion is switched off by configuration (ADR-008).",
                "Set OPENCTI_ENABLED=true to push findings to the knowledge graph.",
            ),
            "degraded": (
                "OpenCTI ingest is disabled or not reachable.",
                "Enable OPENCTI_ENABLED or repair the OpenCTI connection before scheduled runs.",
            ),
            "offline": (
                "OpenCTI ingestion is failing.",
                "Check the OpenCTI endpoint, credentials, and broker connectivity before retrying.",
            ),
        },
    }
    compact = hints.get(component, {}).get(
        status, (detail, "Check the service diagnostics and retry.")
    )
    return compact[0], compact[1]


async def _health_snapshot() -> dict[str, Any]:
    """Component checks and their rollup, shared by /health and /ready."""
    checks: dict[str, dict[str, str]] = {
        "api": {"status": "ok", "detail": "API is responding"},
        "database": {"status": "ok", "detail": "Database is available"},
        "scheduler": {"status": "ok", "detail": "Scheduler is running"},
        "opencti": {"status": "ok", "detail": "OpenCTI sink is enabled"},
    }

    try:
        async with get_session() as session:
            await session.exec(select(1))
    except Exception:
        checks["database"] = {"status": "offline", "detail": "Database check failed"}

    scheduler_running = False
    try:
        from orchestrator.scheduler import scheduler as scheduler_runtime

        scheduler_running = bool(scheduler_runtime.running)
    except Exception:
        scheduler_running = False
    if not scheduler_running:
        checks["scheduler"] = {"status": "degraded", "detail": "Scheduler is not running"}

    if not settings.opencti_enabled:
        # ADR-008: the sink is optional. A deployment that chose to run
        # without it is configured, not degraded, so the choice must not
        # fail health checks or colour the dashboard as a fault.
        checks["opencti"] = {"status": "disabled", "detail": "OpenCTI sink disabled"}

    for component, payload in checks.items():
        status = payload["status"]
        detail = payload["detail"]
        hint, action = _health_hint(component, status, detail)
        payload["hint"] = hint
        payload["action"] = action
        payload["recovery"] = hint

    if any(payload["status"] == "offline" for payload in checks.values()):
        overall = "offline"
    elif any(payload["status"] == "degraded" for payload in checks.values()):
        overall = "degraded"
    else:
        overall = "ok"

    return {
        "status": overall,
        "version": VERSION,
        "updated_at": datetime.now(UTC).isoformat(),
        "checks": checks,
    }


@app.get("/health", tags=["public"])
async def health() -> dict[str, Any]:
    """Liveness: always HTTP 200 while the process answers; the body carries
    the component checks and their rollup for the dashboard."""
    return await _health_snapshot()


@app.get("/ready", tags=["public"])
async def ready() -> JSONResponse:
    """Readiness: the same snapshot, but HTTP 503 while the service cannot do
    its job (a component is offline, or the scheduler is not running). This is
    what the compose healthcheck and the Kubernetes readiness probe call, so a
    dead database or scheduler is visible to the orchestrator around us."""
    snapshot = await _health_snapshot()
    ready_now = snapshot["status"] != "offline" and (
        snapshot["checks"]["scheduler"]["status"] == "ok"
    )
    return JSONResponse(snapshot, status_code=200 if ready_now else 503)


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
            "landing_status": t("landing_status", language=language),
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


class AlertCaseAction(BaseModel):
    """Who acted on the case and, optionally, what they found."""

    by: str = Field(min_length=1, max_length=80)
    note: str | None = Field(default=None, max_length=500)


def _alert_case_payload(case: AlertCase) -> dict[str, Any]:
    return case.model_dump()


@router.get("/alerts", response_model=dict[str, Any], tags=["alerts"])
async def list_alert_cases(
    target_id: str | None = None,
    state: AlertCaseState | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """Alert cases newest first: one per run that met an alert rule, with its
    triage state. ``total`` counts every case the filters match."""
    rows, total = await alert_cases.list_cases(
        target_id=target_id,
        state=state.value if state is not None else None,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [_alert_case_payload(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/alerts/{case_id}", response_model=dict[str, Any], tags=["alerts"])
async def get_alert_case(case_id: int) -> dict[str, Any]:
    try:
        return _alert_case_payload(await alert_cases.get_case(case_id))
    except alert_cases.AlertCaseNotFoundError:
        raise HTTPException(status_code=404, detail=t("alert_not_found", case_id=case_id)) from None


@router.post("/alerts/{case_id}/ack", response_model=dict[str, Any], tags=["alerts"])
async def acknowledge_alert_case(case_id: int, action: AlertCaseAction) -> dict[str, Any]:
    """open → acknowledged: an operator is looking at it."""
    try:
        case = await alert_cases.acknowledge_case(case_id, by=action.by, note=action.note)
    except alert_cases.AlertCaseNotFoundError:
        raise HTTPException(status_code=404, detail=t("alert_not_found", case_id=case_id)) from None
    except alert_cases.AlertCaseStateConflictError as exc:
        raise HTTPException(
            status_code=409, detail=t("alert_state_conflict", state=exc.state)
        ) from exc
    return _alert_case_payload(case)


@router.post("/alerts/{case_id}/resolve", response_model=dict[str, Any], tags=["alerts"])
async def resolve_alert_case(case_id: int, action: AlertCaseAction) -> dict[str, Any]:
    """open | acknowledged → resolved: nothing more to do."""
    try:
        case = await alert_cases.resolve_case(case_id, by=action.by, note=action.note)
    except alert_cases.AlertCaseNotFoundError:
        raise HTTPException(status_code=404, detail=t("alert_not_found", case_id=case_id)) from None
    except alert_cases.AlertCaseStateConflictError as exc:
        raise HTTPException(
            status_code=409, detail=t("alert_state_conflict", state=exc.state)
        ) from exc
    return _alert_case_payload(case)


@router.post("/opencti/outbox/replay", response_model=dict[str, Any], tags=["opencti"])
async def replay_opencti_outbox(
    run_id: int | None = None,
    limit: int = _DLQ_LIMIT_QUERY,
) -> dict[str, Any]:
    """Move dead-letter OpenCTI bundles back to pending and drain the due ones now."""
    if not settings.opencti_enabled:
        raise HTTPException(status_code=409, detail=t("opencti_sink_disabled"))
    replayed = await replay_opencti_dead_letters(run_id=run_id, limit=limit)
    processed = await drain_opencti_outbox(limit=limit)
    return {"status": "replayed", **replayed, "processed_now": processed}


@router.post("/bundles", response_model=dict[str, Any], tags=["bundles"])
async def ingest_external_bundle(
    request: Request,
    work_name: str = Query(default="external-stix"),
) -> dict[str, Any]:
    """Intake a STIX 2.1 bundle from an external producer into OpenCTI (ADR-011).

    The body is the bundle JSON. It is validated against the pinned contract
    schema (``orchestrator/contracts``), parsed with ``pycti`` imported first (so
    the OpenCTI SCOs ``bank-account``/``text`` resolve), and handed to
    ``OpenCTISink``, which owns retries and rejection reporting.

    A failed ingest is not queued: the producer keeps its bundle and gets the
    reason back, 502 when the sink reports a failed ingest (objects rejected,
    client not configured) and 503 when OpenCTI could not be reached once the
    sink's retries were spent, so it can retry.
    """
    if not settings.opencti_enabled:
        raise HTTPException(status_code=409, detail=t("opencti_sink_disabled"))

    try:
        data = await request.json()
    except ValueError as exc:  # json.JSONDecodeError and UnicodeDecodeError
        raise HTTPException(status_code=400, detail=t("bundle.invalid_json", error=exc)) from exc

    try:
        jsonschema.validate(instance=data, schema=load_schema())
    except jsonschema.ValidationError as exc:
        raise HTTPException(
            status_code=422, detail=t("bundle.contract_violation", error=exc.message)
        ) from exc

    import pycti  # noqa: F401  (registers the OpenCTI SCOs before stix2.parse)
    import stix2

    try:
        bundle = stix2.parse(data, allow_custom=True)
    except Exception as exc:  # noqa: BLE001 — a malformed bundle must not 500
        raise HTTPException(status_code=422, detail=t("bundle.parse_failed", error=exc)) from exc

    try:
        await OpenCTISink().ingest_async(bundle, work_name=work_name)
    except OpenCTIIngestError as exc:
        raise HTTPException(status_code=502, detail=t("bundle.ingest_failed", error=exc)) from exc
    except Exception as exc:  # noqa: BLE001 — pycti/requests errors once retries are spent
        # The raw error can carry the OpenCTI URL; it goes to the log, not to
        # the producer.
        logger.error(
            "External bundle ingest failed: work=%s error=%s",
            work_name,
            exc,
            extra={"work": work_name, "error": str(exc)},
        )
        raise HTTPException(status_code=503, detail=t("bundle.ingest_unavailable")) from exc

    return {"status": "ingested", "work_name": work_name, "objects": len(bundle.objects)}


def _ui_dist_index() -> Path | None:
    """The built dashboard's index.html, or None when no build is installed."""
    index = UI_DIST_DIR / "index.html"
    return index if index.is_file() else None


# Directives every /console response shares: same-origin connections, images
# and fonts, no base/form/frame tricks. The script and style sources differ
# per page and are prepended below.
_CONSOLE_CSP_TAIL = (
    "connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
# The React dashboard is one bundled script and one stylesheet, both served
# from this origin under /console/assets/. Nothing inline, nothing remote: a
# string that reaches the DOM from a collector or a model cannot execute.
_UI_CSP = f"default-src 'none'; script-src 'self'; style-src 'self'; {_CONSOLE_CSP_TAIL}"
# Hardening headers every /console HTML response carries, shell or 503 alike.
_CONSOLE_HARDENING_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
_UI_SHELL_HEADERS = {**_CONSOLE_HARDENING_HEADERS, "Content-Security-Policy": _UI_CSP}


def _dashboard_missing_response(request: Request) -> HTMLResponse:
    """
    503 with build instructions when orchestrator/static/ui-dist is absent.

    A deployment without the dashboard is a deployment error, so the status
    is one a probe notices; the page itself carries no data and no script.
    It shares ``_CONSOLE_HARDENING_HEADERS`` with the shell and differs from
    it on purpose in two places: the CSP allows no script at all and styles
    only by nonce (the page has no bundle), and ``Retry-After`` tells the
    probe when to look again.
    """
    nonce = secrets.token_urlsafe(16)
    language = resolve_language(None)
    return templates.TemplateResponse(
        request=request,
        name="dashboard_missing.html",
        context={
            "language": language,
            "title": t("dashboard_missing_title", language=language),
            "body": t("dashboard_missing_body", language=language),
            "back": t("dashboard_missing_back", language=language),
            "csp_nonce": nonce,
        },
        status_code=503,
        headers={
            **_CONSOLE_HARDENING_HEADERS,
            "Content-Security-Policy": f"default-src 'none'; style-src 'nonce-{nonce}'; {_CONSOLE_CSP_TAIL}",
            "Retry-After": "60",
        },
    )


def _ui_shell_response(request: Request) -> HTMLResponse:
    """
    The React dashboard's index.html, or the 503 build notice without a build.

    Both branches carry ``_CONSOLE_HARDENING_HEADERS``; only the CSP (bundle
    vs. no script) and the 503's ``Retry-After`` differ, as documented on
    ``_dashboard_missing_response``.
    """
    index = _ui_dist_index()
    if index is None:
        return _dashboard_missing_response(request)
    return HTMLResponse(index.read_text(encoding="utf-8"), headers=_UI_SHELL_HEADERS)


@app.get("/console", response_class=HTMLResponse, include_in_schema=False)
async def operator_console(request: Request) -> HTMLResponse:
    """
    Operator dashboard shell (the React build; translations ship inside it).

    Mounted on ``app``, not ``router``: the shell carries no target or run
    data — every fetch it makes (/runs, /targets, /analytics/...) goes through
    the protected router with the key the operator types into it. Behind the
    key, a browser could never reach the page that asks for the key.
    """
    return _ui_shell_response(request)


@app.get("/console/assets/{asset_path:path}", include_in_schema=False)
async def operator_console_asset(asset_path: str) -> FileResponse:
    """
    A file of the dashboard build (hashed name, so it can be cached forever).

    Only regular files inside the build's assets directory are served; a path
    that escapes it (``..``, absolute, symlink out) is a 404, not a traversal.
    """
    assets_root = (UI_DIST_DIR / "assets").resolve()
    candidate = (assets_root / asset_path).resolve()
    if not candidate.is_relative_to(assets_root) or not candidate.is_file():
        raise HTTPException(status_code=404, detail="Not Found")
    return FileResponse(
        candidate,
        headers={
            "Cache-Control": "public, max-age=31536000, immutable",
            "X-Content-Type-Options": "nosniff",
        },
    )


# First path segments the React router owns (ui/src/App.tsx): anything under
# them is a view, whatever its spelling, because the segments that follow are
# route parameters and target ids may contain dots (``example.com``,
# ``notes.md`` are valid ids and valid ``/console/targets/{id}`` deep links).
_CLIENT_ROUTE_PREFIXES = frozenset({"targets", "runs"})

# File extensions a browser or a stale link asks for under /console outside
# those prefixes; a last segment ending in one of these is a miss, not a view.
_STATIC_FILE_SUFFIXES = frozenset(
    {
        ".js",
        ".mjs",
        ".css",
        ".map",
        ".json",
        ".jso",
        ".html",
        ".htm",
        ".ico",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".woff",
        ".woff2",
        ".ttf",
        ".txt",
        ".md",
        ".xml",
        ".webmanifest",
    }
)


# Starlette matches routes in registration order: this catch-all must stay the
# last ``/console/...`` route of the module, or it shadows whatever is added
# after it (tests/unit/test_operator_console.py checks the assets route keeps
# its own content type).
@app.get("/console/{client_path:path}", response_class=HTMLResponse, include_in_schema=False)
async def operator_console_client_route(request: Request, client_path: str) -> HTMLResponse:
    """
    Client-side routes of the dashboard (``/console/targets``, ``/console/runs/42``).

    The React router owns everything under ``/console``; a deep link or a
    reload gets the same shell and the router renders the view. Without a
    build these paths are unknown, as they were before. Outside the router's
    own prefixes, a last segment that ends in a static-file extension is a
    file name, not a view (a stale or mistyped asset link, a ``favicon.ico``
    probe): it gets a 404 so monitors and caches see the miss instead of a
    200 shell.
    """
    if _ui_dist_index() is None:
        raise HTTPException(status_code=404, detail="Not Found")
    segments = client_path.strip("/").split("/")
    if segments[0] not in _CLIENT_ROUTE_PREFIXES:
        last_segment = segments[-1].lower()
        if any(last_segment.endswith(suffix) for suffix in _STATIC_FILE_SUFFIXES):
            raise HTTPException(status_code=404, detail="Not Found")
    return _ui_shell_response(request)


@router.get("/analytics/risk-trends", response_model=list[dict[str, Any]], tags=["analytics"])
async def risk_trends() -> list[dict[str, Any]]:
    """Return per-target risk/new-observable trends for the last 20 runs each."""
    risk_rank = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    rank_to_risk = {v: k for k, v in risk_rank.items()}
    history_limit = 20

    runs_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    findings_by_run_id: dict[int, FindingRecord] = {}
    async with get_session() as session:
        ranked_runs = sa_select(
            col(Run.id).label("id"),
            col(Run.target_id).label("target_id"),
            col(Run.status).label("status"),
            col(Run.started_at).label("started_at"),
            col(Run.new_observables).label("new_observables"),
            func.row_number()
            .over(partition_by=Run.target_id, order_by=col(Run.started_at).desc())
            .label("rank"),
        ).subquery()
        runs_result = await session.exec(  # type: ignore[call-overload]  # SQLModel overloads omit SQLAlchemy Select statements.
            sa_select(
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
                select(FindingRecord).where(col(FindingRecord.run_id).in_(run_ids))
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


async def _risk_levels_by_run(session: Any, run_ids: list[int]) -> dict[int, str]:
    """The synthesised risk level of each run that has a finding (one query)."""
    if not run_ids:
        return {}
    result = await session.exec(
        select(FindingRecord.run_id, FindingRecord.risk_level).where(
            col(FindingRecord.run_id).in_(run_ids)
        )
    )
    return {int(run_id): str(risk_level) for run_id, risk_level in result.all()}


@router.get("/runs", response_model=list[dict[str, Any]], tags=["runs"])
async def list_runs(
    target_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    """List recent runs, newest first, optionally filtered by target.

    ``limit`` and ``offset`` page through older runs; the default page is the
    100 most recent, which is what the dashboard reads.

    Each row carries ``risk_level``: the synthesised level of the run's
    finding, or ``null`` for a run without one (failed early, synthesis off or
    still running), so the history can show how the risk moved run by run.
    """
    async with get_session() as session:
        stmt = (
            select(Run)
            .order_by(col(Run.started_at).desc(), col(Run.id).desc())
            .offset(offset)
            .limit(limit)
        )
        if target_id:
            stmt = stmt.where(Run.target_id == target_id)
        result = await session.exec(stmt)
        runs = result.all()
        risk_levels = await _risk_levels_by_run(
            session, [int(run.id) for run in runs if run.id is not None]
        )
    rows = []
    for run in runs:
        data = run.model_dump()
        data["risk_level"] = risk_levels.get(int(run.id)) if run.id is not None else None
        rows.append(data)
    return rows


@router.get("/runs/{run_id}", response_model=dict[str, Any], tags=["runs"])
async def get_run(run_id: int) -> dict[str, Any]:
    """Return a run's status and counts, its risk level and its alert dispatch audit trail."""
    async with get_session() as session:
        run = await session.get(Run, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=t("run_not_found", run_id=run_id))
        result = await session.exec(select(AlertRecord).where(AlertRecord.run_id == run_id))
        alert_records = result.all()
        risk_level = (
            await session.exec(
                select(FindingRecord.risk_level).where(FindingRecord.run_id == run_id)
            )
        ).first()
    data = run.model_dump()
    data["risk_level"] = str(risk_level) if risk_level is not None else None
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
    # Read, do not check-then-read: the retention job can purge the run
    # directory between the two, and a path that is a directory is not a
    # report either. Both are a 404, not a 500.
    try:
        body = Path(run.report_path).read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        raise HTTPException(status_code=404, detail=t("report_not_found", run_id=run_id)) from None
    return PlainTextResponse(body)


@router.get("/runs/{run_id}/finding", response_model=dict[str, Any], tags=["runs"])
async def get_run_finding(run_id: int) -> dict[str, Any]:
    """Return the synthesized Finding for a completed run, or 404."""
    async with get_session() as session:
        result = await session.exec(select(FindingRecord).where(FindingRecord.run_id == run_id))
        record = result.first()
    if record is None:
        raise HTTPException(status_code=404, detail=t("finding_not_found", run_id=run_id))
    return record.to_api_dict()


@router.get("/runs/{run_id}/evidence", response_model=list[EvidenceQualification], tags=["runs"])
async def get_run_evidence(run_id: int) -> list[EvidenceQualification]:
    """Return evidence qualifications persisted for one run."""
    async with get_session() as session:
        run = await session.get(Run, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=t("run_not_found", run_id=run_id))
        rows = await load_run_qualifications(run_id, session=session)
    return rows


@router.get("/runs/{run_id}/manifest", response_model=dict[str, Any], tags=["runs"])
async def get_run_manifest(run_id: int) -> dict[str, Any]:
    """Return the signed manifest for one sealed run, or 404 if none exists."""
    async with get_session() as session:
        run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=t("run_not_found", run_id=run_id))
    if run.manifest_sha256 is None:
        raise HTTPException(status_code=404, detail=t("manifest.not_found", run_id=run_id))
    manifest_path = manifest_path_for_report(run.report_path)
    if manifest_path is None or not manifest_path.exists():
        raise HTTPException(status_code=404, detail=t("manifest.not_found", run_id=run_id))
    try:
        payload = load_manifest_file(manifest_path)
    except (OSError, TypeError, ValueError):
        raise HTTPException(
            status_code=404, detail=t("manifest.not_found", run_id=run_id)
        ) from None
    return payload


async def _run_or_404(run_id: int) -> Run:
    async with get_session() as session:
        run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=t("run_not_found", run_id=run_id))
    return run


@router.get("/runs/{run_id}/report.pdf", response_class=FileResponse, tags=["runs"])
async def get_run_report_pdf(run_id: int) -> FileResponse:
    """Serve the PDF companion of the report (written next to report.md), or 404."""
    run = await _run_or_404(run_id)
    pdf_path = Path(run.report_path).with_name("report.pdf") if run.report_path else None
    if pdf_path is None or not pdf_path.is_file():
        raise HTTPException(status_code=404, detail=t("report_pdf_not_found", run_id=run_id))
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"run-{run_id}-report.pdf",
        headers={"Cache-Control": "no-store"},
    )


_BUNDLE_NAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


@router.get("/runs/{run_id}/bundle", tags=["runs"])
async def get_run_bundle(run_id: int) -> Response:
    """The run's artefacts as one zip archive, the signed manifest included.

    The handoff artefact: whoever receives it can recompute the SHA-256 of
    each file against ``manifest.json`` and check the signature with the
    deployment's key, without access to this service. A sealed run ships
    exactly the files its manifest covers (plus the manifest), so nothing
    unsigned travels under the "signed bundle" name; an unsealed run ships
    every regular file of its directory. Symbolic links are never followed.
    """
    run = await _run_or_404(run_id)
    run_dir = Path(run.report_path).parent if run.report_path else None
    if run_dir is None or not run_dir.is_dir():
        raise HTTPException(status_code=404, detail=t("bundle.not_found", run_id=run_id))
    files = sorted(item for item in run_dir.iterdir() if item.is_file() and not item.is_symlink())
    manifest_path = run_dir / "manifest.json"
    if manifest_path in files:
        try:
            covered = set(load_manifest_file(manifest_path).get("artefacts", {}))
        except (OSError, TypeError, ValueError):
            covered = set()
        if covered:
            files = [item for item in files if item.name in covered or item == manifest_path]
    if not files:
        raise HTTPException(status_code=404, detail=t("bundle.not_found", run_id=run_id))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in files:
            archive.write(item, arcname=item.name)
    target_slug = _BUNDLE_NAME_SAFE.sub("-", run.target_id).strip("-") or "target"
    filename = f"run-{run_id}-{target_slug}.zip"
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/targets/{target_id}/chain/verify", response_model=dict[str, Any], tags=["runs"])
async def verify_target_chain_endpoint(target_id: str) -> dict[str, Any]:
    """Check the manifest chain for every sealed run of a target."""
    # Only a configured target reaches the verifier and the metric: the id is
    # a Prometheus label, and an unbounded one would let any caller create a
    # new time series per request.
    if not any(target.id == target_id for target in _load_targets()):
        raise HTTPException(status_code=404, detail=t("target_not_found", target_id=target_id))
    try:
        async with get_session() as session:
            result = await verify_target_chain(
                target_id=target_id,
                secret_key=settings.orchestrator_secret_key,
                session=session,
                previous_keys=split_keys(settings.orchestrator_secret_key_previous),
            )
        outcome = "ok" if result["ok"] else "broken"
        metrics.evidence_chain_verify_total.labels(target_id, outcome).inc()
        if result["reason"]:
            # Operator-facing text (ADR-004); `reason` stays the stable English id.
            result["message"] = t(
                f"chain.reason.{result['reason']}",
                name=result["detail"],
                run_id=result["first_broken_run_id"],
            )
        return result
    except Exception:
        metrics.evidence_chain_verify_total.labels(target_id, "error").inc()
        raise


app.include_router(router)


def main() -> None:
    """Run the API with uvicorn (container/bare-metal entry point)."""
    import uvicorn

    # log_config=None: uvicorn must not install its own handlers; lifespan()
    # configures the root logger and routes uvicorn's loggers through it.
    uvicorn.run("orchestrator.api:app", host="0.0.0.0", port=8000, reload=False, log_config=None)


if __name__ == "__main__":
    main()
