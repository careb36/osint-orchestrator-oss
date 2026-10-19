"""
Prometheus metrics (Phase 5).

Everything is registered on the default prometheus_client registry so the
process and platform collectors (CPU, RSS, open fds, Python version) come for
free. GET /metrics in orchestrator.api serves it.

Label cardinality is bounded on purpose: target ids come from targets.yaml
(a handful), HTTP paths use the *route template* (`/runs/{run_id}`, never the
resolved path), and statuses are closed enums. Do not add a label whose
values are unbounded (observable values, run ids, error strings).

Naming follows the Prometheus conventions: `_total` for counters, base unit
seconds for durations, one `_info` gauge for build metadata.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
)

PREFIX = "osint_orchestrator"

# ─── Build info ───────────────────────────────────────────────────────────────

build_info = Info(f"{PREFIX}_build", "Orchestrator build metadata")

# ─── HTTP ─────────────────────────────────────────────────────────────────────

http_requests_total = Counter(
    f"{PREFIX}_http_requests_total",
    "HTTP requests handled by the API",
    ["method", "path", "status"],
)
http_request_duration_seconds = Histogram(
    f"{PREFIX}_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# ─── Pipeline ─────────────────────────────────────────────────────────────────

runs_total = Counter(
    f"{PREFIX}_runs_total",
    "Completed collection runs by final status",
    ["target_id", "status"],
)
runs_in_progress = Gauge(
    f"{PREFIX}_runs_in_progress",
    "Collection runs currently executing",
    ["target_id"],
)
run_duration_seconds = Histogram(
    f"{PREFIX}_run_duration_seconds",
    "Wall-clock duration of a full pipeline run (collect → alert)",
    ["target_id"],
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800, 3600),
)
collector_runs_total = Counter(
    f"{PREFIX}_collector_runs_total",
    "Collector executions by outcome (success | failure | error)",
    ["collector", "target_id", "outcome"],
)
collector_duration_seconds = Histogram(
    f"{PREFIX}_collector_duration_seconds",
    "Duration of one collector execution",
    ["collector"],
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1200),
)
run_observables = Gauge(
    f"{PREFIX}_run_observables",
    "Observables in the most recent run of a target (kind = total | new)",
    ["target_id", "kind"],
)
new_observables_total = Counter(
    f"{PREFIX}_new_observables_total",
    "Net-new, successfully ingested observables (the alert/delta definition)",
    ["target_id"],
)
target_last_success_timestamp_seconds = Gauge(
    f"{PREFIX}_target_last_success_timestamp_seconds",
    "Unix timestamp of the last successful run per target",
    ["target_id"],
)
opencti_ingest_total = Counter(
    f"{PREFIX}_opencti_ingest_total",
    "STIX bundles pushed to OpenCTI by outcome (success | failure)",
    ["target_id", "outcome"],
)
opencti_ingest_retries_total = Counter(
    f"{PREFIX}_opencti_ingest_retries_total",
    "Retries of an OpenCTI ingest after a transient error (pycti's own per-object retries excluded)",
    ["target_id"],
)
opencti_outbox_pending = Gauge(
    f"{PREFIX}_opencti_outbox_pending",
    "Pending OpenCTI outbox bundles waiting for retry",
)
opencti_outbox_oldest_age_seconds = Gauge(
    f"{PREFIX}_opencti_outbox_oldest_age_seconds",
    "Age in seconds of the oldest pending OpenCTI outbox bundle",
)
opencti_outbox_deliveries_total = Counter(
    f"{PREFIX}_opencti_outbox_deliveries_total",
    "OpenCTI outbox processing outcomes (sent | failed | dead_letter)",
    ["outcome"],
)
opencti_outbox_retries_total = Counter(
    f"{PREFIX}_opencti_outbox_retries_total",
    "OpenCTI outbox retry attempts",
    ["target_id"],
)
opencti_outbox_dead_letter = Gauge(
    f"{PREFIX}_opencti_outbox_dead_letter",
    "OpenCTI outbox bundles parked in the dead-letter queue (need operator action)",
)
alert_deliveries_pending = Gauge(
    f"{PREFIX}_alert_deliveries_pending",
    "Alert deliveries waiting for a retry",
)
alert_deliveries_dead_letter = Gauge(
    f"{PREFIX}_alert_deliveries_dead_letter",
    "Alert deliveries parked in the dead-letter queue (need operator action)",
)
synthesis_total = Counter(
    f"{PREFIX}_synthesis_total",
    "LLM synthesis attempts by status (ok | skipped | failed)",
    ["target_id", "status"],
)
llm_requests_total = Counter(
    f"{PREFIX}_llm_requests_total",
    "LLM API requests by provider, model and status",
    ["provider", "model", "status"],
)
llm_tokens_total = Counter(
    f"{PREFIX}_llm_tokens_total",
    "LLM token usage by provider, model and direction (input | output)",
    ["provider", "model", "direction"],
)
llm_model_available = Gauge(
    f"{PREFIX}_llm_model_available",
    "Startup preflight: whether the configured LLM model is served by the provider (1=yes, 0=no)",
    ["provider", "model", "route"],
)
alerts_total = Counter(
    f"{PREFIX}_alerts_total",
    "Alert lifecycle events by channel and status (sent | failed | retried | dlq)",
    ["channel", "status"],
)
alert_cases = Gauge(
    f"{PREFIX}_alert_cases",
    "Alert cases waiting for an operator, by triage state (open | acknowledged)",
    ["state"],
)
alert_case_time_to_acknowledge_seconds = Histogram(
    f"{PREFIX}_alert_case_time_to_acknowledge_seconds",
    "Seconds from an alert case being opened to its acknowledgement (MTTA/MTTR source)",
    buckets=(60, 300, 900, 1800, 3600, 4 * 3600, 12 * 3600, 24 * 3600, 3 * 24 * 3600),
)
evidence_chain_verify_total = Counter(
    f"{PREFIX}_evidence_chain_verify_total",
    "Evidence chain verification outcomes per target (ok | broken | error)",
    ["target_id", "outcome"],
)
evidence_qualified_total = Counter(
    f"{PREFIX}_evidence_qualified_total",
    "Qualified evidence rows by target and category",
    ["target_id", "category"],
)

# ─── Scheduler ────────────────────────────────────────────────────────────────

scheduled_jobs = Gauge(
    f"{PREFIX}_scheduled_jobs",
    "Target cron jobs currently registered in the scheduler (worker jobs excluded)",
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


def set_build_info(version: str) -> None:
    """Publish the running version as the build_info info-metric."""
    build_info.info({"version": version})


def render() -> tuple[bytes, str]:
    """Exposition payload and its content type for GET /metrics."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def sample(name: str, labels: dict[str, str] | None = None) -> float | None:
    """Read one sample value (tests and debugging; not used on the hot path)."""
    return REGISTRY.get_sample_value(name, labels or {})
