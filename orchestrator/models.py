"""
Domain models for the orchestrator.

These models define the data flowing through the pipeline:
  Target → Run → CollectorResult → stix2.Bundle → OpenCTI
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator
from sqlalchemy import Index, text
from sqlmodel import Column, DateTime, SQLModel
from sqlmodel import Field as SQLField

logger = logging.getLogger(__name__)

# ─── Enums ───────────────────────────────────────────────────────────────────


class RunStatus(StrEnum):
    """Lifecycle of a collection run.

    Persisted English identifiers (never localised — ADR-004): a run goes
    ``pending`` → ``running`` → ``success`` (all enabled collectors OK),
    ``partial`` (some collector or the OpenCTI ingest failed but produced
    findings) or ``failed`` (every collector failed).
    """

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"  # some collectors failed
    FAILED = "failed"


class CollectorName(StrEnum):
    """Registry of collector identifiers used in config, metrics and reports."""

    OPENOSINT = "openosint"
    SPIDERFOOT = "spiderfoot"
    SOCIALOSINT = "socialosint"
    AMASS = "amass"
    TAVILY = "tavily"


# ─── Collector contract ───────────────────────────────────────────────────────

COLLECTOR_RESULT_CONTRACT_VERSION = "1.0"
SUPPORTED_PLATFORMS = frozenset(
    {"twitter", "reddit", "github", "bluesky", "mastodon", "hackernews"}
)


class Observable(BaseModel):
    """A single OSINT observable before STIX conversion."""

    type: str  # e.g. "domain-name", "ipv4-addr", "url", "email-addr"
    value: str
    # Optional enrichment
    extra: dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    """Directional relationship between two observables."""

    source_value: str
    source_type: str
    target_value: str
    target_type: str
    relationship_type: str  # e.g. "resolves-to", "related-to", "belongs-to"


class EvidenceItem(BaseModel):
    """One structured web-evidence item extracted by a collector."""

    url: str
    title: str
    snippet: str
    published: str | None = None
    query: str


class CollectorResult(BaseModel):
    """
    Output of a single collector for a single target.

    This is the ONLY type that crosses the collector→normalizer boundary.
    Raw tool output must not leave the collector module.
    """

    collector: CollectorName
    target_fqdn: str
    # Version of the collector→normalizer contract for compatibility checks.
    contract_version: str = COLLECTOR_RESULT_CONTRACT_VERSION
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    observables: list[Observable] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    # Free-form notes (converted to STIX Note objects)
    notes: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    # Whether the collector ran successfully
    success: bool = True
    complete: bool = True
    error: str | None = None

    def observable_hash(self) -> str:
        """Stable SHA-256 fingerprint for deduplication between runs."""
        key = "|".join(sorted(f"{o.type}:{o.value}" for o in self.observables))
        return hashlib.sha256(key.encode()).hexdigest()


# ─── Target definition (loaded from targets.yaml) ────────────────────────────


class CollectorConfig(BaseModel):
    """Per-collector block under ``collectors:`` in targets.yaml.

    One flat schema shared by all five collectors; each reads only its own
    keys (openosint: ``investigation_type`` + budget keys, spiderfoot:
    ``modules`` + ``timeout_seconds``, socialosint: ``usernames``,
    ``platforms`` + ``timeout_seconds``, amass: ``active``, ``brute``,
    ``include``, ``exclude``, ``progress_timeout_minutes`` +
    ``timeout_seconds``, tavily: ``search_depth``, ``max_results``,
    ``include_domains``, ``exclude_domains``, ``search_terms``, ``include_answer``,
    ``max_calls_per_run`` + ``timeout_seconds``). A field must be declared
    once: a repeated name silently replaces the earlier default for every
    collector. The full field contract is documented in
    docs/configuration.md (targets.yaml).
    """

    # A misspelt key (``modules:`` as ``modlues:``) is a configuration error
    # the operator must see, not a silent fall-back to the default.
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    investigation_type: str = "domain"  # for openosint
    modules: list[str] = Field(default_factory=list)  # for spiderfoot
    timeout_seconds: int = 600  # spiderfoot: how long to wait for a whole scan

    # openosint investigation budget (see openosint.investigate.InvestigationBudget).
    # These are hard upper bounds: without them a scheduled run can fan out
    # across an unbounded number of pivots and tool calls.
    max_depth: int = 2
    max_entities: int = 40
    max_tool_calls: int = 60
    tool_timeout_seconds: int = 30  # openosint: per-tool-call timeout

    # socialosint: handles to investigate (required — no handles = collector skipped)
    usernames: list[str] = Field(default_factory=list)
    # socialosint: platforms to query; valid values:
    #   twitter, reddit, github, bluesky, mastodon, hackernews
    # Platforms without credentials are skipped with a warning (not a failure).
    platforms: list[str] = Field(
        default_factory=lambda: ["twitter", "reddit", "github", "bluesky", "hackernews"]
    )

    # amass: enumeration mode. ``active`` attempts zone transfers and
    # certificate name grabs against the target's infrastructure (touches the
    # target — keep it off unless the authorization covers active probing);
    # ``brute`` runs wordlist brute forcing after the passive searches.
    active: bool = False
    brute: bool = False
    # amass: data source names to restrict the run to / to leave out
    # (names as listed by the engine, e.g. "crt.sh", "HackerTarget").
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)
    # amass: minutes without new findings before the enumeration stops
    # (``oam_enum -timeout``). ``timeout_seconds`` remains the hard wall-clock
    # bound for the whole collector run.
    progress_timeout_minutes: int = Field(default=10, ge=1)

    # tavily: request limits. ``timeout_seconds`` (declared above) is the
    # wall-clock budget of the whole collector run. Both caps are also clamped
    # by the global TAVILY_MAX_RESULTS / TAVILY_MAX_CALLS_PER_RUN settings.
    max_results: int = Field(default=5, ge=1, le=20)
    search_depth: str = "basic"
    include_domains: list[str] = Field(default_factory=list)
    exclude_domains: list[str] = Field(default_factory=list)
    search_terms: list[Annotated[str, Field(min_length=1, max_length=80)]] = Field(
        default_factory=list, max_length=5
    )
    include_answer: bool = False
    max_calls_per_run: int = Field(default=3, ge=1, le=20)


def _socialosint_default_timeout() -> int:
    """Return the global SocialOSINT timeout from settings (lazy import to avoid circulars)."""
    from orchestrator.config import settings  # noqa: PLC0415

    return settings.socialosint_timeout_seconds


def _amass_default_timeout() -> int:
    """Return the global Amass timeout from settings (lazy import to avoid circulars)."""
    from orchestrator.config import settings  # noqa: PLC0415

    return settings.amass_timeout_seconds


def _tavily_default_timeout() -> int:
    """Return the global Tavily timeout from settings (lazy import to avoid circulars)."""
    from orchestrator.config import settings  # noqa: PLC0415

    return settings.tavily_timeout_seconds


# Blocks whose timeout default comes from a global setting; the tuple of the
# CollectorSet validator below is derived from these keys.
_GLOBAL_TIMEOUT_DEFAULTS: dict[str, Callable[[], int]] = {
    "socialosint": _socialosint_default_timeout,
    "amass": _amass_default_timeout,
    "tavily": _tavily_default_timeout,
}


class CollectorSet(BaseModel):
    """The collector blocks of a target; optional collectors are opt-in.

    Defaults: openosint and spiderfoot enabled, socialosint, amass and tavily
    disabled with their timeout taken from the corresponding global settings.
    """

    model_config = ConfigDict(extra="forbid")

    openosint: CollectorConfig = Field(default_factory=CollectorConfig)
    spiderfoot: CollectorConfig = Field(default_factory=CollectorConfig)
    socialosint: CollectorConfig = Field(
        default_factory=lambda: CollectorConfig(
            enabled=False,
            timeout_seconds=_socialosint_default_timeout(),
        )
    )
    amass: CollectorConfig = Field(
        default_factory=lambda: CollectorConfig(
            enabled=False,
            timeout_seconds=_amass_default_timeout(),
        )
    )
    tavily: CollectorConfig = Field(
        default_factory=lambda: CollectorConfig(
            enabled=False,
            timeout_seconds=_tavily_default_timeout(),
        )
    )

    @field_validator(*_GLOBAL_TIMEOUT_DEFAULTS)
    @classmethod
    def _global_timeout_default(cls, cfg: CollectorConfig, info: ValidationInfo) -> CollectorConfig:
        # A partial block such as ``amass: {enabled: true}`` bypasses the
        # default factory above and would inherit the generic
        # ``timeout_seconds`` (600 s); apply the collector's global default
        # unless the operator set a value explicitly.
        if "timeout_seconds" not in cfg.model_fields_set:
            # Pydantic always supplies a field name to this field validator.
            assert info.field_name is not None
            default = _GLOBAL_TIMEOUT_DEFAULTS[info.field_name]
            return cfg.model_copy(update={"timeout_seconds": default()})
        return cfg

    @field_validator("socialosint")
    @classmethod
    def _validate_socialosint_platforms(cls, cfg: CollectorConfig) -> CollectorConfig:
        normalized = [platform.lower().strip() for platform in cfg.platforms if platform.strip()]
        unknown = sorted(
            {platform for platform in normalized if platform not in SUPPORTED_PLATFORMS}
        )
        if unknown:
            supported = ", ".join(sorted(SUPPORTED_PLATFORMS))
            unknown_list = ", ".join(unknown)
            raise ValueError(
                "collectors.socialosint.platforms contains unsupported value(s): "
                f"{unknown_list}. Supported platforms: {supported}."
            )
        return cfg.model_copy(update={"platforms": normalized})


class ScheduleConfig(BaseModel):
    """Cron schedule of a target (five fields, UTC) plus misfire grace time.

    A run missed by more than ``misfire_grace_time_seconds`` is skipped
    rather than fired late.
    """

    model_config = ConfigDict(extra="forbid")

    cron: str = "0 8 * * *"
    # APScheduler accepts only a positive grace time; 0 would make add_job
    # raise and abort the registration of every target after this one.
    misfire_grace_time_seconds: int = Field(default=3600, ge=1)


class AlertsConfig(BaseModel):
    """Per-target alert dispatch configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    # Trigger an alert whenever there are new observables in a run.
    on_new_observables: bool = True
    # Minimum finding risk level that triggers an alert even without new
    # observables. Stable English identifiers only (never localised here).
    # Fires when risk_level is at this level or above (high → critical).
    min_risk_level: str = "high"  # low | medium | high | critical | unknown
    # Also open an alert case (and notify the channels) when the run failed:
    # a target that silently stops being collected is itself a finding for
    # the operator. Off by default so a flaky collector does not page.
    on_run_failure: bool = False
    # When False, the alert payload contains only counts and types — no
    # observable values — to reduce data sent outside the process.
    include_values: bool = True


# Target.id names files and directories under report_dir
# (daily_reports/<date>/<id>/run-<run_id>/report.md), so it must be a plain slug: no path
# separators, no whitespace, nothing a shell or a renderer would interpret.
_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class Target(BaseModel):
    """One monitored entity parsed from targets.yaml.

    ``authorization`` and ``purpose`` are mandatory by design: they are
    written into every run report as the audit trail for why the collection
    happened (see the Authorised-use policy in README / SECURITY.md).
    """

    # Unknown keys are rejected so that ``enabeld: false`` or ``schedual:``
    # make the target invalid (and reported) instead of running it with the
    # defaults. The nested blocks forbid extras for the same reason.
    model_config = ConfigDict(extra="forbid")

    id: str
    enabled: bool = True
    fqdn: str
    authorization: str
    purpose: str
    collectors: CollectorSet = Field(default_factory=CollectorSet)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    llm: Literal["local", "anthropic", "openai", "nebius"] = "local"
    # Override the global ORCHESTRATOR_LANGUAGE for this target's reports and
    # synthesis. None = use the global setting.
    language: str | None = None
    report_dir: str = "daily_reports"
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        if not _TARGET_ID_RE.match(value):
            raise ValueError(
                "target id must be 1-64 characters of letters, digits, '.', '_' or '-', "
                "starting with a letter or digit: it names the report directory"
            )
        return value


# ─── Run tracking (persisted to SQLite) ──────────────────────────────────────


class Run(SQLModel, table=True):
    """One pipeline execution for a target — the backbone of the audit trail.

    Rows are created ``pending`` before execution (which also enforces the
    one-active-run-per-target guard), then updated in place with counts,
    error text and the report path. Purged by the retention job except for
    ``seen_observables``, which is never touched.
    """

    __tablename__ = "runs"
    # One active run per target, enforced by the database: the in-process lock
    # of run_control.create_pending_run serialises the API and the scheduler;
    # the index also covers a second process (the showcase command) racing
    # them. The condition names the stored enum names.
    __table_args__ = (
        Index(
            "ux_runs_one_active_per_target",
            "target_id",
            unique=True,
            sqlite_where=text("status IN ('PENDING', 'RUNNING')"),
            postgresql_where=text("status IN ('PENDING', 'RUNNING')"),
        ),
    )

    id: int | None = SQLField(default=None, primary_key=True)
    target_id: str = SQLField(index=True)
    started_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )
    finished_at: datetime | None = SQLField(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    status: RunStatus = SQLField(default=RunStatus.PENDING)
    collectors_run: str = ""  # comma-separated list
    new_observables: int = 0  # count of net-new observables vs prior run
    error: str | None = None
    report_path: str | None = None
    manifest_sha256: str | None = SQLField(default=None, index=True, nullable=True)
    collection_status: str = "not_recorded"
    qualification_status: str = "not_recorded"
    synthesis_status: str = "not_recorded"
    report_status: str = "not_recorded"
    integrity_status: str = "not_recorded"
    evidence_collected: int | None = None
    evidence_qualified: int | None = None


class SeenObservable(SQLModel, table=True):
    """
    SHA-256 of observable ID (STIX deterministic ID) already ingested.
    Used to detect new findings between runs.
    """

    __tablename__ = "seen_observables"
    # One row per (target, observable). The pipeline and the outbox drain both
    # insert here; the database, not a SELECT-then-INSERT, keeps it unique.
    __table_args__ = (
        Index("ix_seen_observables_target_stix", "target_id", "stix_id", unique=True),
    )

    id: int | None = SQLField(default=None, primary_key=True)
    target_id: str = SQLField(index=True)
    stix_id: str = SQLField(index=True)  # e.g. "domain-name--<uuid5>"
    first_seen_run_id: int


class RunObservable(SQLModel, table=True):
    """Observable seen in a specific run, with delta flag for daily reporting."""

    __tablename__ = "run_observables"

    id: int | None = SQLField(default=None, primary_key=True)
    run_id: int = SQLField(index=True)
    stix_id: str = SQLField(index=True)
    stix_type: str = SQLField(index=True)
    value: str
    is_new: bool = False
    # True only when the bundle containing this observable was successfully
    # ingested into OpenCTI. If False, the next run will re-mark it as new
    # (see Issue #8).
    ingested: bool = False


# ─── Synthesizer output ───────────────────────────────────────────────────────


class Finding(BaseModel):
    """A single synthesized finding for a target."""

    target_id: str
    run_id: int
    summary: str
    new_since_last_run: list[str] = Field(default_factory=list)
    # Stable English identifier, NOT display text: it is persisted, compared
    # and filtered on. Localise it at the point of rendering, never here —
    # translating the stored value would silently break every comparison.
    risk_level: str = "unknown"  # low | medium | high | critical | unknown
    risk_justification: str = ""
    suggested_pivots: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ─── Synthesizer persistence ──────────────────────────────────────────────────


class FindingRecord(SQLModel, table=True):
    """
    Persisted record of a synthesized Finding for auditing and the API.

    run_id is unique: one finding per run.  list fields are stored as
    JSON-encoded strings because SQLite has no native array type.
    """

    __tablename__ = "findings"

    id: int | None = SQLField(default=None, primary_key=True)
    run_id: int = SQLField(unique=True, index=True)
    target_id: str = SQLField(index=True)
    summary: str = ""
    new_since_last_run: str = "[]"  # JSON-encoded list[str]
    risk_level: str = "unknown"
    risk_justification: str = ""
    suggested_pivots: str = "[]"  # JSON-encoded list[str]
    generated_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )
    provider: str = ""
    model: str = ""
    duration_ms: int = 0
    raw_response: str = ""

    @staticmethod
    def _decode_string_list(value: str | None, *, run_id: int, field: str) -> list[str]:
        def _log_invalid() -> None:
            logger.warning(
                "FindingRecord field could not be decoded as list[str]; using empty list",
                extra={"run_id": run_id, "field": field},
            )

        if value is None:
            return []
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            _log_invalid()
            return []
        if not isinstance(decoded, list) or not all(isinstance(item, str) for item in decoded):
            _log_invalid()
            return []
        return decoded

    def to_api_dict(self) -> dict[str, Any]:
        payload = self.model_dump()
        payload["new_since_last_run"] = self._decode_string_list(
            self.new_since_last_run,
            run_id=self.run_id,
            field="new_since_last_run",
        )
        payload["suggested_pivots"] = self._decode_string_list(
            self.suggested_pivots,
            run_id=self.run_id,
            field="suggested_pivots",
        )
        return payload


class EvidenceCategory(StrEnum):
    ADVERSE_MEDIA = "adverse_media"
    SANCTIONS = "sanctions"
    LITIGATION = "litigation"
    REGULATORY_ACTION = "regulatory_action"
    CORPORATE_PROFILE = "corporate_profile"
    UNRELATED = "unrelated"


class EvidenceRelevance(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceQualification(SQLModel, table=True):
    """Persisted output of the evidence-qualification LLM step."""

    __tablename__ = "evidence_qualifications"

    id: int | None = SQLField(default=None, primary_key=True)
    run_id: int = SQLField(index=True)
    target_id: str = SQLField(index=True)
    url: str = ""
    title: str = ""
    category: str = EvidenceCategory.UNRELATED.value
    relevance: str = EvidenceRelevance.LOW.value
    confidence: float = 0.0
    rationale: str = ""
    provider: str = ""
    model: str = ""
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


# ─── Alert audit ──────────────────────────────────────────────────────────────


class AlertStatus(StrEnum):
    """Outcome of one dispatch attempt recorded in the ``alerts`` audit table."""

    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


class AlertRecord(SQLModel, table=True):
    """Audit trail for every alert dispatch attempt."""

    __tablename__ = "alerts"

    id: int | None = SQLField(default=None, primary_key=True)
    run_id: int = SQLField(index=True)
    channel: str  # "webhook" | "email"
    status: AlertStatus = AlertStatus.SKIPPED
    error: str | None = None
    sent_at: datetime | None = SQLField(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )


class AlertCaseState(StrEnum):
    """Triage state of an alert case: what an operator did about it."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class AlertCaseReason(StrEnum):
    """Which rule of the target's ``alerts`` block opened the case."""

    NEW_OBSERVABLES = "new_observables"
    RISK_LEVEL = "risk_level"
    RUN_FAILURE = "run_failure"


class AlertCase(SQLModel, table=True):
    """One triage item per run that met an alert rule.

    ``alerts`` (AlertRecord) is the delivery audit, one row per channel per
    attempt: with no channel configured a run that met a rule leaves nothing
    there. The case is the thing an operator acknowledges and resolves, so it
    is opened before any channel is tried and exists without one.
    ``acknowledged_by`` / ``resolved_by`` are free text: there are no users
    (ADR-005).
    """

    __tablename__ = "alert_cases"

    id: int | None = SQLField(default=None, primary_key=True)
    run_id: int = SQLField(unique=True, index=True)
    target_id: str = SQLField(index=True)
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    run_status: str
    risk_level: str = "unknown"
    new_observable_count: int = 0
    reason: str = AlertCaseReason.NEW_OBSERVABLES.value
    state: str = SQLField(default=AlertCaseState.OPEN.value, index=True)
    acknowledged_at: datetime | None = SQLField(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    acknowledged_by: str | None = None
    resolved_at: datetime | None = SQLField(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    resolved_by: str | None = None
    note: str | None = None


class AlertDeliveryStatus(StrEnum):
    """Lifecycle of a queued alert message: retry until sent or dead-letter."""

    PENDING = "pending"
    # Claimed by a drain that is sending it right now. A row left here by a
    # crash is returned to PENDING at startup (requeue_interrupted_deliveries).
    IN_PROGRESS = "in_progress"
    SENT = "sent"
    DEAD_LETTER = "dead_letter"


class AlertDelivery(SQLModel, table=True):
    """Persistent retry queue for alert delivery attempts."""

    __tablename__ = "alert_deliveries"

    id: int | None = SQLField(default=None, primary_key=True)
    run_id: int = SQLField(index=True)
    target_id: str = SQLField(index=True)
    channel: str  # "webhook" | "email"
    language: str | None = None
    payload_json: str  # AlertEvent.model_dump_json() payload
    status: AlertDeliveryStatus = AlertDeliveryStatus.PENDING
    # Total send attempts made for this message, including the first
    # synchronous attempt in _dispatch_alerts.
    attempts: int = 1
    # Class default only — rows are created with settings.alert_retry_max_attempts
    # (ALERT_RETRY_MAX_ATTEMPTS, default 4).
    max_attempts: int = 3
    next_attempt_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )
    last_error: str | None = None
    sent_at: datetime | None = SQLField(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )
    updated_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )


class OpenCTIOutboxStatus(StrEnum):
    """Lifecycle of a queued STIX bundle awaiting OpenCTI ingestion."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"  # see AlertDeliveryStatus.IN_PROGRESS
    SENT = "sent"
    DEAD_LETTER = "dead_letter"


class OpenCTIOutbox(SQLModel, table=True):
    """Persistent queue for STIX bundles pending OpenCTI ingestion."""

    __tablename__ = "opencti_outbox"

    id: int | None = SQLField(default=None, primary_key=True)
    run_id: int = SQLField(index=True)
    target_id: str = SQLField(index=True)
    work_name: str
    # The serialised STIX bundle while the row is PENDING/IN_PROGRESS/DEAD_LETTER;
    # cleared once SENT so SQLite does not become a second STIX store (ADR-003).
    bundle_json: str | None = None
    status: OpenCTIOutboxStatus = OpenCTIOutboxStatus.PENDING
    attempts: int = 1
    # Class default only — rows are created with settings.opencti_outbox_max_attempts
    # (OPENCTI_OUTBOX_MAX_ATTEMPTS, default 6).
    max_attempts: int = 4
    next_retry_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )
    last_error: str | None = None
    sent_at: datetime | None = SQLField(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True),
    )
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )
    updated_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True)),
    )


class UserAccount(SQLModel, table=True):
    """Personal identity; password digests are never returned by API serializers."""

    __tablename__ = "user_accounts"
    id: int | None = SQLField(default=None, primary_key=True)
    username: str = SQLField(unique=True, index=True)
    display_name: str
    role: str = "accountant"
    password_hash: str
    active: bool = True
    failed_logins: int = 0
    locked_until: datetime | None = SQLField(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class UserSession(SQLModel, table=True):
    __tablename__ = "user_sessions"
    id: str = SQLField(primary_key=True)
    user_id: int = SQLField(index=True)
    expires_at: datetime = SQLField(sa_column=Column(DateTime(timezone=True), nullable=False))


class Dossier(SQLModel, table=True):
    """A professional review, independent of collector configuration."""

    __tablename__ = "dossiers"
    id: int | None = SQLField(default=None, primary_key=True)
    title: str
    entity_name: str
    entity_type: str
    identifier: str = ""
    country: str = ""
    purpose: str
    owner_id: int
    state: str = "draft"
    revision: int = 1
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class DossierRun(SQLModel, table=True):
    __tablename__ = "dossier_runs"
    __table_args__ = (Index("ux_dossier_run", "dossier_id", "run_id", unique=True),)
    id: int | None = SQLField(default=None, primary_key=True)
    dossier_id: int = SQLField(index=True)
    run_id: int


class EvidenceReview(SQLModel, table=True):
    __tablename__ = "evidence_reviews"
    __table_args__ = (Index("ux_dossier_evidence", "dossier_id", "evidence_id", unique=True),)
    id: int | None = SQLField(default=None, primary_key=True)
    dossier_id: int = SQLField(index=True)
    evidence_id: int
    decision: str
    reason: str
    actor_id: int


class DossierEvent(SQLModel, table=True):
    """Append-only application audit: no update/delete endpoints are provided."""

    __tablename__ = "dossier_events"
    id: int | None = SQLField(default=None, primary_key=True)
    dossier_id: int = SQLField(index=True)
    actor_id: int
    actor_name: str
    action: str
    details_json: str
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )


class DossierReport(SQLModel, table=True):
    """Immutable version: freezes sources, decisions and attribution at approval."""

    __tablename__ = "dossier_reports"
    __table_args__ = (Index("ux_dossier_version", "dossier_id", "version", unique=True),)
    id: int | None = SQLField(default=None, primary_key=True)
    dossier_id: int = SQLField(index=True)
    version: int
    snapshot_json: str
    markdown: str
    pdf: bytes
    signature: str
    created_at: datetime = SQLField(
        default_factory=lambda: datetime.now(UTC),
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
