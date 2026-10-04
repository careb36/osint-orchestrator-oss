"""
Configuration — loaded from environment variables / .env file.

All settings are documented in .env.example.
"""

from __future__ import annotations

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """The environment contract of the application (single source of truth).

    Every field maps 1:1 to an ``UPPER_SNAKE`` environment variable (or
    ``.env`` entry) and must be documented in ``.env.example`` — the
    docs-quality CI gate enforces that. Unknown variables are ignored
    (``extra="ignore"``). Defaults target a bare-metal run; the compose
    stack overrides them with container-network values via ``.env``.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # OpenCTI
    opencti_url: str = "http://localhost:8080"
    opencti_admin_token: str = ""
    opencti_ssl_verify: bool = True  # Set to False only for local/dev deployments
    # Retry policy of the OpenCTI sink. Only transient errors are retried
    # (connection refused, timeouts, 429/5xx, a platform lock); an invalid
    # token or a malformed bundle fails on the first attempt. Waits are
    # 2, 4, 8 s ... with ±25 % jitter, capped at 30 s each.
    opencti_ingest_retries: int = 3
    opencti_ingest_backoff_seconds: float = 2.0
    # Persistent OpenCTI outbox worker and retry policy.
    opencti_outbox_cron: str = "*/5 * * * *"  # UTC cron schedule for outbox drain
    opencti_outbox_max_attempts: int = 6  # total attempts, including first ingest
    opencti_outbox_base_delay_seconds: float = 60.0
    opencti_outbox_jitter_ratio: float = 0.25

    # SpiderFoot
    spiderfoot_url: str = "http://localhost:5001"
    spiderfoot_modules: str = "sfp_dns,sfp_whois,sfp_ssl"
    spiderfoot_timeout_seconds: int = 600

    # Orchestrator
    # Language for operator-facing text (reports, LLM synthesis, API error
    # details). Per-target override: `language` in targets.yaml.
    # See docs/adr/ADR-004-language-policy.md.
    #
    # Named with the orchestrator_ prefix like its siblings, which is what
    # binds it to ORCHESTRATOR_LANGUAGE. A bare `language` field would bind to
    # LANGUAGE — a standard GNU gettext variable set on most Linux hosts — and
    # the report language would silently follow the host locale.
    orchestrator_language: str = "es"
    orchestrator_secret_key: str = "insecure-dev-key"
    orchestrator_database_url: str = "sqlite+aiosqlite:///./orchestrator.db"
    targets_file: str = "targets.yaml"

    # LLM
    # ollama | anthropic | openai | none. "none" switches synthesis off for
    # every target, including those with `llm: local` — an explicit off is
    # the operator's decision, not something a per-target field re-enables.
    llm_provider: str = "ollama"
    llm_model: str = "llama3.2"  # model for the cloud providers (anthropic | openai)
    # Model for Ollama. Separate from llm_model on purpose: a target with
    # `llm: local` always uses Ollama, and under a cloud global config it was
    # sending the cloud model name (e.g. claude-sonnet-4-5) to Ollama → 404.
    ollama_model: str = "llama3.2"
    llm_base_url: str = "http://localhost:11434"
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    # base_url for the openai-compat provider (empty = default OpenAI API)
    openai_base_url: str = ""

    # Synthesizer
    llm_timeout_seconds: float = 120.0
    # Upper bound on the model's reply. 2048 tokens is ample for the JSON
    # finding; raise it only if summaries come back truncated. The SDK clients
    # make at most one retry of their own (max_retries=1): a hung provider
    # must not hold a run for 3 × LLM_TIMEOUT_SECONDS.
    llm_max_tokens: int = 2048
    llm_max_observables_in_prompt: int = 200
    synthesis_history_runs: int = 5
    # Set to True to enrich synthesis with OpenCTI context; fails silently if
    # OpenCTI is unavailable.  Off by default so synthesis works standalone.
    synthesis_opencti_context: bool = False

    # Optional enrichment keys (passed to openosint via env)
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""

    # ─── SocialOSINT collector (Phase 4b) ────────────────────────────────────
    # URL of the running OWASP SocialOSINT web service (docker-compose profile
    # "socialosint"). The collector returns success=False if unreachable.
    socialosint_url: str = "http://socialosint:8000"
    # Seconds to wait for the whole analysis job (LLM call included).
    socialosint_timeout_seconds: int = 300

    # ─── Amass collector (opt-in) ────────────────────────────────────────────
    # OWASP Amass v5 runs as an engine sidecar (docker-compose profile "amass").
    # The orchestrator drives it with the CLI clients shipped in the image:
    # oam_enum submits the enumeration to the engine, oam_subs reads the
    # discovered names (and their IPs) back from the shared asset database.
    amass_engine_url: str = "http://amass:4000"
    # Directory shared with the engine container (its /.config/amass): the
    # engine writes asset.db there and oam_subs reads it from this path.
    amass_data_dir: str = "/app/amass/data"
    # CLI binaries (copied from the upstream image in the Dockerfile). Override
    # with absolute paths when running the orchestrator outside Docker.
    amass_enum_bin: str = "oam_enum"
    amass_subs_bin: str = "oam_subs"
    # Wall-clock bound for a full Amass run (enum + subs), in seconds. Default
    # for collectors.amass.timeout_seconds in targets.yaml.
    amass_timeout_seconds: int = 1800

    # ─── Tavily collector (opt-in) ───────────────────────────────────────────
    # Tavily search API for web research on authorised targets. Disabled by
    # default: the collector is only enabled when a target opts in.
    tavily_api_key: str = ""
    tavily_search_depth: str = "basic"  # basic | advanced
    # Global ceilings for the per-target ``max_results`` / ``max_calls_per_run``.
    tavily_max_results: int = 5
    tavily_max_calls_per_run: int = 3
    # Default wall-clock budget (seconds) of a whole Tavily run per target,
    # retries included; targets.yaml ``timeout_seconds`` overrides it.
    tavily_timeout_seconds: int = 120
    # Comma-separated domain lists, like ALERT_EMAIL_TO (pydantic-settings would
    # otherwise require JSON for a list field and refuse the documented values).
    tavily_include_domains: str = ""
    tavily_exclude_domains: str = ""

    # ─── Retention ───────────────────────────────────────────────────────────
    # Days to keep run rows and daily_reports directories (0 = disabled).
    orchestrator_retention_days: int = 90
    # UTC cron expression for the nightly purge job.
    orchestrator_retention_cron: str = "30 3 * * *"

    # ─── Alerts (Phase 4a) ────────────────────────────────────────────────────
    # Webhook channel
    alert_webhook_url: str = ""
    alert_webhook_secret: str = ""  # HMAC-SHA256 signing key
    alert_timeout_seconds: int = 10
    # Email channel (SMTP)
    alert_smtp_host: str = ""
    alert_smtp_port: int = 587
    alert_smtp_user: str = ""
    alert_smtp_password: str = ""
    alert_smtp_from: str = ""
    alert_email_to: str = ""  # comma-separated list
    alert_smtp_starttls: bool = True
    # Persistent retry queue for failed alert deliveries.
    alert_retry_cron: str = "*/5 * * * *"  # UTC cron schedule for retry worker
    alert_retry_max_attempts: int = 4  # total attempts, including the first send
    alert_retry_base_delay_seconds: float = 30.0
    alert_retry_jitter_ratio: float = 0.25

    # ─── API auth, logging, metrics (Phase 5) ────────────────────────────────
    # Comma-separated list of accepted API keys (more than one so a key can be
    # rotated without a cut-over window). Empty = authentication DISABLED:
    # every endpoint is open and a warning is logged once at startup. /health
    # and /metrics never require a key (see orchestrator/auth.py).
    orchestrator_api_key: str = ""
    # Log verbosity and shape. `json` emits one JSON object per line for log
    # shippers (Loki, ELK, CloudWatch); `text` is the human-readable default.
    orchestrator_log_level: str = "INFO"
    orchestrator_log_format: str = "text"  # text | json
    # Serve Prometheus metrics at GET /metrics.
    orchestrator_metrics_enabled: bool = True

    @field_validator("opencti_url", "spiderfoot_url", "amass_engine_url", mode="before")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        """Normalise base URLs so downstream path joins never double the slash."""
        return v.rstrip("/")


settings = Settings()
