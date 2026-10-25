# Configuration

Two files configure a deployment: `.env` (services and secrets) and
`targets.yaml` (what is collected, and when).

## Environment variables

[`.env.example`](../.env.example) lists every variable with a comment; copy it
to `.env`. [`orchestrator/config.py`](../orchestrator/config.py) is the
authoritative definition of the application settings below. Variables that only
configure other containers (`OPENCTI_ADMIN_*`, `MINIO_*`, `RABBITMQ_*`,
`MISP_*`, `KEYCLOAK_*`, `AUTH_*`, `SOCIALOSINT_LLM_*` and the SocialOSINT
platform credentials) are read by the compose files and documented in
`.env.example` only.

Defaults shown are the ones shipped in `.env.example` for Docker.

### Core

| Variable | Default | Meaning |
| --- | --- | --- |
| `ORCHESTRATOR_LANGUAGE` | `es` | Operator-facing language, `es` or `en`; a target can override it. |
| `ORCHESTRATOR_SECRET_KEY` | `insecure-dev-key` | HMAC key that signs the per-run evidence manifests. Empty or the default logs a WARNING at startup. Generate with `openssl rand -hex 32`. |
| `ORCHESTRATOR_SECRET_KEY_PREVIOUS` | (empty) | Comma-separated keys retired by a rotation. `chain/verify` accepts manifests signed with any of them; new manifests are signed with `ORCHESTRATOR_SECRET_KEY` only. See the rotation procedure in [operations](operations.md#evidence-chain). |
| `ORCHESTRATOR_DATABASE_URL` | `sqlite+aiosqlite:////app/data/orchestrator.db` | Container path is the persistent volume; use `./orchestrator.db` bare-metal. |
| `TARGETS_FILE` | `targets.yaml` | Re-read on every API and scheduler call. |
| `ORCHESTRATOR_RETENTION_DAYS` | `0` | Days to keep runs and report directories; `0` (default) never purges. For each target, its first run that met an alert rule and every run after it are kept whatever the period (the evidence chain must stay a contiguous run of manifests). |
| `ORCHESTRATOR_RETENTION_CRON` | `30 3 * * *` | UTC cron of the purge job. |
| `ORCHESTRATOR_API_KEY` | *(empty)* | API keys, comma-separated while rotating. Empty leaves the API **open** (WARNING at startup). |
| `ORCHESTRATOR_LOG_LEVEL` | `INFO` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR`. |
| `ORCHESTRATOR_LOG_FORMAT` | `text` | `text` for a terminal, `json` for a log shipper. |
| `ORCHESTRATOR_METRICS_ENABLED` | `true` | `false` makes `GET /metrics` return 404. |

### OpenCTI

| Variable | Default | Meaning |
| --- | --- | --- |
| `OPENCTI_URL` | `http://opencti:8080` | OpenCTI URL used by the ingest client. |
| `OPENCTI_ADMIN_TOKEN` | *(empty)* | Must match the token OpenCTI was bootstrapped with, or ingest fails. |
| `OPENCTI_ENABLED` | `false` | Sink-off Compose install (the code default is `true` when the variable is absent). To enable the bundled OpenCTI stack, set `true` and use `--profile opencti` (or `COMPOSE_PROFILES=opencti` in `.env`). `false` runs without OpenCTI ingest and outbox; reports, findings, delta and alerts keep working. For installs without OpenCTI only: runs made while disabled are never backfilled ([ADR-008](adr/ADR-008-optional-opencti-sink.md)). |
| `OPENCTI_SSL_VERIFY` | `true` | Set `false` only for local/self-signed TLS in dev. |
| `OPENCTI_INGEST_RETRIES` | `3` | Number of retries after a *transient* OpenCTI error. An invalid token is never retried. |
| `OPENCTI_INGEST_BACKOFF_SECONDS` | `2.0` | Base wait before an ingest retry (doubled each retry, ±25 % jitter, 30 s cap). |
| `OPENCTI_OUTBOX_CRON` | `*/5 * * * *` | UTC cron for OpenCTI outbox drain retries. |
| `OPENCTI_OUTBOX_MAX_ATTEMPTS` | `6` | Total OpenCTI outbox attempts including first ingest. |
| `OPENCTI_OUTBOX_BASE_DELAY_SECONDS` | `60.0` | Base delay for outbox exponential backoff. |
| `OPENCTI_OUTBOX_JITTER_RATIO` | `0.25` | Jitter ratio applied to outbox retry delays. |

### LLM

The provider a target talks to is decided per target, by the `llm` field in
`targets.yaml` (see the target fields below). `local`, the default, sends the
LLM prompts to the Ollama server at `LLM_BASE_URL` and never to a cloud LLM
provider; the prompts stay on your infrastructure only if that server does.
`anthropic`, `openai` and `nebius` need their key from this table.
`LLM_PROVIDER` never makes a target use a different provider family than its
`llm` names. It is a global switch with three effects: `none` turns synthesis off
for every target, `nebius` routes `llm: openai` targets to Token Factory, and
`openai` or `nebius` selects the provider whose model list the startup check
queries.

| Variable | Default | Meaning |
| --- | --- | --- |
| `LLM_PROVIDER` | `ollama` | `ollama` \| `anthropic` \| `openai` \| `nebius` \| `none`. Global switch only (see above); it does not pick a target's provider. `none` disables synthesis for every target. |
| `LLM_MODEL` | `llama3.2` | Model for the cloud providers; fallback for both routes. |
| `LLM_MODEL_REASONING` | *(empty)* | Model for the synthesis call (reasoning route); falls back to `LLM_MODEL`. |
| `LLM_MODEL_FAST` | *(empty)* | Model for evidence qualification (fast route); falls back to `LLM_MODEL`. |
| `OLLAMA_MODEL` | `llama3.2` | Model Ollama serves for targets with `llm: local` (separate from `LLM_MODEL`, which names the cloud model). |
| `LLM_BASE_URL` | `http://ollama:11434` | Ollama endpoint; ignored by the cloud providers. |
| `ANTHROPIC_API_KEY` | *(empty)* | Required by targets with `llm: anthropic`; without it they skip synthesis. |
| `OPENAI_API_KEY` | *(empty)* | Required by targets with `llm: openai` (unless `LLM_PROVIDER=nebius`); without it they skip synthesis. |
| `OPENAI_BASE_URL` | *(empty)* | Optional base URL for OpenAI-compatible endpoints. |
| `NEBIUS_API_KEY` | *(empty)* | Required by targets with `llm: nebius`, and by `llm: openai` targets when `LLM_PROVIDER=nebius`; without it they skip synthesis. |
| `NEBIUS_BASE_URL` | `https://api.tokenfactory.nebius.com/v1` | Nebius Token Factory OpenAI-compatible base URL. |
| `LLM_TIMEOUT_SECONDS` | `120` | End-to-end timeout for a synthesis request. |
| `LLM_MAX_TOKENS` | `2048` | Upper bound on the model reply. |
| `LLM_MAX_OBSERVABLES_IN_PROMPT` | `200` | Cap observables sent to the synthesizer prompt. |
| `LLM_QUALIFY_ENABLED` | `true` | Enables the fast-route evidence-qualification step before synthesis. |
| `LLM_QUALIFY_MAX_ITEMS` | `30` | Max evidence items qualified per run (0–100). Set `0` to disable qualification. |
| `SYNTHESIS_HISTORY_RUNS` | `5` | Prior runs included as synthesis context. |

### Collectors

| Variable | Default | Meaning |
| --- | --- | --- |
| `SPIDERFOOT_URL` | `http://spiderfoot:5001` | SpiderFoot service URL on the internal network. |
| `SPIDERFOOT_MODULES` | `sfp_dnsresolve,sfp_whois,sfp_sslcert` | Fallback when a target lists no modules. |
| `SOCIALOSINT_URL` | `http://socialosint:8000` | SocialOSINT service URL. |
| `SOCIALOSINT_TIMEOUT_SECONDS` | `300` | Total wall-clock bound for a full SocialOSINT run. |
| `AMASS_ENGINE_URL` | `http://amass:4000` | Amass engine sidecar URL (compose profile `amass`). |
| `AMASS_DATA_DIR` | `/app/amass/data` | Volume shared with the engine; `asset.db` is read from here. |
| `AMASS_ENUM_BIN` | `oam_enum` | Amass CLI clients (absolute paths when running outside Docker). |
| `AMASS_SUBS_BIN` | `oam_subs` | Amass CLI clients (absolute paths when running outside Docker). |
| `AMASS_TIMEOUT_SECONDS` | `1800` | Default wall-clock bound for a full Amass run (enum + subs). |
| `TAVILY_API_KEY` | *(empty)* | Required when `collectors.tavily.enabled=true`; blank records a collector failure on every run. Use `TAVILY_MAX_CALLS_PER_RUN=0` to switch the collector off. |
| `TAVILY_SEARCH_DEPTH` | `basic` | Tavily query depth: `basic` or `advanced`. |
| `TAVILY_MAX_RESULTS` | `5` | Global ceiling for results per query, 1–20; the per-target `max_results` is clamped to it. |
| `TAVILY_MAX_CALLS_PER_RUN` | `5` | Global ceiling for search requests per run, 0–20; the per-target `max_calls_per_run` is clamped to it and `0` switches the collector off for every target (skipped, not failed). `5` covers the five query templates for a single-term target. |
| `TAVILY_TIMEOUT_SECONDS` | `120` | Default wall-clock budget of a whole Tavily run per target, retries included (`timeout_seconds` in `targets.yaml` overrides it). |
| `TAVILY_INCLUDE_DOMAINS` | *(empty)* | Optional comma-separated allowlist of result domains (`example.com,news.example.com`). |
| `TAVILY_EXCLUDE_DOMAINS` | *(empty)* | Optional comma-separated denylist of result domains. |

### Alerts

| Variable | Default | Meaning |
| --- | --- | --- |
| `ALERT_WEBHOOK_URL` | *(empty)* | Webhook endpoint for alerts; empty disables the channel. |
| `ALERT_WEBHOOK_SECRET` | *(empty)* | HMAC key for webhook signatures; without it payloads are unsigned. |
| `ALERT_TIMEOUT_SECONDS` | `10` | Timeout for webhook/email alert send attempts. |
| `ALERT_SMTP_HOST` | *(empty)* | SMTP server for e-mail alerts; empty disables the channel. |
| `ALERT_SMTP_PORT` | `587` | SMTP port for email alerts. |
| `ALERT_SMTP_USER` | *(empty)* | SMTP username for email alerts. |
| `ALERT_SMTP_PASSWORD` | *(empty)* | SMTP password for email alerts. |
| `ALERT_SMTP_FROM` | *(empty)* | Sender address for email alerts. |
| `ALERT_EMAIL_TO` | *(empty)* | Recipient address for e-mail alerts. |
| `ALERT_SMTP_STARTTLS` | `true` | Use STARTTLS for SMTP connections. |
| `ALERT_RETRY_CRON` | `*/5 * * * *` | UTC cron for retry worker (`alert-retry` scheduler job). |
| `ALERT_RETRY_MAX_ATTEMPTS` | `4` | Total attempts per message, including first synchronous send. |
| `ALERT_RETRY_BASE_DELAY_SECONDS` | `30` | Exponential backoff base delay. |
| `ALERT_RETRY_JITTER_RATIO` | `0.25` | ± jitter multiplier applied to each retry delay. |

## targets.yaml

[`targets.example.yaml`](../targets.example.yaml) is a commented starting point.
`authorization` and `purpose` are mandatory: both are written into every report
as the audit trail of why the collection happened. The file is re-read on each
API and scheduler call; after editing `schedule.cron` or `enabled`, apply it
with `POST /scheduler/reload`.

Validation is strict: a key the schema does not know (a misspelt `enabeld:` or
`schedual:`, at any level) makes that target invalid, and so does a second
block reusing an `id` (the first block is kept). Invalid targets are skipped,
logged with their id, and listed by `POST /scheduler/reload`; the rest of the
file still loads.

```yaml
targets:
  - id: my-domain
    fqdn: example.com
    authorization: "Self-owned. Authorised by: Jane Doe on 2026-09-01"
    purpose: "Continuous exposure monitoring"
    llm: nebius
    collectors:
      openosint: {enabled: true}
      spiderfoot: {enabled: true}
      tavily:
        enabled: true
        search_terms: ["Example Corp"]
    schedule:
      cron: "0 8 * * *"   # UTC
```

### Fields

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | *required* | Stable identifier; used in paths, metrics labels and report directories |
| `fqdn` | *required* | The seed entity handed to the collectors |
| `authorization` | *required* | Who approved this target and when |
| `purpose` | *required* | Why it is monitored |
| `enabled` | `true` | `false` skips the cron job; a manual run returns `400` |
| `llm` | `local` | Provider for this target's synthesis and evidence qualification. `local` sends the prompts to the Ollama server at `LLM_BASE_URL`, never to a cloud LLM provider; `anthropic` \| `openai` \| `nebius` need their API key. Two global exceptions: `LLM_PROVIDER=none` disables synthesis even for `local`, and `LLM_PROVIDER=nebius` sends `openai` targets to Nebius (they then need `NEBIUS_API_KEY`) |
| `language` | *(inherit)* | `es` \| `en` — overrides `ORCHESTRATOR_LANGUAGE` |
| `report_dir` | `daily_reports` | Root directory for this target's artifacts |

`collectors.openosint`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | |
| `investigation_type` | `domain` | `auto` \| `domain` \| `email` \| `username` \| `ip` \| `phone` \| `url` \| `hash` \| `person` |
| `max_depth` | `2` | BFS hops from the seed entity |
| `max_entities` | `40` | Distinct entities to pivot from |
| `max_tool_calls` | `60` | Tool invocations for the whole run |
| `tool_timeout_seconds` | `30` | Per-tool-call ceiling |

The four budget keys are hard bounds on the pivot search. Without them a
scheduled run can expand without limit.

`collectors.spiderfoot`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | |
| `modules` | `[]` | SpiderFoot module names (`sfp_*`); empty falls back to `SPIDERFOOT_MODULES` |
| `timeout_seconds` | `600` | How long to wait for the whole scan |

`collectors.socialosint`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Opt-in; requires the `socialosint` compose service |
| `usernames` | `[]` | Handles to investigate; empty list ⇒ collector skipped |
| `platforms` | `[twitter, reddit, github, bluesky, hackernews]` | Valid values add `mastodon`; platforms without credentials in `.env` are skipped with a warning |
| `timeout_seconds` | `SOCIALOSINT_TIMEOUT_SECONDS` (`300`) | Total wall-clock bound for the complete workflow; created service sessions are deleted best-effort on exit |

`collectors.amass`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Opt-in; requires the `amass` compose service |
| `active` | `false` | Zone transfers and certificate name grabs against the target (`oam_enum -active`) |
| `brute` | `false` | Wordlist brute forcing after the passive searches (`oam_enum -brute`) |
| `include` / `exclude` | `[]` | Data-source names to restrict the run to / to leave out |
| `progress_timeout_minutes` | `10` | Minutes without new findings before the enumeration stops |
| `timeout_seconds` | `AMASS_TIMEOUT_SECONDS` (`1800`) | Hard wall-clock bound for the whole collector (enum + subs); the CLI process is killed on expiry |

`schedule`:

| Key | Default | Meaning |
| --- | --- | --- |
| `cron` | `"0 8 * * *"` | Five-field [APScheduler](https://apscheduler.readthedocs.io) expression, UTC |
| `misfire_grace_time_seconds` | `3600` | Skip a run missed by more than this instead of firing it late |

`collectors.tavily`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Opt-in switch; the collector is only registered for a run when it is `true` |
| `search_depth` | `basic` | `basic` or `advanced` (Tavily pricing differs) |
| `max_results` | `5` | Results requested and kept per query, 1–20, clamped by `TAVILY_MAX_RESULTS` |
| `include_domains` / `exclude_domains` | `[]` | Result-domain allowlist / denylist; empty falls back to the global settings |
| `search_terms` | `[]` | Optional list of quoted query terms (for example trade names), up to 5 entries of at most 80 characters each; empty keeps the default domain term |
| `include_answer` | `false` | Also request Tavily's synthesised answer, kept as one bounded note per query |
| `max_calls_per_run` | `5` | Search requests per run, 1–20, clamped by `TAVILY_MAX_CALLS_PER_RUN`. Five query templates ship (adverse news and sanctions, ownership, legal proceedings, criminal record, administrative sanctions); queries are built template by template (every term for template 1, then template 2, and so on) and truncated to the budget, so a multi-term target can exhaust the budget before the last template. No query carries a time filter: a conviction or a sanction of years ago is still a finding for a due-diligence file |
| `timeout_seconds` | `TAVILY_TIMEOUT_SECONDS` (`120`) | Wall-clock budget for the whole collector run, retries and backoff included |

`alerts`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Evaluate alert rules after each run |
| `on_new_observables` | `true` | Alert when the run has new observables |
| `min_risk_level` | `high` | Also alert when the synthesised risk is at or above this level |
| `on_run_failure` | `false` | Also alert (and open a case with reason `run_failure`) when the run failed |
| `include_values` | `true` | `false` sends counts and types only, no observable values |
