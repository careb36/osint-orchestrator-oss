# Operations

Running, securing and observing a deployment. Settings named here are described
in [configuration.md](configuration.md).

## Full stack

Requirements: Docker Engine 24+ with Compose v2, 16 GB of RAM (OpenCTI and
Elasticsearch take most of it; 32 GB is comfortable), 4 cores, 50 GB of disk,
and `vm.max_map_count=262144` on the host (`sudo sysctl -w vm.max_map_count=262144`).

```bash
cp .env.example .env                    # set the passwords, tokens and API keys it lists
cp targets.example.yaml targets.yaml    # only targets you are authorised to assess
docker compose up -d --build
```

| Service | Address |
| --- | --- |
| Orchestrator API and console | <http://localhost:8000> (`/docs`, `/console`) |
| OpenCTI | <http://localhost:8080> (2–3 minutes to become healthy) |
| SpiderFoot | <http://localhost:5001> |

```bash
KEY="$(grep '^ORCHESTRATOR_API_KEY=' .env | cut -d= -f2)"
curl -X POST -H "X-API-Key: $KEY" http://localhost:8000/targets/example-domain/run
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1           # status
curl -H "X-API-Key: $KEY" http://localhost:8000/runs/1/report    # Markdown report
```

A run ends `success` (every collector succeeded), `partial` (something failed:
a collector or an OpenCTI ingest) or `failed` (every collector failed).

### Optional services

Each one is off by default and enabled per target in `targets.yaml`.

| Service | Start it with | Notes |
| --- | --- | --- |
| Tavily web research | `TAVILY_API_KEY` in `.env` | No extra container. Searches the quoted `search_terms` (default: the domain) across third-party sources |
| OWASP Amass | `cp amass/datasources.example.yaml amass/datasources.yaml && docker compose --profile amass up -d amass` | Subdomain enumeration. Data-source keys stay in the engine container. `active` and `brute` touch the target: enable them only when the authorisation covers active probing |
| OWASP SocialOSINT | `docker compose --profile socialosint up -d socialosint` | Needs its own OpenAI-compatible model with vision (`SOCIALOSINT_LLM_*`) and platform credentials; a platform without credentials is skipped. Its analysis is stored as an unverified Note. Platform developer terms apply to what you store |
| MISP | `docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp up -d` | Synchronised through the official OpenCTI connector. First start takes 5–10 minutes; create the API key in MISP (*Administration → List Auth Keys*), set `MISP_KEY` and restart `connector-misp` |
| OIDC login | `docker compose -f docker-compose.yml -f docker-compose.auth.yml --profile auth up -d` | Keycloak (`:8085`) and oauth2-proxy (`:8002`) in front of the console. No account is shipped: create one in the `orchestrator` realm. API keys keep working ([ADR-006](adr/ADR-006-oidc-proxy.md)) |

Without OpenCTI: set `OPENCTI_ENABLED=false`. Reports, findings, the delta and
alerts keep working; nothing is pushed to a knowledge graph, and those runs are
never backfilled later ([ADR-008](adr/ADR-008-optional-opencti-sink.md)).

### Demo mode

A lightweight, public-facing deployment of the same code: the API and a demo
page, SQLite, Tavily and the configured LLM. No OpenCTI, SpiderFoot or Amass.

```bash
cp .env.example .env    # NEBIUS_API_KEY, TAVILY_API_KEY, LLM_PROVIDER=nebius, the two LLM_MODEL_* ids,
                        # ORCHESTRATOR_API_KEY, ORCHESTRATOR_SECRET_KEY
docker compose -f docker-compose.demo.yml up -d --build
open http://localhost:7860/demo
```

What a visitor can do, without an API key:

| Route | Purpose |
| --- | --- |
| `GET /demo` | The demo page |
| `GET /demo/targets` | The allowlist ([`demo/targets.demo.yaml`](../demo/targets.demo.yaml)); there is no free-text target |
| `POST /demo/targets/{id}/run` | Start a run; `429` with `Retry-After` over the daily limits |
| `GET /demo/targets/{id}/runs`, `GET /demo/runs/{id}` | Run list and status |
| `GET /demo/runs/{id}/evidence` | Each web result with its category, relevance, confidence and rationale |
| `GET /demo/runs/{id}/finding` | Which model synthesised the run and how long it took; the synthesis text is not public |
| `GET /demo/runs/{id}/report` | The report with a disclaimer and **without** its synthesis section |
| `GET /demo/runs/{id}/manifest`, `GET /demo/targets/{id}/chain/verify` | The signed manifest and the chain check |

Guards:

- **No model verdict in public.** The synthesis (summary, risk level,
  justification, pivots) is free model prose about a named entity: it is
  available to the operator with the API key and never served by `/demo`. The
  public page shows the qualified evidence, where every row links its source.
- **Allowlist only.** Runs of any other target are invisible to the `/demo`
  routes; every other route still needs the API key.
- **Daily limits** per visitor (`DEMO_MAX_RUNS_PER_IP_PER_DAY`) and overall
  (`DEMO_MAX_RUNS_PER_DAY`), reset at 00:00 UTC. Visitors are counted by an
  HMAC of their address, kept for two days; the address is never stored. Set
  `DEMO_TRUSTED_PROXY_HOPS` to the number of proxies in front of the service.
- **Call budgets** for Tavily (`DEMO_TAVILY_CALLS_PER_DAY`) and the LLM
  (`DEMO_LLM_CALLS_PER_DAY`). When one is spent the call is not made, the run
  still finishes and its error field says why.
- **Startup check.** With `DEMO_MODE=true` the service refuses to start unless
  `OPENCTI_ENABLED=false`, the API key and the signing key are set,
  `TAVILY_API_KEY` is set, every allowlisted target enables the Tavily
  collector and nothing else, and, for each target, the key of the provider
  its synthesis would use is set: `anthropic` → `ANTHROPIC_API_KEY`; `openai`
  → `OPENAI_API_KEY`; `nebius` → `NEBIUS_API_KEY` plus both `LLM_MODEL_*` ids.
  The provider is the resolved one: `llm: openai` under `LLM_PROVIDER=nebius`
  is the Nebius route; `llm: local` and `LLM_PROVIDER=none` need no key.
  Nothing runs on a schedule.
- **Local demo.** `docker-compose.demo.yml` sets `DEMO_TRUSTED_PROXY_HOPS=0`
  and, unless `.env` sets it, raises `DEMO_MAX_RUNS_PER_IP_PER_DAY` to the
  global cap: behind Docker's port mapping every browser on the machine shares
  one address. The counters
  live in the `demo-data` volume; `docker compose -f docker-compose.demo.yml
  down -v` resets them. `/health` reports the OpenCTI sink as `disabled`, not
  `degraded`, because demo mode turns it off by design.
- **Page language.** `/demo?lang=es|en` or the browser's `Accept-Language`;
  the global `ORCHESTRATOR_LANGUAGE` is the fallback.

Runs shown before any visitor starts one are loaded from `demo/seed/` (see its
[README](../demo/seed/README.md)); deployment: [deploy.md](deploy.md).

### Kubernetes

The Helm chart in [`deploy/helm/osint-orchestrator`](../deploy/helm/osint-orchestrator/)
deploys the orchestrator only; OpenCTI and SpiderFoot are referenced by URL.
The orchestrator is single-instance by design (SQLite and an in-process
scheduler): one replica, `Recreate` strategy, one `ReadWriteOnce` volume
([ADR-005](adr/ADR-005-api-auth-and-single-instance.md)).

## API

Interactive reference: `/docs` (OpenAPI at `/openapi.json`). Public routes are
`/`, `/health`, `/metrics`, `/docs`, `/redoc`, `/openapi.json`, `/console`,
`/console/i18n.json` and, with `DEMO_MODE=true`, the `/demo` routes listed
under [Demo mode](#demo-mode); every other route needs `X-API-Key: <key>` or
`Authorization: Bearer <key>`.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Landing page with links to console, docs and health (no API key) |
| `GET` | `/health` | Liveness check (no API key) |
| `GET` | `/metrics` | Prometheus metrics (no API key) |
| `GET` | `/console/i18n.json` | Console translation catalogue (public; no target/run data) |
| `GET` | `/console` | Operator console shell (public, no data; every call it makes needs the API key, entered on the page) |
| `GET` | `/health` | Service health snapshot (`ok`, `degraded`, `offline`) used by the console health cards |
| `GET` | `/analytics/risk-trends` | Per-target risk and new-observable trends for the console risk view |
| `GET` | `/targets` | List configured targets |
| `GET` | `/targets/{id}` | Get a single target |
| `POST` | `/targets/{id}/run` | Trigger a collection run — `202`, returns `run_id`, runs in background |
| `POST` | `/scheduler/reload/preview` | Preview target cron changes from `targets.yaml` without mutating jobs |
| `POST` | `/scheduler/reload` | Reload target cron jobs from `targets.yaml` without restarting the process |
| `POST` | `/alerts/dlq/replay` | Replay dead-letter alert deliveries (`channel` = `webhook` \| `email`, `limit` = `1..1000`) |
| `POST` | `/opencti/outbox/replay` | Replay dead-letter OpenCTI bundles (`run_id`, `limit` = `1..1000`) and drain the due ones now |
| `GET` | `/runs` | 100 most recent runs, newest first; `?target_id=` filters |
| `GET` | `/runs/{id}` | A run's status, counts, and `alerts[]` dispatch audit |
| `GET` | `/runs/{id}/delta` | Net-new observables for that run (from the DB, not the files) |
| `GET` | `/runs/{id}/report` | Markdown report for a completed run (`text/plain`) |
| `GET` | `/runs/{id}/finding` | LLM-synthesized finding for a completed run |
| `GET` | `/runs/{id}/evidence` | Evidence qualifications of a run |
| `GET` | `/runs/{id}/manifest` | Signed evidence manifest of a run (`404` when unsealed) |
| `GET` | `/targets/{id}/chain/verify` | Verify the target's evidence chain |

Errors carry a `detail` string in the operator language: `404` unknown target,
run, report or finding; `400` disabled target; `401` missing or wrong key; `409`
a run is already active for the target.

### Health dashboard polling and retry behaviour

The console health tab polls `/health` every 15 seconds when the tab is open and
re-renders the status cards without losing the current page selection. The status
payload is deterministic and intentionally limited to three values so the UI can
render every state without guessing:

- `ok`: all core checks are healthy
- `degraded`: the app is still serving requests, but a dependency is degraded
  (for example, the scheduler is not running or OpenCTI is disabled)
- `offline`: a core dependency failed its self-check (for example, DB access)

Each entry under `checks` carries one of the same three values, plus `disabled`
for a component that is off by configuration and does not affect the overall
status (today only the OpenCTI sink in demo mode).

A failed poll is surfaced as an error state in the dashboard rather than
crashing the page; the next periodic refresh retries automatically. The UI keeps
its polling interval modest to avoid creating a visible thundering herd while a
service is recovering.

**Key rotation:** set `ORCHESTRATOR_API_KEY=old,new`, restart, move the callers,
then drop the old key. Keys are compared in constant time.

## Reports and evidence chain

Each run writes its own directory,
`daily_reports/<date>/<target>/run-<run_id>/`:

| File | Content |
| --- | --- |
| `report.md` / `report.pdf` | Operator report: collector status, what is new, inventory, qualified evidence, synthesis |
| `bundle.stix.json` | The run's STIX 2.1 bundle, deterministic ids |
| `delta.json` | Observables new since the previous run |
| `qualified_evidence.json` | Each web result with its category, relevance, confidence and rationale |
| `manifest.json` | SHA-256 of every file above, the hash of the target's previous manifest, and an HMAC-SHA256 signature keyed with `ORCHESTRATOR_SECRET_KEY` |

The manifest is written last and its hash is stored with the run, so altering or
removing any file, manifest or earlier run is detectable
([ADR-007](adr/ADR-007-evidence-chain.md)). `GET /targets/{id}/chain/verify`
re-hashes everything and stops at the first broken run:

| `reason` | Meaning |
| --- | --- |
| `artefact_hash` / `artefact_missing` | A report file was changed or removed after the run (`detail` names it) |
| `manifest_missing` | The manifest file is gone while the run row says it was sealed |
| `signature` | The manifest bytes differ from the hash recorded for the run: it was edited |
| `signature_key` | The manifest is the recorded one but its signature does not match the current key (a key rotation looks like this) |
| `chain_link` | A run does not point to the previous sealed run (a run in between was removed) |
| `unsupported_version` | A manifest format this version cannot read |

A run that failed before its manifest was written is *unsealed*: counted, never
reported as tampering. When retention has purged a target's oldest runs,
verification starts at the oldest remaining run and reports it as
`anchor_run_id`; keep the manifests you need to prove older history.

Offline check of a manifest signature (each file is checked with `sha256sum`):

```bash
python3 -c 'import hashlib,hmac,json,sys; m=json.load(open(sys.argv[1])); s=m.pop("signature"); body=json.dumps(m,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode(); print(hmac.compare_digest(s,"hmac-sha256:"+hmac.new(sys.argv[2].encode(),body,hashlib.sha256).hexdigest()))' manifest.json "$ORCHESTRATOR_SECRET_KEY"
```

Rotating the key never re-signs old manifests; runs signed before the rotation
report `signature_key` and are verified with the retired key.

## Alerts

After each run the target's `alerts` rules are evaluated and the configured
channels are used: a webhook (`ALERT_WEBHOOK_URL`, signed when
`ALERT_WEBHOOK_SECRET` is set) and e-mail (`ALERT_SMTP_HOST`, `ALERT_EMAIL_TO`).
Failed deliveries are retried with exponential backoff
(`ALERT_RETRY_*`); a failure the receiver would repeat goes straight to the
dead-letter queue, replayed with `POST /alerts/dlq/replay`.

The webhook body carries `target_id`, `run_id`, `run_status`, `risk_level`,
`new_observables`, `new_observable_count`, `report_path`, `finding_summary` and
`generated_at`. Verify `X-Orchestrator-Signature: sha256=<hex>` as the
HMAC-SHA256 of the raw body with the shared secret. Payloads include observable
values unless the target sets `include_values: false`.

## Retention

A nightly job (`ORCHESTRATOR_RETENTION_CRON`) deletes runs, findings, alerts and
`daily_reports/<date>` directories older than `ORCHESTRATOR_RETENTION_DAYS`
(default `90`, `0` disables it). The delta memory (`seen_observables`) is never
purged. The default is operational, not a legal retention period: when reports
are due-diligence evidence, set the period your regulation requires or archive
the run directories before the purge.

## Observability

**Logs.** `ORCHESTRATOR_LOG_FORMAT=json` emits one object per line with
`target_id`, `run_id`, `collector` and a request id (`X-Request-ID`, generated
when absent). With `text`, only the message is printed.

**Startup checks.** The service logs a WARNING for an empty API key and for an
empty or default signing key, and checks that the configured cloud LLM models
are served by the provider (`LLM model available` / `LLM model not served by
provider`).

**Metrics.** `GET /metrics` (Prometheus, no API key). Names are prefixed
`osint_orchestrator_`; label values are bounded, never an observable value or a
run id.

| Metric | Labels | Meaning |
| --- | --- | --- |
| `http_requests_total` | `method`, `path` (route template), `status` | API traffic |
| `http_request_duration_seconds` | `method`, `path` (route template) | API latency — no `status` label, so latency cannot be split by response code |
| `runs_total` | `target_id`, `status` | Completed runs by final status (`success`, `partial`, `failed`) |
| `runs_in_progress` | `target_id` | Runs currently executing |
| `run_duration_seconds` | `target_id` | Full pipeline duration histogram |
| `collector_runs_total` | `collector`, `target_id`, `outcome` | Per-collector outcome (`success`, `failure`, `error`) |
| `collector_duration_seconds` | `collector` | Per-collector duration — no `target_id` label, so duration cannot be split by target |
| `run_observables` | `target_id`, `kind` (`total`, `new`) | Observables in the most recent run |
| `new_observables_total` | `target_id` | Net-new, ingested observables (the alert/delta definition) |
| `target_last_success_timestamp_seconds` | `target_id` | Last successful run timestamp (use `time() - metric` for freshness age) |
| `opencti_ingest_total` | `target_id`, `outcome` | STIX bundles pushed to OpenCTI |
| `opencti_ingest_retries_total` | `target_id` | Retries after a transient OpenCTI error (pycti's internal per-object retries are not counted) |
| `opencti_outbox_pending` | — | Pending OpenCTI bundles waiting for retry |
| `opencti_outbox_oldest_age_seconds` | — | Age of oldest pending OpenCTI outbox bundle |
| `opencti_outbox_deliveries_total` | `outcome` | Outbox outcomes (`sent`, `failed`, `dead_letter`) |
| `opencti_outbox_retries_total` | `target_id` | OpenCTI outbox retry attempts |
| `opencti_outbox_dead_letter` | — | OpenCTI bundles parked in the dead-letter queue (need operator action) |
| `alert_deliveries_pending` | — | Alert deliveries waiting for a retry |
| `alert_deliveries_dead_letter` | — | Alert deliveries parked in the dead-letter queue (need operator action) |
| `synthesis_total` | `target_id`, `status` (`ok`, `skipped`, `failed`) | LLM synthesis attempts |
| `llm_requests_total` | `provider`, `model`, `status` | LLM API requests by provider (`anthropic`, `openai`, `nebius`, `ollama`), model and status (`ok`, `http_429`, `http_5xx`, `timeout`, `error`, `schema_downgrade`). One sample per SDK completion call: the Anthropic SDK's single internal retry is not sampled. |
| `llm_tokens_total` | `provider`, `model`, `direction` (`input`, `output`) | LLM token usage by provider and model, split by prompt vs completion direction |
| `llm_model_available` | `provider`, `model`, `route` (`reasoning`, `fast`) | Startup preflight gauge: `1` when the configured route model is listed by the provider `GET /models`, `0` when it is not served |
| `alerts_total` | `channel`, `status` | Alert lifecycle events (`sent`, `failed`, `retried`, `dlq`) |
| `evidence_chain_verify_total` | `target_id`, `outcome` | Evidence-chain verifications by outcome (`ok`, `broken`, `error`) |
| `evidence_qualified_total` | `target_id`, `category` | Qualified evidence rows by category (`adverse_media`, `sanctions`, `litigation`, `regulatory_action`, `corporate_profile`, `unrelated`) |
| `scheduled_jobs` | — | Cron jobs registered in the scheduler |
| `build_info` | `version` | Build metadata |

```promql
increase(osint_orchestrator_runs_total{status="failed"}[1d]) > 0                 # a run failed
increase(osint_orchestrator_opencti_ingest_total{outcome="failure"}[1h]) > 0     # findings not reaching OpenCTI
osint_orchestrator_scheduled_jobs == 0                                            # targets.yaml not loaded
time() - osint_orchestrator_target_last_success_timestamp_seconds > 86400         # a target is stale
```

## Database

SQLite, operational state only. Alembic migrations in
`orchestrator/migrations/versions/` are applied on every startup. After
changing a model: `alembic upgrade head`, then
`alembic revision --autogenerate -m "…"`; CI runs `alembic check`.

## UI operations runbook

### Console smoke checks

The browser console is the UI's production entry point. Run the CI-safe smoke
suite before every release:

```bash
pytest tests/unit/test_operator_console.py -v
```

The smoke path covers the core operator journey: load `/console`, verify the key
prompt and CSP hardening, load `/console/i18n.json`, and confirm that protected
API calls are still rejected without a key while the shell remains reachable.

### Frontend telemetry and error tracking

The console logs browser-side events to the developer console with structured
context (`event`, `path`, `language`, `message`, `stack`). This is intentionally
low-volume and bounded: the last 25 events are retained in memory for the active
page and every error is stamped with enough detail to distinguish auth issues,
API failures and unhandled client exceptions without exposing raw API keys.

### Incident triage and rollback

| Signal | Likely cause | Immediate action |
| --- | --- | --- |
| `/console` loads but all data calls return `401` | API key missing or stale | Verify the stored key, clear/re-enter it, check the service's `ORCHESTRATOR_API_KEY` value |
| `/console` fails in-browser with a JS error | Frontend regression or malformed API payload | Open the browser console, inspect the last `ui-telemetry` event, and compare it with the failing route and payload |
| `/console/i18n.json` or static shell fails to load | Deployment problem or CSP regression | Confirm the app is healthy, the page loads with the expected nonce-based CSP, and the asset is served without redirect |
| Data loads but a target or run view is empty | API/auth issue or empty database | Check `/targets`, `/runs` and `/analytics/risk-trends` with the same key; if empty, verify scheduler and database state |

Rollback steps:

1. Stop the change by reverting the release commit or image tag.
2. Restore the previous deployment and confirm that the prior API key and
   ingress/auth settings still match the running service.
3. Re-run the console smoke checks and verify the shell and data endpoints work
   before reopening traffic.
4. Capture the browser console telemetry and the failing API response in the
   incident log so the underlying cause is fixed before a new rollout.

## Release checklist and support SOP

Before a UI release, confirm all of the following:

- [ ] The console smoke checks pass in CI (`pytest tests/unit/test_operator_console.py -v`)
- [ ] CSP and X-Content-Type-Options hardening remain intact for the shell
- [ ] Error telemetry includes `event`, `path`, `message`, and a stack when available
- [ ] A stale or missing API key is clearly surfaced to the operator and the key remains in session storage only
- [ ] The release notes mention any API contract or auth changes that affect console users
- [ ] A rollback plan and owner are recorded for the release window

Support SOP:

- Check the operator console logs first for `ui-telemetry` and any `console_error`
  events; these isolate browser regressions from backend run failures.
- If the backend API is healthy but the UI is not, verify the browser is not
  holding a stale key and that the CSP still matches the new shell.
- If the issue is systemic, revert to the last known-good image, restore the
  previous config, re-run the smoke checks, and document which telemetry event
  triggered the incident.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Elasticsearch exits seconds after `docker compose up` | `vm.max_map_count` below 262144 on the host |
| `curl :8080/health` refused for the first minutes | OpenCTI and Elasticsearch take 2–3 min; follow `docker compose logs -f opencti` |
| Containers killed by the OOM killer | Host below 16 GB, or `ELASTIC_MEMORY_SIZE` too high for it |
| `401` on every call | `ORCHESTRATOR_API_KEY` is set but the header is missing or wrong; `/health` and `/metrics` never need one |
| The API answers without a key | `ORCHESTRATOR_API_KEY` is empty — the startup log says so explicitly |
| `404` on `/metrics` | `ORCHESTRATOR_METRICS_ENABLED=false` |
| `400` on `POST /targets/{id}/run` | The target exists but is `enabled: false` |
| `pip install -e .` cannot resolve `openosint` | The dependency is a `git+https` pin, so a git client must be on `PATH` |
| A SpiderFoot scan never finishes | Raise the target's `timeout_seconds`; check the module names are real `sfp_*` modules in that image |
| Run is `partial` with `opencti-sink:` in `error` | The bundle never reached OpenCTI — check `osint_orchestrator_opencti_ingest_total{outcome="failure"}`, `OPENCTI_URL` and `OPENCTI_ADMIN_TOKEN`; the observables are re-reported as new next run |
| Reports come out in the wrong language | `ORCHESTRATOR_LANGUAGE`, or the target's `language`; an unrecognised value is logged and ignored |
| A run finishes with no finding / `synthesis_total{status="failed"}` grows | The LLM endpoint is unreachable — compose ships no Ollama service; check `LLM_BASE_URL` or switch `LLM_PROVIDER` |
| Synthesis always unavailable | Check startup logs for `LLM model not served by provider` and `osint_orchestrator_llm_model_available{...} == 0`; switch to an id listed by the provider `GET /models` |
| Browser login loops or `502` on `:8002` with the auth overlay | Keycloak not healthy yet, or `AUTH_PROXY_PORT`/`AUTH_REDIRECT_URL` disagree — both must use the same port (`.env.example` ships 8002) |
| `osint_orchestrator_scheduled_jobs` is lower than expected | A target is `enabled: false`, or its `cron` is not five fields — both are skipped, the second with an `ERROR` log |
| `osint_orchestrator_scheduled_jobs` is 0 | `targets.yaml` was not found at `TARGETS_FILE` when the app started (a `WARNING` names the path) |
| A changed `cron` has no effect | Cron jobs are registered at startup; apply edits with `POST /scheduler/reload` |
