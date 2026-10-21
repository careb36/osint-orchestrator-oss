# Operations

Running, securing and observing a deployment. Settings named here are described
in [configuration.md](configuration.md).

## Full stack

Requirements: Docker Engine 24+ with Compose v2.20+, 16 GB of RAM (OpenCTI and
Elasticsearch take most of it; 32 GB is comfortable), 4 cores, 50 GB of disk,
and `vm.max_map_count=262144` on the host (`sudo sysctl -w vm.max_map_count=262144`).

```bash
cp .env.example .env                    # set the passwords, tokens and API keys it lists
cp targets.example.yaml targets.yaml    # only targets you are authorised to assess
# Set OPENCTI_ENABLED=true in .env for the full stack.
docker compose --profile opencti up -d --build
```

| Service | Address |
| --- | --- |
| Orchestrator API and dashboard | <http://localhost:8000> (`/docs`, `/console`) |
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
| MISP | `docker compose -f docker-compose.yml -f docker-compose.misp.yml --profile misp --profile opencti up -d` | Requires both profiles and `OPENCTI_ENABLED=true`. Synchronised through the official OpenCTI connector. First start takes 5–10 minutes; create the API key in MISP (*Administration → List Auth Keys*), set `MISP_KEY` and restart `connector-misp` |
| OIDC login | `docker compose -f docker-compose.yml -f docker-compose.auth.yml --profile auth up -d` | Keycloak (`:8085`) and oauth2-proxy (`:8002`) in front of the console. No account is shipped: create one in the `orchestrator` realm. API keys keep working ([ADR-006](adr/ADR-006-oidc-proxy.md)) |
| investigation-assistant worker | `docker compose -f docker-compose.yml -f docker-compose.engine.yml --profile opencti --profile engine up -d --build` | One-shot container that exports one case of the investigation-assistant engine and posts its STIX bundle to `POST /bundles` ([ADR-011](adr/ADR-011-external-stix-producers.md)). Needs `OPENCTI_ENABLED=true`, a clone of the producer and its own API key; see below |

#### investigation-assistant worker

The worker runs the investigation-assistant engine from its own image, built
from the operator's clone of that repository with its own `Dockerfile`. It
exports one case to a STIX 2.1 bundle, posts it to `POST /bundles` over the
compose network (`http://orchestrator:8000`), and exits. It starts only once
the orchestrator is healthy, which with the `opencti` profile means once
OpenCTI is up. Its exit status is the result: `0` when the bundle was
ingested, non-zero when the export was refused or the orchestrator rejected
the bundle.

Configure it in `.env`:

| Variable | Side | Value |
| --- | --- | --- |
| `INVESTIGATION_ASSISTANT_DIR` | worker | Path to the clone of the investigation-assistant repository |
| `INVESTIGATION_CASE` | worker | Case slug under `<clone>/cases` (default `demo_simulado`) |
| `INVESTIGAR_ORCHESTRATOR_API_KEY` | worker | The worker's own API key. The producer reads it from the environment only: it is never in the image or on the command line |
| `ORCHESTRATOR_API_KEY` | orchestrator | Comma-separated list that includes the worker's key. Removing that entry revokes the worker without touching the other keys |
| `OPENCTI_ENABLED` | orchestrator | `true`: `POST /bundles` answers `409` while the OpenCTI sink is off |

Compose refuses to start the overlay until `INVESTIGATION_ASSISTANT_DIR` and
`INVESTIGAR_ORCHESTRATOR_API_KEY` are set. A worker key that is not in
`ORCHESTRATOR_API_KEY` gets `401` and the worker exits non-zero.

Case data never leaves the host except into OpenCTI. `<clone>/cases` is
mounted read-only. The worker copies the selected case into a tmpfs, runs
`investigar run` and then `investigar export-stix --ingest`, and the copy, the
pipeline outputs and the bundle are discarded with the container. The case's
`case.yaml` must set `stix.fecha_corte`, and `stix.mapeo_cuenta: text` when its
accounts have no bank or country; the exporter refuses the case otherwise.

Smoke path:

```bash
docker compose -f docker-compose.yml -f docker-compose.engine.yml \
  --profile opencti --profile engine up -d --build
docker compose -f docker-compose.yml -f docker-compose.engine.yml \
  logs investigation-engine          # ends with "Ingestado en el orquestador"
```

The orchestrator logs `OpenCTI ingest OK: work=investigation-assistant:<case>
objects=<n>` once OpenCTI has accepted the bundle. In the OpenCTI UI the
case's objects carry the case slug as a label, so filtering by that label
lists them.

`demo_simulado` holds fictitious data. Every other case holds real case data:
ingest it only into your own OpenCTI, never into a shared or public instance
such as the OpenCTI demo.

Out of scope, each a separate decision: scheduled or streaming intake, and
bundles from producers you do not trust ([ADR-011](adr/ADR-011-external-stix-producers.md)).

Without OpenCTI: keep `OPENCTI_ENABLED=false` (the `.env.example` default) and
use `docker compose up -d --build` without the `opencti` profile or
`COMPOSE_PROFILES=opencti`. Reports, findings, the delta and
alerts keep working; nothing is pushed to a knowledge graph, and those runs are
never backfilled later ([ADR-008](adr/ADR-008-optional-opencti-sink.md)).

### Kubernetes

The Helm chart in [`deploy/helm/osint-orchestrator`](../deploy/helm/osint-orchestrator/)
deploys the orchestrator only; OpenCTI and SpiderFoot are referenced by URL.
The orchestrator is single-instance by design (SQLite and an in-process
scheduler): one replica, `Recreate` strategy, one `ReadWriteOnce` volume
([ADR-005](adr/ADR-005-api-auth-and-single-instance.md)).

## Showcase run

`python -m orchestrator.showcase` fills an empty deployment with two finished
runs of a fictitious entity so the console, the reports and the evidence chain
can be seen before any collector or model provider is configured. It needs no
network and no API key.

```bash
docker compose exec orchestrator python -m orchestrator.showcase
# bare metal, from the repository root:
python -m orchestrator.showcase
```

What it does. Each recording in
[`orchestrator/showcase_data/`](../orchestrator/showcase_data/) (`run-1.json`,
`run-2.json`, replayed in that order) holds the output of the collectors
(observables, relationships, notes, web evidence) and the answers of the
model: one qualification per evidence item and one finding, both in Spanish
and in English. The command hands them to the pipeline through a collector
that returns the recorded `CollectorResult` and an LLM client that answers
the qualification and synthesis prompts from the recording; everything else
is the production code path (`orchestrator/pipeline.py`): STIX normalisation,
`is_new` against the target's `seen_observables`, `RunObservable` rows, the
synthesis validation, `report.md`, `bundle.stix.json`, `delta.json`,
`report.pdf`, `qualified_evidence.json`, the manifest signed with
`ORCHESTRATOR_SECRET_KEY` and chained to the previous run (ADR-007), the
daily index and the alert case. The runs are ordinary rows: retention purges
them after `ORCHESTRATOR_RETENTION_DAYS`, `GET /targets/showcase-example/chain/verify`
verifies them, and a configured alert channel receives their alerts like any
other run's.

What it is honest about. The entity uses reserved names (`.example`
domains, `203.0.113.0/24` addresses) and the texts are written, not model
output: every `evidence_qualifications` and `findings` row says provider
`showcase` and model `recorded-sample`. The target block in
`targets.example.yaml` ships `enabled: false`, so the scheduler never runs it
and `POST /targets/showcase-example/run` answers 400; the replay admits its
runs directly. For a real target, copy the block under a new `id`, set
`enabled: true`, replace `fqdn` and `search_terms` with an entity you are
authorised to assess, and set `NEBIUS_API_KEY` and `TAVILY_API_KEY`; keep the
sample block as it is. The id is the key of a target's history
(`seen_observables`, the synthesis history, the risk trend), so reusing
`showcase-example` for a real entity would feed it the sample's fabricated
observables as prior observations.

Preconditions, each reported with exit code 1: `OPENCTI_ENABLED=false`
(the sample must not be ingested into a knowledge graph); the target
`showcase-example` present in `targets.yaml` (copy the block from
`targets.example.yaml`); no run of that target pending or running. The
recordings' language follows the target's `language`, then
`ORCHESTRATOR_LANGUAGE`. `--seed-dir` points the command at another
directory of `run-*.json` files, for example a recording of your own.

Run it with the API already up (`docker compose exec`, the documented path)
or before starting the API, not while the API is starting: the startup
recovery fails every run still PENDING or RUNNING in the database
(`mark_interrupted_runs`), a replay included, since a process that has
just started cannot know about a runner outside it. A replay failed that
way is reported with exit code 1 (`status failed: interrupted …`); replay
it again once the API is up.

## API

Interactive reference: `/docs` (OpenAPI at `/openapi.json`). Public routes are
`/`, `/health`, `/metrics`, `/docs`, `/redoc`, `/openapi.json` and `/console`
(with its client routes and `/console/assets/*`); every other route needs
`X-API-Key: <key>` or `Authorization: Bearer <key>`.

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Landing page with links to the dashboard, docs and health (no API key) |
| `GET` | `/health` | Liveness: always 200 while the process answers; component checks in the body (no API key) |
| `GET` | `/ready` | Readiness: the same body, 503 while the database is offline or the scheduler is not running (no API key) |
| `GET` | `/metrics` | Prometheus metrics (no API key) |
| `GET` | `/console` | Operator dashboard shell (public, no data; every call it makes needs the API key, entered on the page). Serves the React build from `orchestrator/static/ui-dist`; without a build it answers `503` with build instructions |
| `GET` | `/console/{route}` | Client-side routes of the dashboard (`/console/targets`, `/console/runs/{id}`): same shell, the router renders the view. `404` without a build |
| `GET` | `/console/assets/{file}` | Hashed script and stylesheet of the dashboard build (immutable cache; no path traversal) |
| `GET` | `/health` | Service health snapshot (`ok`, `degraded`, `offline`) shown on the dashboard overview |
| `GET` | `/ready` | Same snapshot with an HTTP status a probe can act on: 200 ready, 503 not ready |
| `GET` | `/analytics/risk-trends` | Per-target risk and new-observable trends for the dashboard's risk columns and target detail |
| `GET` | `/targets` | List configured targets |
| `GET` | `/targets/{id}` | Get a single target |
| `POST` | `/targets/{id}/run` | Trigger a collection run — `202`, returns `run_id`, runs in background |
| `POST` | `/scheduler/reload/preview` | Preview target cron changes from `targets.yaml` without mutating jobs |
| `POST` | `/scheduler/reload` | Reload target cron jobs from `targets.yaml` without restarting the process |
| `POST` | `/alerts/dlq/replay` | Replay dead-letter alert deliveries (`channel` = `webhook` \| `email`, `limit` = `1..1000`) |
| `GET` | `/alerts` | Alert cases newest first (`?target_id=`, `?state=open\|acknowledged\|resolved`, `limit`, `offset`) with `total` |
| `GET` | `/alerts/{id}` | One alert case |
| `POST` | `/alerts/{id}/ack` | `open` → `acknowledged`; body `{"by": "<operator>", "note": "…"}`; 409 from any other state |
| `POST` | `/alerts/{id}/resolve` | `open` or `acknowledged` → `resolved`; same body; 409 when already resolved |
| `POST` | `/bundles` | Ingest an external STIX 2.1 bundle (ADR-011); body is the bundle, `?work_name=` (default `external-stix`). 400 not JSON, 409 OpenCTI disabled, 422 contract or parse failure, 502 ingest failed, 503 OpenCTI unreachable; a failure is not queued |
| `POST` | `/opencti/outbox/replay` | Replay dead-letter OpenCTI bundles (`run_id`, `limit` = `1..1000`) and drain the due ones now |
| `GET` | `/runs` | Runs newest first, each with the `risk_level` of its finding (`null` without one); `?target_id=` filters, `?limit=` (1–500, default 100) and `?offset=` page through older runs |
| `GET` | `/runs/{id}` | A run's status, counts, `risk_level`, and `alerts[]` dispatch audit |
| `GET` | `/runs/{id}/delta` | Net-new observables for that run (from the DB, not the files) |
| `GET` | `/runs/{id}/report` | Markdown report for a completed run (`text/plain`) |
| `GET` | `/runs/{id}/finding` | LLM-synthesized finding for a completed run |
| `GET` | `/runs/{id}/evidence` | Evidence qualifications of a run |
| `GET` | `/runs/{id}/manifest` | Signed evidence manifest of a run (`404` when unsealed) |
| `GET` | `/runs/{id}/report.pdf` | PDF companion of the report (`application/pdf`; `404` when the run has none) |
| `GET` | `/runs/{id}/bundle` | Every file of the run directory, `manifest.json` included, as one `application/zip` download (`404` without artefacts) |
| `GET` | `/targets/{id}/chain/verify` | Verify the target's evidence chain; 404 for a target not in `targets.yaml` |

Errors carry a `detail` string in the operator language: `404` unknown target,
run, report or finding; `400` disabled target; `401` missing or wrong key; `409`
a run is already active for the target.

### Dashboard refresh and health values

The dashboard loads `/health` with the overview and re-fetches `/runs` every
10 seconds while a run is pending or running; when a run reaches a terminal
status it also refreshes the risk trends and the findings. The health payload
is deterministic and intentionally limited to three overall values so the UI
can render every state without guessing:

- `ok`: all core checks are healthy
- `degraded`: the app is still serving requests, but a dependency is degraded
  (for example, the scheduler is not running)
- `offline`: a core dependency failed its self-check (for example, DB access)

Each entry under `checks` carries one of the same three values, plus
`disabled` for a component switched off by configuration: with
`OPENCTI_ENABLED=false` the `opencti` check reads `disabled` and does not
lower the overall status (ADR-008: the sink is optional). `/health` always
answers 200; use `/ready` where an HTTP status matters (the compose
healthcheck, Kubernetes readiness and startup probes, a load balancer): it
answers 503 while a check is `offline` or the scheduler is not running.

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

**Rotating the signing key.** Old manifests are never re-signed. Move the
current key to `ORCHESTRATOR_SECRET_KEY_PREVIOUS` (comma-separated when more
than one key has been retired), put the new key in `ORCHESTRATOR_SECRET_KEY`
and restart: new runs are signed with the new key and `chain/verify` still
accepts the manifests signed with a retired one. A manifest that matches none
of the configured keys reports `signature_key`. Keep every retired key for as
long as the runs it signed are within your retention period; the offline check
above takes whichever key signed that manifest.

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

### Alert cases (triage)

Every run that meets an alert rule opens one **alert case** before any channel
is tried, so a deployment without a webhook or SMTP still has a list to work
through, and a failed delivery never loses the alert. The case records the
rule that fired (`reason`: `new_observables`, `risk_level` or `run_failure`,
the last one only with `alerts.on_run_failure: true` on the target), the run's
status and risk level, and its triage state:

| State | Meaning | How it gets there |
| --- | --- | --- |
| `open` | Nobody has looked at it | Opened by the pipeline |
| `acknowledged` | An operator is on it | `POST /alerts/{id}/ack` with the operator's name |
| `resolved` | Nothing more to do | `POST /alerts/{id}/resolve` from `open` or `acknowledged` |

The dashboard's *Alerts* view lists open cases first and offers both actions;
the name is free text because the API has no users (ADR-005). Cases are purged
with their run by retention. Two metrics follow the queue: `alert_cases{state}`
(open and acknowledged counts) and `alert_case_time_to_acknowledge_seconds`
(a histogram observed on every acknowledgement). Mean time to acknowledge over
the last day, in PromQL:

```promql
increase(osint_orchestrator_alert_case_time_to_acknowledge_seconds_sum[1d])
  / increase(osint_orchestrator_alert_case_time_to_acknowledge_seconds_count[1d])
```

## Retention

A nightly job (`ORCHESTRATOR_RETENTION_CRON`) deletes runs that finished more
than `ORCHESTRATOR_RETENTION_DAYS` ago (default `90`, `0` disables it) with their
observables, findings, qualified evidence, alert cases, alerts and queued
deliveries. A
`daily_reports/<date>` directory is deleted once its whole day is older than the
cutoff and no remaining run started that day, so a kept run never loses its
report or manifest. The delta memory (`seen_observables`) is never purged. The default is operational, not a legal retention period: when reports
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
| `alert_cases` | `state` | Alert cases waiting for an operator (`open`, `acknowledged`) |
| `alert_case_time_to_acknowledge_seconds` | — | Histogram: seconds from a case opening to its acknowledgement |
| `evidence_chain_verify_total` | `target_id`, `outcome` | Evidence-chain verifications by outcome (`ok`, `broken`, `error`) |
| `evidence_qualified_total` | `target_id`, `category` | Qualified evidence rows by category (`adverse_media`, `sanctions`, `litigation`, `regulatory_action`, `corporate_profile`, `unrelated`) |
| `scheduled_jobs` | — | Target cron jobs registered in the scheduler (the retention and retry workers are not counted) |
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

### Dashboard smoke checks

`/console` is the UI's production entry point. The Docker images build the React
dashboard (`ui/`) in a Node stage and copy the output to
`orchestrator/static/ui-dist`; a source checkout without that directory gets a
`503` page from `/console` with the build steps. To run the dashboard from a
checkout:

```bash
cd ui && npm ci && npm run build && cd ..
mkdir -p orchestrator/static && rm -rf orchestrator/static/ui-dist
cp -r ui/dist orchestrator/static/ui-dist
```

Run the CI-safe smoke suites before every release:

```bash
pytest tests/unit/test_operator_console.py -v
cd ui && npm run lint && npm run test:run && npm run build
```

The Python suite covers the shell contract: `/console` is reachable without a
key, protected API calls still answer `401`, the dashboard build is served with
a `script-src 'self'` CSP and immutable assets, and a missing build answers
`503` without a script. The UI suite covers the operator journey against a
mocked API (key prompt on `401`, key validation and storage, navigation,
filters, run detail, handoff), the Spanish/English catalogue, and an axe-core
accessibility check of every main view.

### Handover actions

Every run detail ends with a **Handoff** block, the place where an analyst
closes a review and passes the run on:

| Action | What it does | Backed by |
| --- | --- | --- |
| Verify evidence chain | Re-hashes every sealed run of the target and checks the signatures; shows the first broken run with a link | `GET /targets/{id}/chain/verify` |
| Download signed bundle | One `.zip` with the run directory: report, STIX bundle, delta, qualified evidence, PDF and `manifest.json`. The recipient recomputes the SHA-256 of each file against the manifest and checks the HMAC with the deployment's `ORCHESTRATOR_SECRET_KEY` | `GET /runs/{id}/bundle` |
| Download PDF report | The human-ready copy of the report | `GET /runs/{id}/report.pdf` |
| Copy handoff summary | Plain text for a ticket or an e-mail: target, run, status, timing, risk level, new observables, evidence counts, manifest hash, chain result of this session and the dashboard link. Falls back to a text box when the browser has no clipboard | run records already loaded |
| Start follow-up run | Triggers a new run of the same target; refused while one is active | `POST /targets/{id}/run` |
| Alerts dispatched | Channel, status, time and error of every alert the run sent | `alerts[]` of `GET /runs/{id}` |

The evidence tab offers *Continue to the report* and *Prepare handoff* so the
path from review to output never leaves the page.

### Frontend telemetry and error tracking

The dashboard logs browser-side events to the developer console with structured
context (`event`, `path`, `language`, `message`, `stack`). This is intentionally
low-volume and bounded: the last 25 events are retained in memory for the active
page and every error is stamped with enough detail to distinguish auth issues,
API failures and unhandled client exceptions without exposing raw API keys.

### Incident triage and rollback

| Signal | Likely cause | Immediate action |
| --- | --- | --- |
| `/console` loads but all data calls return `401` | API key missing or stale | Verify the stored key, clear/re-enter it, check the service's `ORCHESTRATOR_API_KEY` value |
| A view shows "Something went wrong" with *Try again* | Frontend regression or malformed API payload in that view (the shell keeps working) | Try again or open another view; in the browser console inspect the last `ui-telemetry` events (`ui_error`, `error_boundary_triggered`) and compare them with the failing route and payload |
| `/console` answers `503` | The image or checkout has no dashboard build | Build `ui/` and copy `ui/dist` to `orchestrator/static/ui-dist` (the Docker images do this in their Node stage) |
| `/console/assets/*` fails to load | Deployment problem or CSP regression | Confirm the page loads with the `script-src 'self'` CSP and the hashed asset is served with `200` and an immutable cache header |
| Data loads but a target or run view is empty | API/auth issue or empty database | Check `/targets`, `/runs` and `/analytics/risk-trends` with the same key; if empty, verify scheduler and database state |

Rollback steps:

1. Stop the change by reverting the release commit or image tag.
2. Restore the previous deployment and confirm that the prior API key and
   ingress/auth settings still match the running service.
3. Re-run the dashboard smoke checks and verify the shell and data endpoints
   work before reopening traffic.
4. Capture the browser console telemetry and the failing API response in the
   incident log so the underlying cause is fixed before a new rollout.

## Threat model

The repository carries an OWASP pytm model of this architecture
(`scripts/threat_model.py`) and its generated report
(`docs/threat-model.md`). The model mirrors `docs/architecture.md`, the ADRs,
the compose files and the Dockerfiles: four trust boundaries (public internet,
optional OIDC edge, compose network, OpenCTI platform), the orchestrator, its
sidecars, the vendor services it talks to (Tavily, the cloud LLM, Keycloak,
oauth2-proxy, OpenCTI and its MISP connector, the alert webhook and SMTP
relay), the data stores and every flow with its protocol, TLS version and the
credentials it carries. Each component asserts only the controls its own code
or image ships: the orchestrator's validation, CSP or non-root user never
count for a sidecar or a vendor service. Each endpoint declares the protocol
it serves and the highest classification it is entrusted with, and each flow
what its transport may carry, so pytm's data-leak rules fire only on the
transfers the model means to flag: the target name reaching a public source,
credentials crossing the host boundary in clear.

pytm is a modelling tool, not a runtime dependency: it lives in a throwaway
virtualenv, pinned, and never in `pyproject.toml`.

    python3 -m venv .venv-pytm
    .venv-pytm/bin/pip install pytm==1.4.0
    .venv-pytm/bin/python scripts/threat_model.py

The script resolves the 114-threat library against the model and writes
`docs/threat-model.md`. Two checks make it fail instead of writing a report
with a gap in it:

- **Every finding needs a response for its threat and element class**
  (orchestrator, sidecar, vendor, store or flow), or an explicit
  `(element, threat)` override. The response is `mitigated` (a control of that
  element, cited), `transferred` (vendor or upstream code consumed as shipped)
  or `accepted` (a documented decision with its production hardening note).
- **Every `(threat, element)` pair must be listed in
  `scripts/threat_model_findings.txt`.** A pair that appears (a new element,
  a new flow, a control removed) or vanishes fails the run until a reviewer
  runs `scripts/threat_model.py --accept`, which rewrites the ledger; its diff
  is reviewed with the pull request.

Regenerate the report after changing the model, the architecture or a triage
rationale, and review the diff: an accepted finding is a decision on record,
never a silence. The accepted set is deliberate — plaintext host-internal
flows and stores on a single trusted host (ADR-005), the shipped OIDC overlay
without TLS termination, static API keys and tokens (ADR-005), the
loopback-only unauthenticated sidecars, the unsigned webhook by default, and
the residual risk that a schema-valid model reply skews a risk level — each
with the hardening step a shared-infrastructure deployment must add.

## Release checklist and support SOP

A release is a `vX.Y.Z` tag on `main`: the image workflow publishes
`ghcr.io/careb36/osint-orchestrator-oss:X.Y.Z` and `:latest`, and the release
workflow creates the GitHub Release from that version's `CHANGELOG.md`
section. Before tagging, confirm all of the following against a deployment of
the release candidate (`docker compose --profile opencti up -d --build` from
the commit, with `OPENCTI_ENABLED=true`):

- [ ] CI is green on the commit (lint, unit tests, dashboard, Helm chart,
      public-release guard, image build with the vulnerability scan)
- [ ] `GET /ready` answers 200 and `docker compose ps` shows no `unhealthy`
      service
- [ ] `ORCHESTRATOR_API_KEY=… pytest tests/integration -m integration` passes
      against the running stack
- [ ] A manual run of one target reaches `success`, its report and manifest
      download, and `GET /targets/{id}/chain/verify` answers `ok: true`
- [ ] `CHANGELOG.md` has the `## [X.Y.Z] - YYYY-MM-DD` section (the release
      workflow refuses a tag without it) and `pyproject.toml` /
      `deploy/helm/osint-orchestrator/Chart.yaml` carry the same version

Before a UI release, also confirm:

- [ ] The dashboard smoke checks pass in CI (`pytest tests/unit/test_operator_console.py -v` and the `frontend` job)
- [ ] CSP and X-Content-Type-Options hardening remain intact for the shell
- [ ] Error telemetry includes `event`, `path`, `message`, and a stack when available
- [ ] A stale or missing API key is clearly surfaced to the operator and the key remains in session storage only
- [ ] The release notes mention any API contract or auth changes that affect dashboard users
- [ ] A rollback plan and owner are recorded for the release window

Support SOP:

- Check the browser's developer console first for `ui-telemetry` events; they
  isolate browser regressions from backend run failures.
- If the backend API is healthy but the UI is not, verify the browser is not
  holding a stale key and that the CSP still matches the new shell.
- If the issue is systemic, revert to the last known-good image, restore the
  previous config, re-run the smoke checks, and document which telemetry event
  triggered the incident.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| Elasticsearch exits seconds after `docker compose --profile opencti up` | `vm.max_map_count` below 262144 on the host |
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
| A run finishes with no finding / `synthesis_total{status="failed"}` grows | The LLM endpoint is unreachable. Targets default to `llm: local`, which is Ollama, and compose ships no Ollama service: point `LLM_BASE_URL` at one, or set the target's `llm` to a cloud provider and configure its key. `LLM_PROVIDER` alone does not move a target off Ollama |
| Synthesis always unavailable | Check startup logs for `LLM model not served by provider` and `osint_orchestrator_llm_model_available{...} == 0`; switch to an id listed by the provider `GET /models` |
| Browser login loops or `502` on `:8002` with the auth overlay | Keycloak not healthy yet, or `AUTH_PROXY_PORT`/`AUTH_REDIRECT_URL` disagree — both must use the same port (`.env.example` ships 8002) |
| `osint_orchestrator_scheduled_jobs` is lower than expected | A target is `enabled: false`, or its `cron` is not five fields — both are skipped, the second with an `ERROR` log |
| `osint_orchestrator_scheduled_jobs` is 0 | `targets.yaml` was not found at `TARGETS_FILE` when the app started (a `WARNING` names the path) |
| A changed `cron` has no effect | Cron jobs are registered at startup; apply edits with `POST /scheduler/reload` |
