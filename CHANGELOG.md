# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project is pre-1.0 and does not publish semver tags yet; entries are
grouped by date and development phase. Security fixes are cross-referenced
from [SECURITY.md](SECURITY.md).

## [Unreleased]

### Added

- `GET /ready`: readiness probe that answers 503 while the database is
  offline or the scheduler is not running, and 200 otherwise, with the same
  body as `/health`. The compose healthcheck and the Helm readiness and
  startup probes use it; `/health` stays a liveness check that always answers
  200.

- Dashboard resilience and performance pass: the routed views sit inside an
  error boundary keyed by the route, whose fallback offers *Try again* and
  *Back to the overview* and which resets on navigation, so one crashed view
  never takes the shell down; views are code-split and loaded on demand with
  the libraries in two long-cached vendor chunks; the smoke test walks the
  analyst path and fails on any `console.error` or UI error event. The DoD
  (`ui/docs/dod.md`) records the state of every phase and `ui/docs/kpis.md`
  the scorecard the current telemetry allows.
- Run history with transitions: `GET /runs` and `GET /runs/{id}` carry the
  `risk_level` of the run's finding; the runs view and the target detail show
  the risk of each run and what changed since the target's previous run
  (status, risk up or down), the runs view sorts by risk, and the target
  detail opens with a timeline of its runs, oldest first.
- Run handoff: `GET /runs/{id}/bundle` (the run directory with its signed
  `manifest.json` as one zip, verifiable offline) and `GET /runs/{id}/report.pdf`;
  the dashboard's run detail gains a Handoff block that verifies the target's
  evidence chain, downloads the bundle or the PDF, copies a plain-text handoff
  summary, starts a follow-up run and lists the alerts the run dispatched, and
  the evidence tab leads to the report and to the handoff.
- Operator dashboard foundation (`ui/`): the React app is built in a Node
  stage of both Dockerfiles and served by the orchestrator at `/console`
  (client routes, `/console/assets/*` with immutable caching,
  `script-src 'self'` CSP). Access uses the API key as every other client does
  (ADR-005): the mock login and roles are gone. New CI job `frontend` (lint,
  tests, build, inline-script check).
- Dashboard overview (`/console`): key figures computed from the API (active
  runs, runs in 24 h, success rate, median run time as task completion time,
  targets at high or critical risk, 7-day coverage), targets ordered by
  attention with latest and peak risk from `/analytics/risk-trends` and a
  Start-run action, active runs with elapsed time that refresh themselves,
  the findings of the latest runs, and empty states for each block.
- Dashboard in Spanish and English (`ui/src/i18n.tsx`): every operator-facing
  string of the React app carries both languages, checked by a catalogue
  test like the backend's; the stored choice wins, then a supported browser
  language, then Spanish (ADR-004). A language switcher in the top bar
  persists the choice; dates follow the locale; persisted identifiers (run
  status, risk, relevance) keep their English value in the data and get a
  display label. Accessibility smoke tests with axe-core (WCAG 2.1 A/AA and
  best-practice rules, colour contrast excluded in jsdom) cover the overview,
  targets, runs, target and run detail, the key gate and the not-found view.
- Dashboard triage controls: search, filters and sortable columns on the
  targets view (text, enabled flag, last-run status, risk), on the runs view
  (text, target, status, started within 24 h or 7 days) and on a run's
  evidence (text, relevance, category) and observables (text, type); the
  state lives in the URL query string so a filtered view survives a reload
  and can be shared. Target detail gains the risk trend and a Start-run
  action; a running run shows a distinct in-progress cue and its elapsed
  time.
- Evidence qualification on the fast LLM route (`LLM_QUALIFY_ENABLED`,
  `LLM_QUALIFY_MAX_ITEMS`): each Tavily result is classified (category,
  relevance, confidence, rationale) against the entity under review, stored in
  `evidence_qualifications` (migration `0006`), written to
  `qualified_evidence.json` under the signed manifest, labelled on its STIX
  Note, listed in the report and served by `GET /runs/{id}/evidence`; high and
  medium items are passed to the synthesis, which must cite their URLs.
- Evidence chain (ADR-007): every run writes a signed `manifest.json` (artefact
  SHA-256s, HMAC-SHA256 with `ORCHESTRATOR_SECRET_KEY`) chained to the previous
  sealed run of the target; `runs.manifest_sha256` (migration `0005`);
  `GET /runs/{id}/manifest`, `GET /targets/{id}/chain/verify` and the metric
  `evidence_chain_verify_total`. Retention-purged runs anchor the chain instead
  of reading as tampering. An empty or default signing key logs a WARNING.
- Tavily web-research collector (opt-in, `collectors.tavily`): three
  due-diligence queries per run that search the target's domain as a quoted
  term, `url` observables and one STIX Note per distinct page, wall-clock
  budget with bounded retries, `TAVILY_*` settings, bilingual README sections.
- Public-release guard: `scripts/check_public_release.sh` fails on forbidden
  references (specific public bodies, official portals) and on gitleaks
  findings; CI runs it on every push and PR. New *Public release guard* and
  *Responsible use* sections in `CONTRIBUTING.md` / `CONTRIBUTING.es.md`.
- OWASP Amass v5 collector (opt-in, `collectors.amass`): engine sidecar
  (`--profile amass`, official image pinned to v5.1.1), `oam_enum`/`oam_subs`
  clients in the orchestrator image, names and addresses normalised to STIX
  `domain-name`/`ipv4-addr`/`ipv6-addr` with `resolves-to`/`related-to`
  relationships, `AMASS_*` settings, `amass/` engine configuration and
  bilingual README sections.
- Optional OIDC front door: Keycloak + oauth2-proxy compose overlay
  (`--profile auth`), ADR-006, health-gated startup order.
- Bilingual executive project presentation for management/AML audiences
  (`docs/business/`), `CONTRIBUTING.md`, `SECURITY.md`, this changelog and a
  documentation index (`docs/README.md`).

### Changed

- Documentation restructured ([ADR-009](docs/adr/ADR-009-documentation-language.md)):
  the README is a short overview in English and Spanish; reference material
  moved to `docs/architecture.md`, `docs/configuration.md` and
  `docs/operations.md` (English). Removed: the Spanish companions of the ADRs,
  `CONTRIBUTING` and `SECURITY`, the business presentations with their PDF
  script, `docs/README.md` and `docs/socialosint.md`. The settings table
  checked by `tests/unit/test_env_coverage.py` is now `docs/configuration.md`.
- `TAVILY_MAX_RESULTS` (1–20) and `TAVILY_MAX_CALLS_PER_RUN` (0–20) are
  validated at startup; an out-of-range value that was previously clamped
  now stops the service with a configuration error. `0` calls skips the
  collector for every target.
- A partial `socialosint:`, `amass:` or `tavily:` block in `targets.yaml`
  (for example `amass: {enabled: true}`) now inherits the collector's global
  timeout (`SOCIALOSINT_TIMEOUT_SECONDS`, `AMASS_TIMEOUT_SECONDS`,
  `TAVILY_TIMEOUT_SECONDS`) instead of the generic 600 s.
- Executive presentation (EN/ES): the regulatory-context section now describes
  the supervisory and financial-intelligence bodies generically instead of
  naming them, and no longer links to government portals.
- The orchestrator service publishes host port 8000 directly; the auth
  overlay front door defaults to 8002 (`AUTH_PROXY_PORT`), no longer 8001
  (which collides with the `socialosint` service).
- READMEs EN/ES re-synced: quick-start services list, SpiderFoot build
  provenance, missing LLM/Ollama caveat, `GET /` endpoint, SocialOSINT field
  reference.
- `GET /runs/{id}/finding` now returns `new_since_last_run` and
  `suggested_pivots` as JSON arrays (`list[str]`) instead of JSON-encoded
  strings. Clients that were calling `json.loads` on those fields must stop
  doing so.

- MISP services moved to the `docker-compose.misp.yml` overlay
  (`-f docker-compose.yml -f docker-compose.misp.yml --profile misp`): Compose
  interpolates every service of the files it loads, so the required MISP
  variables blocked `docker compose up` on installs without MISP.
  `MISP_SSL`, `MISP_SSL_VERIFY`, `MISP_IMPORT_ONLY_PUBLISHED` and
  `MISP_IMPORT_TO_IDS_NO_SCORE` from `.env` now reach the connector (same
  defaults: false/false/false/40); they were hardcoded before. Production with
  a real certificate needs both `MISP_SSL=true` and `MISP_SSL_VERIFY=true`.
- `OPENCTI_ADMIN_PASSWORD` and `OPENCTI_ADMIN_TOKEN` are required (`:?`):
  with the template comments no longer leaking into the values, a blank one
  would otherwise boot OpenCTI with empty admin credentials.

### Removed

- Startup detection of databases created before Alembic (app tables present,
  no `alembic_version`), which stamped them at the baseline revision; every
  database now starts from the migrations. The daily report index no longer
  parses its pre-Phase-3 four-column rows.
- Demo mode: `DEMO_MODE` and the other `DEMO_*` settings, the public `/demo`
  page and routes, `Dockerfile.demo`, `docker-compose.demo.yml`, the allowlist
  and seed files under `demo/`, `scripts/export_demo_seed.py` and the daily
  Tavily and LLM call budgets. The orchestrator ships as one product, the API
  with the operator dashboard; migration `0008` drops the `demo_daily_usage`
  counters.
- The server-rendered operator console (`orchestrator/templates/console.html`)
  and its routes `/console/legacy` and `/console/i18n.json`: the React
  dashboard covers every view it had (health, risk, runs, run detail with
  evidence search, filters and sort, artefact download) in both languages.
  Without a dashboard build `/console` now answers `503` with the build steps
  instead of falling back; the Docker images always ship the build.
- Dead `SPIDERFOOT_CORRELATION` key from `.env.example` (read by nothing).

### Fixed

- Installs declare `sqlalchemy[asyncio]`: recent SQLAlchemy releases stopped
  pulling in `greenlet`, so a fresh `pip install` (CI, the Docker image) could
  not import the async engine and every test and container start failed.

- A deployment with `OPENCTI_ENABLED=false` no longer stays `unhealthy`: the
  compose healthcheck required `/health` to report `ok`, and a disabled sink
  reported `degraded`. The `opencti` check now reads `disabled`, which does
  not lower the overall status (ADR-008), and the healthcheck polls `/ready`.
- Security: model and internet-derived text is made inert more thoroughly.
  HTML tags are stripped until none is left, so a tag re-formed by removing
  an inner one (`<scr<b>ipt>`) or hidden behind a `<` in an attribute goes
  too, and an unterminated tag cannot open one; setext headings, thematic
  breaks and bare `www.` links are escaped like ATX headings and `http(s)`
  already were. The synthesizer's fallback finding and its repair prompt
  quote the validation error, which quotes the model's own reply, as one
  inert, bounded line, and two invalid replies now count as a `failed`
  synthesis instead of `ok`.
- The integration tests (`tests/integration/test_e2e.py`) send
  `ORCHESTRATOR_API_KEY` to the protected routes and assert the `401` without
  it; since the API key landed (ADR-005) they had been failing against a
  running stack. OpenCTI's health probe also accepts a `401` as reachable.
- A run keeps `running` until it is sealed (ADR-007). The final status was
  written before synthesis, the report and the manifest, so a second run of
  the same target was admitted meanwhile; whichever sealed last pointed to the
  wrong predecessor and `chain/verify` reported a false `chain_link` break. An
  error after sealing no longer turns a final status into `failed`; it is
  appended to the run's error instead.
- Retention no longer deletes the `daily_reports/<date>` directory of a run it
  keeps. Rows expire by their exact `finished_at` and directories went by date
  alone, so every purge removed the report and manifest of the cutoff day's
  later runs (404 on `/runs/{id}/report`, `manifest_missing` on
  `chain/verify`). Only whole days before the cutoff that no remaining run
  points to are deleted, and none when the remaining runs cannot be read.
- Retention purges `evidence_qualifications` with the runs they belong to; the
  qualified URLs and rationales were kept forever.
- Evidence qualification asks once more for the items an answer left out and
  uses batches of 5: live, a 10-item answer was truncated and none of its items
  were qualified.
- `.env.example`: blank values no longer carry an inline comment. Compose's
  env_file parser took the comment as the value, so a copied template set
  e.g. `TAVILY_INCLUDE_DOMAINS` to the comment text (every Tavily query
  failed), `LLM_MODEL_REASONING`/`LLM_MODEL_FAST` to a non-existent model and
  the MISP passwords to a public string. A unit test now rejects the pattern.
- Docker image installs the new `llm` extra (`openai`, `anthropic`): the
  cloud synthesis providers (`openai`, `nebius`, `anthropic`) failed every
  call with "package is not installed".
- SpiderFoot collector speaks the SpiderFoot 4 API: `/startscan` is asked for
  JSON (it answered 303 before), the scan id is read from
  `["SUCCESS", id]`, the status from column 5 of `/scanstatus`, and event
  rows use the data in column 1 (HTML-unescaped) and the type from any column
  holding a mapped event type, else the last column (SpiderFoot 4's layout).
  Rows it cannot read, including dict rows without a string `type`, are
  counted in one warning instead of silently mapping nothing. Default
  `SPIDERFOOT_MODULES` uses real module names
  (`sfp_dnsresolve,sfp_whois,sfp_sslcert`; `sfp_dns`/`sfp_ssl` do not exist).
- Each run writes its artefacts to its own directory,
  `daily_reports/<date>/<target>/run-<run_id>/`. All runs of a target on the
  same day shared one directory, so a later run overwrote `report.md`,
  `bundle.stix.json` and `delta.json` of the earlier ones and
  `GET /runs/{id}/report` returned the latest run's report for every run of
  that day. The daily `index.md` links the target's latest run directory.
  Existing directories are not migrated; their runs keep pointing at the
  shared files.
- SpiderFoot event mapping: `NETBLOCK_OWNER` carries a CIDR block and now
  maps to `ipv4-addr` (`NETBLOCKV6_OWNER` to `ipv6-addr`) instead of
  `autonomous-system`, where every netblock became AS0; `BGP_AS_MEMBER` is
  mapped. One validation policy for both row layouts: AS numbers must be
  1..2**32-1, IP values must parse as an address or CIDR of the right family,
  and unusable values are counted as unreadable instead of ingested.
- `pycti` pinned to `6.8.11`, the `opencti/platform` tag: the open `>=6.2.0`
  range resolved to pycti 7.x, whose `x_opencti_modified_at` input the 6.8
  platform rejects, so every STIX Note (Tavily pages) failed to ingest. The
  image now installs `libmagic1`, which pycti 6.x needs at import time.

## 2026-09-14

### Fixed

- MISP Redis runtime configuration: dedicated `misp-redis`, explicit
  `REDIS_HOST`, empty-password handling in the derived v2.4.198 image.

### Added

- Development efficiency tooling documentation (ADHD Mode, Aider, context
  mode, pi-subagents) (#59).

## 2026-09-13

### Added

- Operator console: minimal read-only web UI (`GET /console`), full ES/EN
  copy, accessibility pass, session-only API-key handling with explicit
  opt-in "remember in this browser".
- Per-target risk trend view (`GET /analytics/risk-trends`).
- OpenCTI outbox: failed bundles persist in `opencti_outbox` and drain via a
  durable retry worker; runs degrade to `partial` instead of losing data.
- Reliable alerts: retry queue with exponential backoff and jitter, DLQ
  status and `POST /alerts/dlq/replay`.
- Versioned collector contract (`CollectorResult` v1.0) with compatibility
  guard tests.
- Target freshness metric `target_last_success_timestamp_seconds` for
  operational SLOs (#49).
- Scheduler preview endpoint `POST /scheduler/reload/preview` and per-target
  run guard (#48); runtime scheduler reload `POST /scheduler/reload` (#30).

## 2026-09-11

### Added

- Phase 4b: real MISP stack (`--profile misp`: MariaDB, dedicated Redis,
  misp-modules, misp-core) + official `connector-misp`; SocialOSINT HTTP
  collector (opt-in per target) (#14).
- Retention: nightly purge of old runs and `daily_reports/` directories
  (`ORCHESTRATOR_RETENTION_DAYS`, `ORCHESTRATOR_RETENTION_CRON`) (#16).
- Alembic schema migrations replacing manual `ALTER TABLE` patches; existing
  databases are auto-stamped at baseline (#17, #19).
- Transient-only OpenCTI ingest retry with exponential backoff, off the
  event loop (#20).

### Fixed

- Batched `IN()` deletes and `shutil.rmtree` in retention; warning on invalid
  target; async connection closed before stamping.

## 2026-09-08

### Added

- Phase 5: API-key authentication (`X-API-Key` / `Bearer`, constant-time
  comparison, multi-key rotation), JSON logs with request ids, Prometheus
  `GET /metrics`, Helm chart for single-instance deployment (ADR-005).
- Phase 4a: webhook + email (SMTP) alerts with HMAC-SHA256 payload signing,
  per-target dispatch rules, ingested-observable delta semantics (#8), DB-based
  `GET /runs/{id}/delta` (#10).
- Phase 3: LLM synthesis (Ollama / Anthropic / OpenAI-compatible providers),
  prompts, `FindingRecord`, synthesis status in runs and reports.
- Phase 2 finalisation: daily `index.md` executive summary, optional
  best-effort `report.pdf` via fpdf2.

### Changed

- `openosint` dependency pinned by full 40-character commit SHA.

## 2026-09-04

### Added

- Phase 1: in-process OpenOSINT collector via `investigate()`, STIX 2.1
  normalizer with deterministic ids, OpenCTI ingest through pycti; native
  OpenCTI `Phone-Number` observable.
- ADR-004 language policy: Spanish for operators, English for code; `i18n.py`
  message catalogue with `es`/`en` completeness tests.
- Spanish README and ADR translations.

## 2026-09-03 and earlier

### Added

- Phase 0: repository skeleton, ADR-001–003, `pyproject.toml`, CI (ruff,
  pytest, helm lint), docker-compose stack, `GET /health`.

[Unreleased]: https://github.com/careb36/osint-orchestrator-oss/commits/main
