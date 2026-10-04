# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project is pre-1.0 and does not publish semver tags yet; entries are
grouped by date and development phase. Security fixes are cross-referenced
from [SECURITY.md](SECURITY.md).

## [Unreleased]

### Added

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

- MISP services moved to the `docker-compose.misp.yml` overlay
  (`-f docker-compose.yml -f docker-compose.misp.yml --profile misp`): Compose
  interpolates every service of the files it loads, so the required MISP
  variables blocked `docker compose up` on installs without MISP.

### Removed

- Dead `SPIDERFOOT_CORRELATION` key from `.env.example` (read by nothing).

### Fixed

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
  rows use the data in column 1 (HTML-unescaped) and the type in the last
  column. Default `SPIDERFOOT_MODULES` uses real module names
  (`sfp_dnsresolve,sfp_whois,sfp_sslcert`; `sfp_dns`/`sfp_ssl` do not exist).
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
