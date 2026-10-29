# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project is pre-1.0 and does not publish semver tags yet; entries are
grouped by date and development phase. Security fixes are cross-referenced
from [SECURITY.md](SECURITY.md).

## [Unreleased]

### Fixed

- The MISP image could not be built: `.dockerignore` excluded `deploy/` while
  `Dockerfile.misp` copies its two entrypoints from `deploy/misp`, so the build
  stopped at `entrypoint_fpm.sh: not found`. Nothing built that Dockerfile, so
  the breakage was invisible until now.

- `Dockerfile.socialosint` ships the transitive packages with published CVEs
  pinned instead of whatever the upstream requirements resolve to: 43 fixable
  CRITICAL/HIGH findings became 1. Most of them were the `wheel` and
  `jaraco.context` copies vendored inside `setuptools/_vendor`, so bumping
  setuptools is what removed them; upgrading those two on their own left the
  vulnerable files in the image. The remaining HIGH (`oauthlib`) is accepted
  in `.trivyignore` with an expiry date and a recorded reason: the vulnerable
  code is oauthlib's authorization-server half and this image only ever acts
  as an OAuth client, so it cannot fire. Upgrading it is separately blocked by
  `tweepy`'s `oauthlib<4` requirement.

### Added

- CI builds and scans `Dockerfile.misp` and `Dockerfile.socialosint`. Both are
  opt-in compose profiles that no workflow touched, so Trivy only ever saw the
  orchestrator image. The SocialOSINT scan is blocking now that the image is
  clean; the MISP one is advisory because its newest base tag still ships
  `jmespath` 2.8.0 (CVE-2026-54133, fixed in 2.9.1) and no tag carries the fix.

### Changed

- Publishing an image is now gated by the event, not only by the ref. Any event
  that was not a pull request used to push, so a `workflow_dispatch` from a
  feature branch published `:<branch>` and `:sha-<short>` to GHCR. Only a
  `workflow_run` (main, already gated on CI success) and a `v*` tag push
  publish; a pull request, a scheduled run and a manual dispatch build without
  pushing. The header comment claimed "manual dispatch -> :sha only", which was
  not what the file did.
- The optional-image scan now also runs monthly, so an expired `.trivyignore`
  acceptance turns into a red scheduled run on the first of the month instead
  of waiting for a pull request that happens to touch those images. The
  scheduled run scans only and never publishes an image. When it fails it
  opens an issue (reusing the existing one) so the failure is not left on the
  Actions tab.
- CI runs on the self-hosted runner while GitHub-hosted minutes are exhausted.
  Every workflow takes its runner from the repository variable `CI_RUNS_ON`;
  unset, a private repository uses the runner labelled `osint` and a public
  one `ubuntu-latest`. A new push to a pull request cancels the run it
  replaces. Python 3.11 comes from a pinned uv release instead of
  setup-python, and nothing is written outside `RUNNER_TEMP`: gitleaks, the
  venv, the migration check database and the Helm renders. See *CI runner* in
  CONTRIBUTING.md.

- The daily report reads in the order a reviewer needs it: synthesis (risk
  label with its code, what changed since the previous run, suggested pivots)
  first, then the qualified evidence, then the new observables, then errors,
  and only after that a technical annex with the collector status, the full
  inventory with STIX identifiers and the relationships rendered as values
  (`example.com -> 1.2.3.4`) with the identifiers beside them. A closing
  "document data" block names the software version, the provider and model
  that wrote the assessment, and states that the generated text is not an
  opinion and must be validated by the compliance officer.
- Stable identifiers are shown as labels wherever an operator reads them:
  `orchestrator/i18n.py` gains `tv()` and a value catalogue (run status,
  risk level, evidence category and relevance, collector outcome, STIX
  types and relationship types, both languages), used by the report, the
  daily index and the alert e-mail (`riesgo alto` instead of `riesgo high`,
  `Estado: exitosa (success)`; the code stays next to the label, so mail
  rules matching `high` keep working). Relevance uses its own feminine
  labels in Spanish (alta, media, baja). The daily index writes
  `label (\`code\`)` and re-renders earlier rows from their codes, so targets
  reporting in different languages no longer mix languages in one file.
  Evidence confidence is printed as a percentage with a note on what it is.
  The persisted identifiers do not change (ADR-004).
- Report and alert e-mail dates are printed in the operator's time zone with
  the UTC instant beside them (`25/10/2026 00:20 -03 (2026-10-25T03:20:06Z)`,
  `orchestrator/timefmt.py`); report directories stay named by the UTC day;
  new setting
  `ORCHESTRATOR_TIMEZONE` (IANA name, default `UTC`, unknown names fall back
  to UTC with a warning). `Finding` carries `provider` and `model` so the
  report can name them; `orchestrator.__version__` is the single source of
  the version string (`api.VERSION` reads it).

- Tavily collector: two more query templates per language look for the
  record itself rather than the news cycle: a criminal conviction or
  prosecution (money laundering, fraud) and administrative sanctions (fines,
  disqualification, proceedings). The default call budget
  (`max_calls_per_run`, `TAVILY_MAX_CALLS_PER_RUN` and the Helm chart's
  `config.tavily.maxCallsPerRun`) rises from 3 to 5 so a single-term target
  still covers every template; a single-term run now spends five Tavily
  searches instead of three. Upgrade note: an `.env` copied from an earlier
  `.env.example` still sets `TAVILY_MAX_CALLS_PER_RUN=3` and keeps capping
  runs at three queries; raise it to 5. A unit test pins that no request
  carries a recency filter (`topic`, `days`, `time_range`): a due-diligence
  search looks back as far as the sources go.

- Retention is off by default: `ORCHESTRATOR_RETENTION_DAYS` is now `0` in
  `config.py`, `.env.example` and the Helm values (it was `90`). Runs, reports,
  findings, qualified evidence and alert cases are the evidence a compliance
  file is built on, and record-keeping rules count their retention in years,
  so a fresh deployment no longer deletes anything on its own. When an
  operator does set a period, each target keeps its first run that met an
  alert rule (the alert case is where the review is recorded) and every run
  after it, so the purged runs are always a contiguous prefix of the
  target's evidence chain and `chain/verify` keeps reporting it intact;
  a purged run's own `run-<id>` directory is removed even when its day
  directory stays. The purge summary reports `runs_retained_protected`
  instead of `alert_cases_deleted`, which is now always zero.

### Fixed

- `report.pdf` is legible again. The previous renderer cut every line into
  40-character chunks and drew every second chunk past the right edge of the
  page, so the download the console offers as "report in PDF" came out as
  near-blank pages with truncated text. `orchestrator/reports/pdf.py` now
  renders the report's Markdown subset (headings, bullets, pipe tables,
  links, paragraphs) as a paged A4 document: text flows between the margins,
  overlong URLs and STIX ids wrap character-wise, tables keep their header,
  links keep their URL on paper, and every page carries a footer with the
  page number in the report language. Core Helvetica covers Latin-1; a few
  common characters outside it (dashes, ellipsis, arrows, curly quotes) are
  transliterated and anything else degrades to `?` instead of aborting.
  A table cell is capped at 900 characters so one row always fits on a
  page (fpdf2 refuses taller rows; a 3,000-character URL or collector error
  used to cost the whole PDF); the footer text comes from `orchestrator/i18n.py`.

### Added

- Personal accounts with revocable HttpOnly sessions, accountant/administrator
  permissions, local administrator provisioning and password/session controls.
- Professional dossiers with entity identity, reasoned evidence decisions,
  authenticated event history, optimistic revisions and immutable final PDF
  versions with verified source chains and signed snapshots (ADR-012).
- Persisted per-stage outcomes and evidence coverage; runs linked to an alert
  case or cited by a dossier are retained from the oldest of them onward, so
  the purged runs stay a contiguous prefix of the target's evidence chain.
  Historical stages remain explicitly unrecorded.
- A report whose text cannot be drawn losslessly now produces no PDF instead
  of a silently altered one, so the run is recorded as an incomplete report
  rather than sealed with a document that no longer says what the evidence
  says. Qualification errors and missing reports/PDFs/seals remain visible and
  degrade the terminal run outcome.
- Weekly security baseline (`security-baseline.yml`): gitleaks over the full
  history, Semgrep at ERROR severity and a Trivy dependency scan, each pinned
  or checksum-verified and each uploading SARIF as an artifact. It does not
  gate pull requests. The dependency scan resolves the Python tree into a
  `requirements.txt` before scanning, because Trivy reads lockfiles and not
  `pyproject.toml`: without that step it audited only the dashboard's
  `package-lock.json` and reported a clean green over an unaudited Python
  dependency set. The step fails if fewer than 50 packages resolve, so the
  zero-coverage case cannot pass silently again.

- `classification` per target in `targets.yaml`: `osint` (the default; open
  sources only, may go to the cloud provider `llm` names) or `restricted` (an
  investigation that mixes in material that must stay on premises). A
  restricted target requires `llm: local` and cannot enable SocialOSINT (its
  own cloud LLM) or Tavily's `include_answer` (written by Tavily's model); the
  loader rejects the block with the reason named, so the policy no longer
  depends on nobody mistyping the YAML. `GET /targets` adds `processing`,
  where the prompts actually go after `LLM_PROVIDER` (`none`, `ollama` or the
  cloud provider, with the `openai` to Nebius remap applied). The console's
  target card shows the classification (translated) and that processing
  location instead of the bare `llm` value, and the report header carries
  both lines.

- README screenshots (both languages) now show the console after the showcase
  run, served by the real API over a database seeded with the two recordings,
  instead of the unit tests' fixtures; the captions say so.
- The showcase from a fresh clone: `daily_reports/` ships in the repository
  (a `.gitkeep`), so Docker no longer creates the bind mount root-owned on
  the first `docker compose up` and the container (uid 1000) can write the
  reports; both READMEs say what to do when the host user is not uid 1000.
  The image workflow's pull-request smoke now runs `python -m
  orchestrator.showcase` inside the built image and expects two sealed runs.
- README (both languages): the quickstart has three tiers, from no keys to the
  full stack: the showcase run, a real Tavily → Nemotron run with
  `NEBIUS_API_KEY` and `TAVILY_API_KEY` on the `showcase-example` block
  (no SpiderFoot scan, no OpenCTI), and the OpenCTI profile.
- Showcase run: `python -m orchestrator.showcase` replays the two recorded runs
  in `orchestrator/showcase_data/` (a fictitious entity, reserved names only)
  through the real pipeline, so an empty deployment shows finished runs,
  qualified evidence, a finding, a signed and chained manifest and an alert
  case without a collector or an LLM key. The rows say provider `showcase`
  and model `recorded-sample`; the `showcase-example` target in
  `targets.example.yaml` ships disabled. `run_target_pipeline`,
  `_qualification_client` and `synthesize` accept injected collectors and an
  LLM client for it. See docs/operations.md (Showcase run).
- One active run per target is now enforced by the database (migration 0010:
  partial unique index `ux_runs_one_active_per_target` on PENDING and RUNNING
  rows), not only by the in-process lock of `create_pending_run`: a second
  process, such as the showcase command, racing the API loses the INSERT and
  is reported as not admitted. Runs still active when the migration runs are
  failed first, as the startup cleanup would.
- Dashboard: the evidence tab of a run names the provider and model that
  qualified the rows ("Qualified by nebius · nvidia/…"), next to the finding
  that already shows its reasoning model and latency. README screenshots
  regenerated.
- README (both languages): the hackathon table now lists the work merged since the
  first dashboard, from alert cases and the external STIX intake to the threat model.
- investigation-assistant worker (ADR-011, phase 3): `docker-compose.engine.yml`
  adds a one-shot `investigation-engine` service, built from the operator's
  clone of the producer with its own `Dockerfile`, that exports one case
  (`INVESTIGATION_CASE`, default `demo_simulado`) and posts its STIX bundle to
  `POST /bundles` once the orchestrator is healthy. The case corpus is mounted
  read-only and worked on in a tmpfs; the worker's key comes from
  `INVESTIGAR_ORCHESTRATOR_API_KEY` and must be one of the
  `ORCHESTRATOR_API_KEY` values. One command starts orchestrator, OpenCTI and
  the worker; see docs/operations.md.
- External STIX 2.1 intake (ADR-011): `python -m orchestrator.ingest_bundle
  <file> [--work-name …] [--dry-run]` and `POST /bundles` validate a producer's
  bundle against the pinned JSON Schema in `orchestrator/contracts/`, parse it
  with pycti's SCOs registered and hand it to the OpenCTI sink. A failed ingest
  is reported to the producer, not queued: the CLI exits 1 (2 for an unreadable
  bundle) and the endpoint answers 400, 422, 502 or 503 with a localised
  reason. The sink's rejection error now names the first rejected objects by id
  and type. New dependency: `jsonschema`.
- `GET /runs` takes `limit` (1–500, default 100) and `offset` to page through
  runs older than the most recent 100.
- `GET /ready`: readiness probe that answers 503 while the database is
  offline or the scheduler is not running, and 200 otherwise, with the same
  body as `/health`. The compose healthcheck and the Helm readiness and
  startup probes use it; `/health` stays a liveness check that always answers
  200.
- `ORCHESTRATOR_SECRET_KEY_PREVIOUS`: comma-separated keys retired by a
  rotation. `chain/verify` accepts manifests signed with any of them while
  new manifests are signed with `ORCHESTRATOR_SECRET_KEY` only, so rotating
  the signing key no longer turns every earlier run into `signature_key`.
  The rotation procedure is in `docs/operations.md`.
- Release workflow: a `v*` tag creates the GitHub Release with that version's
  `CHANGELOG.md` section as notes (and refuses a tag without one). The image
  workflow scans every pull-request build with Trivy (fixable CRITICAL
  findings block, HIGH ones are reported) and attaches an SBOM to every pushed
  image. CI installs
  the `llm` extra, lints `tests/integration/` too and runs mypy as an advisory
  step. `docs/operations.md` has the backend release checklist.
- Alert cases: every run that meets an alert rule opens a triage item
  (`alert_cases`, migration `0009`) before any channel is tried, so a
  deployment without a webhook or SMTP still has a queue to work and a
  failed delivery never loses the alert. `GET /alerts`, `GET /alerts/{id}`,
  `POST /alerts/{id}/ack` and `POST /alerts/{id}/resolve`; the operator's
  name is free text (ADR-005). New per-target rule `alerts.on_run_failure`.
  Metrics `alert_cases{state}` and `alert_case_time_to_acknowledge_seconds`
  make the time-to-acknowledge KPI measurable. Retention purges cases with
  their run.
- Dashboard *Alerts* view (`/alerts`): the alert cases the backend opens for
  every run that meets a rule, filtered by target and state (open by default),
  sortable, with the reason, risk and run status as cues and Acknowledge /
  Resolve actions recorded with the operator's name (kept per browser). The
  run workspace links to the run's case. Closes the Phase 2 triage item of
  `ui/docs/dod.md`; MTTR joins the KPI scorecard.

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
- `CONTRIBUTING.md`, `SECURITY.md`, this changelog and a documentation index
  (`docs/README.md`) linking every guide and ADR.

### Changed

- README (both languages) shows the operator dashboard: the overview and the
  run workspace with qualified evidence, re-rendered from the showcase replay
  at 1366 px in each language (`docs/img/`), after the dossiers and accounts
  pages joined the console.
- README (both languages) lists all five collectors in the pipeline diagram and
  in a table that says which run by default and which are opt-in per target;
  SocialOSINT was missing from both.
- README (both languages) shows the four `.env` lines and the per-target
  `llm: nebius` that run every target on Token Factory with the two Nemotron
  routes; `.env.example` names the Nemotron models next to `LLM_MODEL_FAST`
  and `LLM_MODEL_REASONING`.
- `targets.yaml` is validated strictly: an unknown key anywhere in a target
  (`enabeld:`, `schedual:`, `modlues:`) makes that target invalid and reported
  instead of silently taking the default, a `misfire_grace_time_seconds` below
  1 is rejected (APScheduler would have aborted the whole registration), and a
  second block with an already used `id` is skipped and reported; the first
  block wins, as the API already resolved it.
- `osint_orchestrator_scheduled_jobs` counts target jobs only; it no longer
  jumps by three on the first reload once the retention and retry workers
  are registered.
- OpenCTI stack moved from `6.8.11` to the long-term line `7.260811.0-lts.1`
  (platform, worker, `connector-import-file-stix`, `connector-opencti`,
  `connector-misp`), with `pycti` pinned to the matching release
  `7.260811.0.1` (an LTS tag `X-lts.N` ships on PyPI as `X.N`; the pin test
  knows the mapping). The platform now needs `OPENCTI_ENCRYPTION_KEY` in
  `.env` (`openssl rand -base64 32`, mandatory since OpenCTI 7.260224.0);
  `compose up` stops when it is blank. pycti 7 no longer imports
  python-magic, so the image drops `libmagic1`. Upgrade steps for a `6.8.11`
  deployment are in `docs/deploy.md`.
- Compose starts only SpiderFoot and the orchestrator by default, with the sink
  disabled in `.env.example`. Existing installs with `OPENCTI_ENABLED=true`
  must now add `--profile opencti` (or set `COMPOSE_PROFILES=opencti` in `.env`)
  to start the OpenCTI stack.
- CI now fails on mypy errors in `orchestrator/`.
- Tests only: the auth-exemption test now covers `/ready`.
- The orchestrator image runs as uid 1000 instead of root (`USER 1000` in
  `Dockerfile`; the Helm chart already ran it that way). The `./daily_reports`
  bind mount must be writable by that uid (`docs/deploy.md`).
- Every compose port binds the loopback interface: OpenCTI (`8080`),
  SpiderFoot (`5001`), SocialOSINT (`8001`), Keycloak (`8085`), oauth2-proxy
  (`8002`) and MISP (`8443`) join the orchestrator on `127.0.0.1`. Reach them
  through an SSH tunnel or your reverse proxy.
- Image pins: `redis:8.0.6`, `rabbitmq:3.13.7-management`, `mariadb:10.11.19`
  (patch releases instead of floating minor tags) and the SpiderFoot build
  context pinned to commit `0f815a2`. A unit test rejects floating tags,
  unpinned git contexts and non-loopback ports in every compose file.
- Helm chart: `config.openctiEnabled`, the cloud model routes
  (`config.llm.modelReasoning` / `modelFast`), `config.tavily.*`,
  `config.retention.*` and `config.alertRetry.*` are chart values instead of
  `extraEnv` entries, and an `extraEnv` entry with the same key still wins, so
  an existing values file renders each key once and needs no migration;
  `NEBIUS_API_KEY` and `TAVILY_API_KEY` have secret slots;
  the release notes point at the dashboard; the README explains the published
  image tags instead of saying none is published.

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

- The OpenCode delegation channel: `.github/workflows/opencode.yml`,
  `opencode.json`, the `/oc` trigger and the local-run fallback. In 625
  workflow runs since it was added, none executed a task (every run was
  skipped by its owner guard or waited for an approval that never came), and
  each PR comment started eight empty check runs. Delegation goes through the
  Copilot coding agent only; `AGENTS.md`, `CONTRIBUTING.md`, the *Agent task*
  issue template and `.claude/rules/workflow.md` describe that one channel.
- `.opencode/skills/ciberseguridad/SKILL.md`, which that retirement left behind
  and nothing could then load. It was the portable copy of a personal skill,
  written for a directory outside this repository, so it named an absolute
  home path, prescribed gates this project does not run (`bandit`,
  `pip-audit`, `make check`, a `SECURITY_TRIAGE.md` of its own) and was in
  Spanish, against [ADR-004](docs/adr/ADR-004-language-policy.md). The project's
  own gates are in `SECURITY.md`, `docs/threat-model.md` and
  `scripts/threat_model.py`. The file stays in history at `74a47e6`.
- Dead settings nothing read: `SPIDERFOOT_TIMEOUT_SECONDS` (the per-target
  `collectors.spiderfoot.timeout_seconds` replaced it), `SYNTHESIS_OPENCTI_CONTEXT`,
  and the `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `CENSYS_API_ID` and
  `CENSYS_API_SECRET` placeholders (the OpenOSINT collector never passed them
  on). Gone from `config.py`, `.env.example`, `docs/configuration.md` and the
  Helm `secrets.values`; a value still set in an existing `.env` is ignored, as
  it already was.
- `ui/PRODUCT_BRIEF.md` (the Phase 1 brief, superseded by `ui/docs/scope.md`)
  and `ui/UX_CHECKLIST.md` (a fully ticked checklist; `ui/docs/dod.md` is the
  live record). The dashboard's unused `@typescript-eslint/eslint-plugin` and
  `@typescript-eslint/parser` dev dependencies (`typescript-eslint` already
  bundles both) and the orphan `handoff.openAlerts` message.
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

- Documentation of LLM provider selection: the per-target `llm` field (default
  `local`, Ollama) chooses the provider, and `LLM_PROVIDER` is a global switch
  (`none` disables synthesis, `nebius` routes `llm: openai` targets to Token
  Factory and selects the startup model check) that never moves a target off
  Ollama. The READMEs, `SECURITY.md`, `docs/configuration.md`,
  `docs/architecture.md`, `docs/deploy.md`, `docs/operations.md`,
  `.env.example`, `targets.example.yaml`, the Helm chart README and values,
  and the comment on the `llm` extra in `pyproject.toml` said or implied
  otherwise. `llm: local` is described as the Ollama server at `LLM_BASE_URL`,
  not as "nothing leaves the host", and the READMEs say that the startup model
  check needs `LLM_PROVIDER=nebius` (or `openai`) and its key.
- `http_request_duration_seconds` and `http_requests_total` are recorded when
  the response is sent, not when the ASGI call returns: a manual run's
  collectors ran inside that call as a background task and charged minutes of
  latency to a 202 served in milliseconds.
- `GET /runs/{id}/report` reads the file instead of checking then reading, so
  a report purged by retention between the two, or a path that is a
  directory, is a 404 rather than a 500.
- The `opencti` and `bundles` tags (`POST /opencti/outbox/replay`,
  `POST /bundles`) are described in the OpenAPI schema; a test now checks
  that every tag in use has a description.
- Installs declare `sqlalchemy[asyncio]`: recent SQLAlchemy releases stopped
  pulling in `greenlet`, so a fresh `pip install` (CI, the Docker image) could
  not import the async engine and every test and container start failed.
- STIX Note ids include the target: the id was derived from the collector
  identity and the note text only, so two targets with the same note ("no
  public results matched the query set") shared one Note that OpenCTI merged.
- Autonomous-system observables without a parseable number are dropped instead
  of becoming `AS0`: every unparseable value ("AS15169 Google LLC", "ASN")
  collided on one STIX id. `AS`, `ASN` and bare numbers are accepted.
- Tavily note segments cannot be forged by a page title or snippet: `|` is
  replaced before the note is assembled, so a title spelling `| url=…` can no
  longer attach another page's qualification labels to its Note.
- SpiderFoot scans the run gives up on (timeout, cancellation, a polling
  error) are stopped with `POST /stopscan`; they kept probing the target on
  the SpiderFoot server, and every scheduled run added another.
- SocialOSINT note text ("analysis, unverified", "platforms skipped") follows
  the target's language through the i18n catalogue instead of being
  hard-coded in Spanish (ADR-004).
- OpenOSINT: an error while mapping the entity graph is reported as a failed
  collector (`graph mapping: …`) instead of escaping `collect()`.
- `GET /targets/{id}/chain/verify` answers 404 for a target that is not in
  `targets.yaml`. The id is a label of `evidence_chain_verify_total`, so any
  authenticated caller could add one time series to `/metrics` per request.
- A deployment with `OPENCTI_ENABLED=false` no longer stays `unhealthy`: the
  compose healthcheck required `/health` to report `ok`, and a disabled sink
  reported `degraded`. The `opencti` check now reads `disabled`, which does
  not lower the overall status (ADR-008), and the healthcheck polls `/ready`.
- Documentation: five files still pointed at the removed `docs/socialosint.md`;
  ADR-008 still cited the retired public demo; `ui/UX_CHECKLIST.md` was
  unticked for delivered items; the "Built during the hackathon" tables stopped
  at #30. `docs/architecture.md` gains an *Operator dashboard* section and
  ADR-010 records the dashboard decisions. A unit test now fails on a
  reference to a documentation file that does not exist.

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

### Security

- The `6.8.11` OpenCTI images carried published advisories: CVE-2026-35210
  (authorization bypass), CVE-2026-35211 (GraphQL exposure), CVE-2026-35212
  (XSS), GHSA-ffm6-vvph-g5f5 (SSRF in data ingestion) and GHSA-q537-qhj4-wcjx
  (privilege escalation through the GraphQL API). `7.260811.0-lts.1` is past
  every fix version.

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
