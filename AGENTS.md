# Agent instructions for osint-orchestrator

This file is read by every coding agent that works on the repository: GitHub
Copilot (via the stub in `.github/copilot-instructions.md`) and Claude Code
(directly, with `.claude/rules/` restating it per file type). The rules are the
same for all of them and for human contributors; `CONTRIBUTING.md` is the long
form.

## What this project is

A FastAPI + APScheduler service that runs OSINT collectors (OpenOSINT, SpiderFoot and, opt-in per target, Tavily, Amass and SocialOSINT), qualifies web evidence and synthesises a risk read with an LLM, normalises findings to STIX 2.1 and ingests them into OpenCTI, then writes a signed report per run and sends alerts. The same process serves the operator dashboard (`ui/`) under `/console`. Architecture decisions live in `docs/adr/` and are summarised in `docs/architecture.md`: modular monolith (ADR-001), STIX 2.1 as the internal contract (ADR-002), OpenCTI as the single source of truth (ADR-003), Spanish for operators / English for code (ADR-004), static API keys and a single-instance deployment (ADR-005), optional OIDC proxy (ADR-006), signed evidence chain (ADR-007), optional OpenCTI sink (ADR-008), documentation language (ADR-009), the dashboard as a React SPA served by the API (ADR-010), external STIX 2.1 bundles as an intake path (ADR-011). Read the relevant ADR before changing architecture; do not contradict one without proposing a new ADR.

## Language policy (ADR-004) — non-negotiable

- Code, comments, log messages, commit messages, `README.md`, ADRs, and developer-facing docs: **English**.
- Operator-facing prose (API error `detail`, report bodies, alert subjects/bodies, LLM synthesis) is localised through `orchestrator/i18n.py`. Every message key must carry both `es` and `en`; `tests/unit/test_i18n.py` fails otherwise. Default language is `es`. The dashboard is separate: its catalogue is `ui/src/i18n.tsx`, checked by `src/i18n.test.ts`.
- Identifiers that are persisted or compared (`risk_level`, `RunStatus`, STIX types, enum values) stay English in every language.

## Running it locally

`docker compose up -d --build` brings up the stack (README *Quick start*). It
interpolates `docker-compose.yml` for every service the file declares, profile
or not, so a blank `${VAR:?}` — OpenCTI, MinIO and RabbitMQ credentials — stops
`up` before anything runs. MISP and OIDC credentials are `${VAR:?}` only inside
`docker-compose.misp.yml` and `docker-compose.auth.yml`, so they stop `up` only
when those overlays are loaded with `-f`. `.env.example` lists them all. For the
API alone:

    cp targets.example.yaml targets.yaml   # gitignored; example-domain ships enabled
    uvicorn orchestrator.api:app --reload  # :8000; /health and /metrics need no key

`/console` answers `503` until a dashboard build sits in
`orchestrator/static/ui-dist` (the Dockerfiles copy it there from `ui/dist`).
For dashboard work run `npm run dev` in `ui/`: Vite proxies the prefixes in
`src/lib/apiPaths.ts` (`/health`, `/targets`, `/runs`, `/analytics`, `/alerts`)
to `:8000` and serves `http://localhost:5173/console/`.

## Before you open or update a PR

Run these from the repository root and paste the output in the PR description:

    ruff check orchestrator/ tests/
    ruff format --check orchestrator/ tests/
    mypy orchestrator/ --ignore-missing-imports
    pytest tests/unit/ -v -m "not integration"

CI runs the same commands (`ruff` over all of `tests/`, not only `tests/unit/`,
and mypy is blocking). A PR with red lint, a type error or failing tests is not
ready for review.

Any change to `orchestrator/models.py` also needs an Alembic migration
(`alembic revision --autogenerate`) in `orchestrator/migrations/versions/`; CI
applies the migrations to a fresh database and fails on `alembic check`:

    export ORCHESTRATOR_DATABASE_URL="sqlite+aiosqlite:////tmp/migration_check.db"
    alembic upgrade head && alembic check

Integration tests need the compose stack and the API key it was started with
(the protected routes answer `401` without it):
`docker compose up -d && ORCHESTRATOR_API_KEY=<key> pytest tests/integration/ -m integration -v`.

CI also runs the *Public-release guard*, `bash scripts/check_public_release.sh`
(gitleaks plus a forbidden-reference pattern that lives in that script only;
`CHECK_HISTORY=1` extends it to the git history). Run it before opening a PR
that adds prose. No tracked file — code, doc, fixture or commit message — may
name a specific public body, regulator or official government portal. See
*Public release guard* in `CONTRIBUTING.md`.

If you touched `deploy/helm/`, also run:

    helm lint deploy/helm/osint-orchestrator --strict
    helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0

Both flags matter. `--strict` is what CI runs, so a lint without it can pass
locally and still block the PR. `--kube-version` is the flag CI passes, so a
render without it follows helm's built-in default instead, which changes with
the helm release (the chart declares `kubeVersion: >=1.25.0-0`). CI also
renders the chart a second time with every optional resource switched on
(`.github/workflows/ci.yml`); if you changed a conditional template, copy that
step too.

If you touched `ui/`, from `ui/`:

    npm ci
    npm run lint && npm run test:run && npm run build

That is the CI *Dashboard* job: ESLint with `--max-warnings 0`, Vitest
(including axe-core accessibility and end-to-end view tests) and a `tsc && vite
build`. CI then fails a build whose `index.html` gains an inline script,
because the API serves the dashboard with `script-src 'self'`.

## Conventions

- Python 3.11, FastAPI, APScheduler. Async SQLModel over `aiosqlite`; `orchestrator/database.py::get_session()` is the only way to get a session.
- Dashboard: React 18 + TypeScript + Vite SPA in `ui/`, served by the API at `/console` with no second process or port (ADR-010). It is a client of the public REST API and holds no rule of its own; the backend stays the source of truth.
- Tests: pytest with `asyncio_mode = auto`, `pytest_httpx` for HTTP, and an in-memory SQLite engine per test (copy the `_make_engine` / `_session_factory` pattern in `tests/unit/test_alerts.py`). Tests must never touch the real `orchestrator.db` or the network; `tests/conftest.py` pins `ORCHESTRATOR_ENV_FILE=""` so a developer's `.env` cannot change their result.
- Every collector returns a `CollectorResult`; raw tool output never leaves the collector module. STIX objects are built only in `orchestrator/normalizer/stix.py`, with deterministic ids. Do not build STIX elsewhere.
- Dependencies are pinned on purpose: git dependencies by full 40-character SHA (see `openosint` in `pyproject.toml`), Docker images by explicit tag, never `:latest`. Bump a pin in its own commit and say why.
- Secrets: nothing that looks like a credential may appear in `.env.example`, docs, fixtures or tests. Use blank values with `# Generate: openssl rand -hex 32`, or `<placeholder>` strings. Test tokens are short and obviously fake (`"test-token"`). GitGuardian scans every PR and a hit blocks it.
- New settings go in `orchestrator/config.py` with the component prefix (`ORCHESTRATOR_`, `OPENCTI_`, `ALERT_`, …), a comment explaining them, and a line in `.env.example`.
- Log in English with parameterized logging (`logger.info("... target=%s run_id=%d", ...)`); keep field names explicit (`target`, `run_id`, `collector`) and follow the surrounding module's style.
- Put structured context in `extra={...}`, not only in the message: with `ORCHESTRATOR_LOG_FORMAT=json` every `extra` field becomes a top-level key a log shipper can filter on, while the message text is opaque. Use the established names (`target_id`, `run_id`, `collector`, `status`). Do not name an extra `ts`, `level`, `logger`, `msg`, `request_id`, `exc` or `stack` — those are the formatter's own keys and yours is emitted as `extra_<name>` instead. The request id comes from the middleware's contextvar; never pass it yourself.
- Keep the PR focused on its issue: no drive-by refactors, no reformatting of files you did not otherwise change, no new dependencies unless the issue asks for one.
- If the issue lists files you must not touch, do not touch them. If the task genuinely needs a change there, stop and explain in the PR instead of making it.

## Working as the delegated agent

When a maintainer delegates an issue to you (assigns an issue written with
the *Agent task* template to the agent), the contract is:

- **One issue, one branch, one PR.** Branch from `main`; Copilot names the
  branch `copilot/<short-slug>` itself. Never commit to `main`.
- **Do exactly what the issue says**, in the order it says it. Every numbered
  item under *What to do* and every test under *Tests* is an acceptance
  criterion that the reviewer checks against the code, not against the PR
  text. If an item cannot be met, say so in the PR and leave the test red;
  never weaken, skip or delete a test to get green.
- **Files you must not touch unless the issue names them:**
  `.github/workflows/`, `.gitignore`, `AGENTS.md`, dependency pins in
  `pyproject.toml`, and any existing file under `docs/adr/`.
- **New metric** → declare it in `orchestrator/metrics.py` **and** add one
  row to the metrics table of `docs/operations.md` with exactly the labels
  declared in code.
- **New setting** → `orchestrator/config.py`, `.env.example`, and the
  environment tables of `docs/configuration.md`
  (`tests/unit/test_env_coverage.py` fails otherwise).
- **Documentation language (ADR-009).** Documentation is English and lives in
  `docs/`; reference material is never copied into the README. `README.es.md`
  is the only translation: change it in the same PR as `README.md`, with the
  same sections.
- **Fill `.github/pull_request_template.md`** and paste the real output of the
  commands in *Before you open or update a PR*. If you could not run one, say
  which and why.
- **No network access beyond installing the pinned dependencies, and no new
  dependencies.** The tests are offline by design. Do not work around that.
- **Reviews:** when the reviewer requests changes with numbered items, address
  every item on the same branch, reply under each thread with what changed,
  and do not open a second PR.

## PR description

Spanish or English. Say what changed and why, how you tested it (paste the commands above with their output), and anything you could not verify.
