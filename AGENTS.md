# Agent instructions for osint-orchestrator

This file is read by every coding agent that works on the repository: GitHub
Copilot (via the stub in `.github/copilot-instructions.md`) and Claude Code
(directly, with `.claude/rules/` restating it per file type). The rules are the
same for all of them and for human contributors; `CONTRIBUTING.md` is the long
form.

## What this project is

A FastAPI + APScheduler service that runs OSINT collectors (OpenOSINT, SpiderFoot and, opt-in per target, Tavily, Amass and SocialOSINT), qualifies web evidence and synthesises a risk read with an LLM, normalises findings to STIX 2.1 and ingests them into OpenCTI, then writes a signed report per run and sends alerts. Architecture decisions live in `docs/adr/` and are summarised in `docs/architecture.md`: modular monolith (ADR-001), STIX 2.1 as the internal contract (ADR-002), OpenCTI as the single source of truth (ADR-003), Spanish for operators / English for code (ADR-004), static API keys and a single-instance deployment (ADR-005), optional OIDC proxy (ADR-006), signed evidence chain (ADR-007), optional OpenCTI sink (ADR-008), documentation language (ADR-009). Read the relevant ADR before changing architecture; do not contradict one without proposing a new ADR.

## Language policy (ADR-004) — non-negotiable

- Code, comments, log messages, commit messages, `README.md`, ADRs, and developer-facing docs: **English**.
- Operator-facing prose (API error `detail`, report bodies, alert subjects/bodies, LLM synthesis) is localised through `orchestrator/i18n.py`. Every message key must carry both `es` and `en`; `tests/unit/test_i18n.py` fails otherwise. Default language is `es`.
- Identifiers that are persisted or compared (`risk_level`, `RunStatus`, STIX types, enum values) stay English in every language.

## Before you open or update a PR

Run these from the repository root and paste the output in the PR description:

    ruff check orchestrator/ tests/unit/
    ruff format --check orchestrator/ tests/unit/
    pytest tests/unit/ -v -m "not integration"

CI runs the same commands. A PR with red lint or failing tests is not ready for review.

If you touched `deploy/helm/`, also run:

    helm lint deploy/helm/osint-orchestrator --strict
    helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0

Both flags matter. `--strict` is what CI runs, so a lint without it can pass
locally and still block the PR. `--kube-version` is required because the chart
declares `kubeVersion: >=1.25.0-0`, and `helm template` otherwise assumes an
older default and refuses to render. CI also renders the chart a second time
with every optional resource switched on (`.github/workflows/ci.yml`); if you
changed a conditional template, copy that step too.

## Conventions

- Python 3.11. Async SQLModel over `aiosqlite`; `orchestrator/database.py::get_session()` is the only way to get a session.
- Tests: pytest with `asyncio_mode = auto`, `pytest_httpx` for HTTP, and an in-memory SQLite engine per test (copy the `_make_engine` / `_session_factory` pattern in `tests/unit/test_alerts.py`). Tests must never touch the real `orchestrator.db` or the network.
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
