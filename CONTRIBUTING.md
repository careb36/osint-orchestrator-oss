# Contributing to OSINT Orchestrator

Thank you for your interest in contributing. This guide consolidates the rules
that are otherwise scattered across the documentation, the ADRs and
`AGENTS.md`. When they disagree, this file and the ADRs
win — and a PR fixing the disagreement is welcome.

## Ground rules

1. **Authorised use only.** This tool performs live reconnaissance. Never add
   code, tests, fixtures or examples that target systems you do not own or
   lack written authorisation to assess. See [SECURITY.md](SECURITY.md) and
   the *Responsible use* section of the README.
2. **Read the relevant ADR before changing architecture**
   ([`docs/adr/`](docs/adr/)). Do not contradict an ADR in code without
   proposing a new ADR (or an amendment) in the same PR.
3. **Language policy ([ADR-004](docs/adr/ADR-004-language-policy.md)) is
   non-negotiable.** Code, comments, docstrings, logs, commits and PRs are
   English. Operator-facing prose goes through `orchestrator/i18n.py` with
   both `es` and `en` entries (CI enforces catalogue completeness). Persisted
   identifiers (`risk_level`, `RunStatus`, STIX types) stay English always.

## Development setup

```bash
# Python 3.11+; git is required (openosint is a pinned git dependency).
pip install -e ".[dev]"
# Optional: the cloud LLM SDKs (openai/nebius/anthropic synthesis)
pip install -e ".[dev,llm]"

# Quality gates — the same commands CI runs
ruff check orchestrator/ tests/
ruff format --check orchestrator/ tests/
mypy orchestrator/ --ignore-missing-imports
pytest tests/unit/ -v -m "not integration"

# Only if you touched deploy/helm/ (both flags matter; see below)
helm lint deploy/helm/osint-orchestrator --strict
helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0 > /dev/null
```

Integration tests need the full compose stack and the API key the stack was
started with (the protected routes answer `401` without it):
`docker compose up -d && ORCHESTRATOR_API_KEY=<key> pytest tests/integration/ -m integration -v`.

Unit tests are intentionally isolated from a developer's local `.env`:
`tests/conftest.py` sets `ORCHESTRATOR_ENV_FILE=""` before importing
`orchestrator.config`, so local machine settings cannot change unit-test
results.

## Pull request workflow

1. Branch from `main`. One logical change per PR.
2. Commit messages in English, imperative mood, prefixed by scope when useful
   (`feat(alerts): …`, `docs(readme): …`, `fix(sink): …`).
3. Fill the PR template. The **Documentation impact** checklist is required,
   not decorative.
4. Paste the output of the quality gates into the PR description. A PR with
   red lint or failing tests is not ready for review.
5. Bump a dependency pin (git SHA or Docker tag) in its own commit and say
   why. Never `:latest`.

## Conventions that reviewers enforce

- **Sessions:** `orchestrator/database.py::get_session()` is the only way to
  get a database session.
- **STIX:** STIX objects are built only in `orchestrator/normalizer/stix.py`,
  with deterministic ids. Collectors return `CollectorResult`; raw tool output
  never leaves the collector module.
- **Settings:** new settings go in `orchestrator/config.py` with the component
  prefix (`ORCHESTRATOR_`, `OPENCTI_`, `ALERT_`, …), an explanatory comment,
  and a line in `.env.example` (CI fails on undocumented keys).
- **Tests:** pytest with `asyncio_mode = auto`, `pytest_httpx` for HTTP, and
  an in-memory SQLite engine per test (copy the `_make_engine` pattern in
  `tests/unit/test_alerts.py`). Tests never touch the real `orchestrator.db`
  or the network.
- **Secrets:** nothing that looks like a credential may appear in
  `.env.example`, docs, fixtures or tests. Use blank values with
  `# Generate: openssl rand -hex 32` or `<placeholder>` strings. GitGuardian
  scans every PR and a hit blocks it.
- **Migrations:** any `orchestrator/models.py` change ships with an Alembic
  migration (`alembic revision --autogenerate`); CI runs `alembic check`.

## Documentation Definition of Done

A change is not done until its documentation is complete:

- API changes → the endpoint table in `docs/operations.md`.
- New/changed settings → `.env.example` (comment on the line above a blank
  value) and the environment tables in `docs/configuration.md`.
- New metrics → the metrics table in `docs/operations.md`, with the labels
  the code declares. `tests/unit/test_metrics_docs.py` fails otherwise.
- Operator-facing workflow changes → the relevant guide under `docs/`.
- Documentation is English ([ADR-009](docs/adr/ADR-009-documentation-language.md)).
  The README is the only translated file: `README.es.md` is updated **in the
  same PR** as `README.md`, with the same sections. Keep both short; reference
  material belongs in `docs/`.
  `tests/unit/test_readme_parity.py` fails if the two pages disagree on the
  number of sections, on the command blocks, on the documentation pages they
  link to or on the screenshots they show, so a step added to one language and
  not the other is caught before review.

## Delegating a task to a coding agent

Routine, well-specified work is delegated to the GitHub Copilot coding agent.
It reads `AGENTS.md` (through `.github/copilot-instructions.md`) before every
task, and a maintainer reviews every PR it opens with the same gates as a
human PR.

The review checklist the agent and reviewers follow is
`.github/skills/context-aware-code-review/SKILL.md`.

Claude Code also loads `.claude/rules/` (a general workflow file plus
path-scoped Python and TypeScript files). Those restate `AGENTS.md` for the
file being edited and add nothing to it; change `AGENTS.md` first and the
rules second.

### One-time prerequisites (repository owner)

1. The Copilot coding agent is enabled for the repository (*Settings →
   Copilot → Coding agent*). Its pull requests come from the `Copilot` user and
   its Actions runs wait for a maintainer's **Approve and run workflows**
   click, so no agent-written code runs in CI unreviewed.
2. `main` is protected by a ruleset that requires the *Lint & Unit Tests*,
   *Helm chart*, *Public-release guard* and *PR is complete* checks and forbids
   force pushes, so nothing reaches `main` without a pull request and a green
   CI run. *PR is complete* (`.github/workflows/pr-guard.yml`) fails while a PR
   is a draft, is titled `[WIP]` or changes no files.

### Delegating one task

1. Open an issue with the **Agent task** template. Write it so every numbered
   step and every named test can be checked against the code: the issue *is*
   the acceptance test. Name the files the agent must not touch.
2. Assign the issue to **Copilot**. It opens a draft PR on a `copilot/…`
   branch within a minute, first with an empty "Initial plan" commit and a
   `[WIP]` title, then with the implementation. The PR is not ready while it
   is a draft or titled `[WIP]`; merging it then would close the issue with
   nothing implemented.
3. When the title loses `[WIP]`, approve its workflow runs so CI runs on it
   like on any other PR.
4. Review it as usual (see below). To request a follow-up, leave a **comment**
   on the PR that mentions `@copilot` and lists the numbered items; the agent
   pushes to the same branch and answers in the thread.
5. Keep **one delegated task per area in flight at a time** so branches do not
   drift from `main`; a branch that falls behind gets `main` merged into it
   before the required checks are re-evaluated.

### What the reviewer checks

Every delegated PR goes through the same gate, on a clean checkout of the PR
head, before it is merged:

- `ruff check`, `ruff format --check`, `pytest tests/unit/`,
  `alembic upgrade head && alembic check` on a temporary database, and the
  Helm lint/render commands if `deploy/helm/` changed.
- Each numbered item and each test of the issue, verified against the code
  rather than against the PR description.
- Repository guards: no credentials, `README.md`/`README.es.md` still
  mirrors (`test_readme_parity.py`), every page under `docs/` linked from its
  index (`test_doc_links.py`), the metrics table in `docs/operations.md`
  matching `orchestrator/metrics.py` (`test_metrics_docs.py`), and `.gitignore`,
  workflows and `pyproject.toml` untouched unless the issue asked for it.

## Public release guard

This repository is published. Two things never enter the tree, in any file,
fixture, comment or commit message:

- **Credentials** of any kind (see *Secrets* above).
- **References to specific public bodies, regulators or official government
  portals.** The documentation describes the regulatory context in generic
  terms on purpose; keep it that way.

Run the guard before opening a PR; CI runs the same script and fails the PR
on a hit:

```bash
bash scripts/check_public_release.sh              # tracked tree + gitleaks
CHECK_HISTORY=1 bash scripts/check_public_release.sh   # also scan git history
```

The secrets pass reads the files that could reach the repository: those git
tracks plus the untracked ones it does not ignore. Your `.env` is never
scanned, so keeping live credentials there — as the quick start tells you to —
does not make the guard fail locally while CI passes. Install gitleaks (CI
pins v8.21.2 and checks its SHA-256); without it the pass reports `SKIP` and
verifies nothing.

The forbidden-reference pattern lives in that script only. Extend it there.

### Responsible use

The *Responsible use* section of the README and section 1 of
[SECURITY.md](SECURITY.md) are part of the contribution rules: never add
targets, fixtures or examples that point at real third parties, never add code
that interacts with a target beyond public-source collection, and keep every
example domain under `example.com` / `example.org`.

## CI runner

Every workflow picks its runner with the same `runs-on` expression:

| Condition | Jobs run on |
|---|---|
| repository variable `CI_RUNS_ON` set | that value, as JSON (`"ubuntu-latest"`, or a label list) |
| variable unset, private repository | the self-hosted runner labelled `osint` |
| variable unset, public repository | `ubuntu-latest` (GitHub-hosted) |

The variable lives in Settings → Secrets and variables → Actions → Variables.
Setting it to `"ubuntu-latest"` (with the quotes) moves CI back to
GitHub-hosted; deleting it returns to the default above. Job names do not
change with the runner, so the required checks on `main` stay the same.

The self-hosted runner is registered **for this repository**
with the labels `self-hosted, linux, x64, osint`. On a personal account a
runner belongs to one repository; the runner of another repository does not
pick these jobs up. It has no sudo and keeps its disk between runs, so the
steps install their tools (uv and Python 3.11, gitleaks) and write their files
under `RUNNER_TEMP`, which the runner empties for every job. The *Build &
push* job needs Docker with the runner user in the `docker` group. A pull
request has one run at a time: a new push cancels the run of the commit it
replaces.

The runner executes the code of every pull request, workflow files included.
It is for a private repository with trusted collaborators only: review any
change under `.github/workflows/` before running it. That is why a public
repository falls back to GitHub-hosted; never set `CI_RUNS_ON` to the
self-hosted labels on a public repository, where a fork's pull request would
run code on that machine.

## Security issues

Do **not** open a public issue for a vulnerability. Follow the private
reporting path in [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree your contributions are licensed under the project's
[MIT licence](LICENSE).
