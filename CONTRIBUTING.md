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
# pycti loads libmagic at import time: install it first
# (macOS: brew install libmagic; Debian/Ubuntu: apt install libmagic1).
pip install -e ".[dev]"
# Optional: the cloud LLM SDKs (openai/nebius/anthropic synthesis)
pip install -e ".[dev,llm]"

# Quality gates — the same commands CI runs
ruff check orchestrator/ tests/unit/
ruff format --check orchestrator/ tests/unit/
pytest tests/unit/ -v -m "not integration"

# Only if you touched deploy/helm/ (both flags matter; see below)
helm lint deploy/helm/osint-orchestrator --strict
helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0 > /dev/null
```

Integration tests need the full compose stack:
`docker compose up -d && pytest tests/integration/ -m integration -v`.

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
- New metrics → the metrics table in `docs/operations.md`.
- Operator-facing workflow changes → the relevant guide under `docs/`.
- Documentation is English ([ADR-009](docs/adr/ADR-009-documentation-language.md)).
  The README is the only translated file: `README.es.md` is updated **in the
  same PR** as `README.md`, with the same sections. Keep both short; reference
  material belongs in `docs/`.

## Delegating a task to a coding agent

Routine, well-specified work is delegated to a coding agent. Two channels are
set up; both read `AGENTS.md` before every task, and a maintainer reviews every
PR they open with the same gates as a human PR.

- **GitHub Copilot coding agent:** assign the issue to Copilot. It opens a
  draft PR on a `copilot/…` branch. Its workflows need a maintainer's approval
  before CI runs, and the PR is not ready while it is a draft or titled
  `[WIP]`: at that point it may hold nothing but an empty "Initial plan"
  commit, and merging it would close the issue with nothing implemented.
  Follow-up requests go in a PR comment that mentions `@copilot`.
- **[OpenCode](https://opencode.ai):** runs inside this repository's GitHub
  Actions runner (`.github/workflows/opencode.yml`) with the model and
  permissions declared in `opencode.json`; the steps below describe it.

The review checklist both agents and reviewers follow is
`.github/skills/context-aware-code-review/SKILL.md`.

### One-time prerequisites (repository owner)

1. Install the GitHub App
   [`opencode-agent`](https://github.com/apps/opencode-agent) on this
   repository (or run `opencode github install` from a local clone).
2. Add the repository secret `DEEPSEEK_API_KEY` (*Settings → Secrets and
   variables → Actions*). The key lives only there; `opencode.json` refers to
   it as `{env:DEEPSEEK_API_KEY}`.
3. `main` is protected by a ruleset that requires the *Lint & Unit Tests*,
   *Helm chart*, *Public-release guard* and *PR is complete* checks and forbids
   force pushes, so nothing reaches `main` without a pull request and a green
   CI run. *PR is complete* (`.github/workflows/pr-guard.yml`) exits successfully
   for draft PRs and enforces the `[WIP]`/empty-change checks after
   `ready_for_review`.

### Delegating one task

1. Open an issue with the **Agent task** template. Write it so every numbered
   step and every named test can be checked against the code: the issue *is*
   the acceptance test. Name the files the agent must not touch.
2. Comment `/oc` on the issue (optionally followed by one line of extra
   instructions). Only comments whose author is the repository **owner**
   trigger the workflow; anyone else's `/oc` is ignored.
3. The agent creates the branch `opencode/<issue>-<slug>`, pushes it and opens
   a PR that fills the PR template and pastes the quality-gate output. CI runs
   on it like on any other PR.
4. Review it as usual (see below). To request a follow-up, submit a review
   with numbered items and then leave a **comment** on the PR:
   `/oc Address every numbered item in the review above`. The review itself
   does not trigger the agent; the comment does.
5. Keep **one delegated task in flight at a time** so branches do not drift
   from `main`.

### What the reviewer checks

Every delegated PR goes through the same gate, on a clean checkout of the PR
head, before it is merged:

- `ruff check`, `ruff format --check`, `pytest tests/unit/`,
  `alembic upgrade head && alembic check` on a temporary database, and the
  Helm lint/render commands if `deploy/helm/` changed.
- Each numbered item and each test of the issue, verified against the code
  rather than against the PR description.
- Repository guards: no credentials, `README.md`/`README.es.md` still
  mirrors, the metrics table in `docs/operations.md` matching
  `orchestrator/metrics.py`, and `.gitignore`, workflows and `pyproject.toml`
  untouched unless the issue asked for it.

### Fallback: running OpenCode locally

If the Actions channel is unavailable, the same task runs from a clone:

```bash
export DEEPSEEK_API_KEY=<your key>     # never commit it
opencode run -m deepseek/deepseek-chat -f path/to/task.md \
  --title "issue-<n>" "Implement the task in the attached file"
```

Then push the branch and open the PR by hand. The review gate is identical.

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

The forbidden-reference pattern lives in that script only. Extend it there.

### Responsible use

The *Responsible use* section of the README and section 1 of
[SECURITY.md](SECURITY.md) are part of the contribution rules: never add
targets, fixtures or examples that point at real third parties, never add code
that interacts with a target beyond public-source collection, and keep every
example domain under `example.com` / `example.org`.

## Security issues

Do **not** open a public issue for a vulnerability. Follow the private
reporting path in [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree your contributions are licensed under the project's
[MIT licence](LICENSE).
