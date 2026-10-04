---
name: context-aware-code-review
description: Perform repository-aware code reviews that prioritize correctness, security, tests, and project constraints.
---

# Context-aware code review

Use this skill when reviewing pull requests or proposed patches in this repository.

## Review goals

1. Find high-confidence correctness bugs, security risks, and regression risks.
2. Verify changes follow repository guardrails from `AGENTS.md`.
3. Confirm tests and checks match the touched areas.
4. Keep feedback actionable, minimal, and prioritized by risk.

## Repository-specific checks

- Read `AGENTS.md` first and enforce its constraints.
- Keep architecture aligned with ADR decisions in `docs/adr/`.
- Ensure language policy is respected:
  - Developer-facing code/comments/logs/docs in English.
  - Operator-facing text localized via `orchestrator/i18n.py` with both `es` and `en` keys.
- Reject changes that add secrets or sensitive values to code, docs, fixtures, or examples.
- If new settings are introduced, require updates to:
  - `orchestrator/config.py`
  - `.env.example`
  - the environment tables in `docs/configuration.md`
- If metrics are introduced, require updates to:
  - `orchestrator/metrics.py`
  - the metrics table in `docs/operations.md`

## Review against the issue, not the PR text

Delegated PRs come from an *Agent task* issue (`.github/ISSUE_TEMPLATE/agent-task.md`).
Open the linked issue and check every numbered item under *What to do* and every
test under *Tests* against the diff itself:

- A PR that says it is done but is missing listed items is not done. Name each
  missing item. A title or session that reports success proves nothing; count the
  changed files and look for the named tests.
- Every test the issue lists must exist under that name and assert what the issue
  says. A test that compares a value with a copy of itself, or builds the exact
  shape the code expects instead of the real contract, does not count.
- An empty PR (only an "Initial plan" commit) or a draft / `[WIP]` PR must not be
  merged: merging it closes the issue as completed with nothing implemented.

## Failure modes already seen in this repository

Check these explicitly; each one reached a PR at least once:

- **Text logs.** With `ORCHESTRATOR_LOG_FORMAT=text` only the message is printed.
  A log line an operator must act on needs the values in the message
  (parameterized), not only in `extra`.
- **Data loss in docs.** Docs or ADRs that recommend a setting for a situation it
  does not handle safely (e.g. `OPENCTI_ENABLED=false` for outages: observables
  are marked seen and never backfilled). Read the consequence, not the wording.
- **Shared on-disk state.** Anything keyed by date or target alone (report
  directories, files) is overwritten by a second run the same day. Evidence must
  be per run.
- **Async SQLAlchemy.** Reading an ORM attribute after `commit()` on a session
  with `expire_on_commit=True` triggers a lazy load (`MissingGreenlet`). Read the
  value before committing.
- **Time zones.** `datetime.astimezone()` on a naive value uses the host zone.
  Naive datetimes from SQLite are UTC; anything signed or hashed must not depend
  on the host.
- **Untrusted input from collectors.** Values from SpiderFoot, Tavily or an LLM
  can be any type. Validate the type and range before they become STIX values or
  map keys, and count what is dropped instead of discarding it silently.
- **Compose env files.** `KEY=   # comment` makes the comment the value. A blank
  required secret must fail with `:?`, not start a service with an empty value.
- **Merge order.** PRs that touch the same files (`pipeline.py`, `i18n.py`,
  `api.py`, READMEs, `CHANGELOG.md`) must state their merge order; a squash merge
  of a branch that contains another PR's commits ships that PR too.

## Expected validation evidence

Ask for or verify output for:

- `ruff check orchestrator/ tests/unit/`
- `ruff format --check orchestrator/ tests/unit/`
- `pytest tests/unit/ -v -m "not integration"`
- If a migration was added: `ORCHESTRATOR_DATABASE_URL=sqlite+aiosqlite:////tmp/migration_check.db alembic upgrade head && alembic check` (the default URL is the real `./orchestrator.db`).
- Run the tests on a checkout without a local `.env`: `tests/conftest.py` already pins `ORCHESTRATOR_ENV_FILE=""` and a temp database, so a developer's `.env` cannot change the result. Check `ORCHESTRATOR_ENV_FILE=""` explicitly for the paths that do not go through pytest (`alembic`, app startup).
- If `deploy/helm/` changed:
  - `helm lint deploy/helm/osint-orchestrator --strict`
  - `helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0`

## Review output format

Return findings as a short list:

- **Severity**: High / Medium / Low
- **Location**: file and line(s)
- **Issue**: what is wrong and why it matters
- **Fix direction**: concise remediation guidance

If no material issues are found, explicitly say so and mention what was checked.
