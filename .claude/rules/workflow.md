# Workflow

> Always loaded. Restates `AGENTS.md`; read that file first.

## Before a PR is ready

Run from the repository root and paste the output in the PR description:

```
ruff check orchestrator/ tests/
ruff format --check orchestrator/ tests/unit/
python -m pytest tests/unit/ -m "not integration"
```

If `deploy/helm/` changed:

```
helm lint deploy/helm/osint-orchestrator --strict
helm template osint deploy/helm/osint-orchestrator --kube-version 1.30.0
```

If `ui/` changed, from `ui/`:

```
npm run lint && npm run test:run && npm run build
```

A red command is not ready for review. If a command could not be run, say
which and why; never weaken, skip or delete a test to get green.

## Language policy (ADR-004, ADR-009)

- Code, comments, log messages, commit messages, README.md, ADRs and
  developer docs: English.
- Operator-facing text (API `detail`, reports, alerts, synthesis) goes through
  `orchestrator/i18n.py` with both `es` and `en`; `tests/unit/test_i18n.py`
  fails otherwise. The dashboard's catalogue is `ui/src/i18n.tsx`.
- Persisted or compared identifiers (`risk_level`, `RunStatus`, STIX types,
  enum values) stay English in every language.
- `README.es.md` is the only translation and changes with `README.md`, same
  sections.

## Review checklist

Before marking work complete:

- [ ] The change does what the issue says, in the order it says it, and no
      more: no drive-by refactors, no reformatting of untouched files, no new
      dependency unless the issue asks for one.
- [ ] Errors are handled where they happen: collectors return a failed
      `CollectorResult`, the pipeline logs with `logger.exception`, HTTP
      errors raise `HTTPException` with an i18n `detail`. Nothing is silently
      swallowed and nothing escapes a job the scheduler must keep running.
- [ ] No secret or credential-shaped string anywhere (`.env.example`, docs,
      fixtures, tests). Blank values with `# Generate: openssl rand -hex 32`
      or `<placeholder>`; test tokens are short and obviously fake.
- [ ] Every new behaviour has a test; every fixed bug has the test that
      would have caught it.
- [ ] A new setting is in `orchestrator/config.py`, `.env.example` and
      `docs/configuration.md`; a new metric is in `orchestrator/metrics.py`
      and the table in `docs/operations.md`; a changed `orchestrator/models.py`
      ships its Alembic migration.
- [ ] `CHANGELOG.md` has an entry under `## [Unreleased]` (the first
      `### Added` / `### Changed` / `### Fixed` after that heading; dated
      sections repeat the headings).
- [ ] Documentation lives in `docs/` and is linked from where an operator
      would look; reference material is never copied into the README.

## Security triggers

Stop and review the whole change with extra care, not just the diff, when it
touches:

- `orchestrator/auth.py` (static API keys, ADR-005) or the auth-exempt paths;
- `orchestrator/evidence.py` (HMAC manifests and the evidence chain, ADR-007);
- `orchestrator/textsafe.py` or any place model- or internet-derived text is
  rendered (reports, alerts, the dashboard);
- file paths built from run or target data (`daily_reports/`, exports);
- the OpenCTI sink, the collectors' HTTP clients, or anything that publishes
  a port in `docker-compose.yml`.

## Git

- Branch from `main`; one logical change per PR; a delegated issue lands on
  the agent's own `copilot/<short-slug>` branch. Never commit to `main`.
- Commit messages in English, imperative mood, prefixed by scope when useful
  (`api:`, `ci:`, `ui:`, `normalizer:`, `deps:`), with a body that says why.
- Bump a pin (git SHA, image tag, Python package) in its own commit and say
  why. Git dependencies are pinned by full 40-character SHA, images by
  explicit tag, never `:latest`.
- Never rewrite history on a shared branch: no rebase, amend or force-push
  over someone else's commits. Merge `main` into a stale branch instead.
- Maintainer-reserved unless the issue names them: `.github/workflows/`,
  `.gitignore`, `AGENTS.md`, dependency pins in `pyproject.toml`, existing
  files under `docs/adr/`. If the task needs a
  change there, stop and explain it in the PR.
