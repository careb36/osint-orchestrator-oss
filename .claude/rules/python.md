---
paths:
  - "orchestrator/**/*.py"
  - "tests/**/*.py"
  - "migrations/**/*.py"
  - "scripts/**/*.py"
  - "pyproject.toml"
---
# Python

> Extends `workflow.md` for the FastAPI service. Python 3.11.

## Style

- `ruff check` and `ruff format` are the only formatters (line length 100;
  rules `E F I UP B SIM N`, see `pyproject.toml`). No black, no isort.
- Type annotations on every function signature; `from __future__ import
  annotations` at the top of each module, as the existing modules do. mypy
  runs in CI as an advisory step: do not add new findings.
- Prefer early returns to nested conditionals; name thresholds and limits as
  module constants with a comment (`_BATCH_SIZE = 500` in
  `orchestrator/retention.py` is the pattern).
- Small modules with one job. `orchestrator/api.py` and
  `orchestrator/pipeline.py` are already large: add a helper module before
  adding another two hundred lines to either.
- Exceptions: `raise ... from exc` (or `from None`) inside `except`; custom
  exception names end in `Error` (ruff N818).

## Async and persistence

- Everything that does I/O is `async def` and uses async clients: `httpx`
  for HTTP, SQLModel over `aiosqlite` for the database. No `requests`, no
  blocking file or network calls inside a route or a job.
- `orchestrator/database.py::get_session()` is the only way to get a session.
  Do not build engines or sessions elsewhere; code that needs to be testable
  takes a `session_factory` resolved at call time, not at import time.
- A change to `orchestrator/models.py` ships an Alembic migration in
  `orchestrator/migrations/versions/` (next number, same shape as the previous
  one); CI runs `alembic check`.
- Settings are read from `orchestrator.config.settings` (pydantic-settings).
  A new one needs the component prefix, a comment, a line in `.env.example`
  and a row in `docs/configuration.md`; `tests/unit/test_env_coverage.py`
  enforces the last two.

## Collectors, STIX, reports

- Every collector returns a `CollectorResult` and never raises out of
  `collect()`: wrap the tool call, return a failed result (the `_failure`
  helper where the collector has one) and stop whatever the tool started
  (SpiderFoot's `/stopscan` is the example).
  Raw tool output never leaves the collector module.
- STIX objects are built only in `orchestrator/normalizer/stix.py`, with
  deterministic ids (`uuid5` over the fields that identify the object, the
  target included). Do not build STIX anywhere else.
- Text that comes from a model or from the internet passes through
  `orchestrator/textsafe.py` before a report, an alert or the API renders it.

## FastAPI

- Routes stay thin: validate with `Query(..., ge=, le=)` and pydantic models,
  then call a function in the owning module. Keep request, update and
  response models separate.
- Errors are `HTTPException(status_code=..., detail=t("key", ...))` with an
  i18n key that has both languages. Never put a path, a secret or a raw
  exception message in `detail`.
- Protected routes rely on the dependency in `orchestrator/auth.py`; a new
  public route is a deliberate decision, named in the PR, and added to the
  exempt list the tests cover.
- Response models never carry secrets, keys or internal auth state.

## Logging

- English, parameterized: `logger.info("... target=%s run_id=%d", ...)`.
- Structured context goes in `extra={...}` with the established names
  (`target_id`, `run_id`, `collector`, `status`); never name an extra `ts`,
  `level`, `logger`, `msg`, `request_id`, `exc` or `stack`. The request id
  comes from the middleware's contextvar; never pass it.
- No `print()` in library code.

## Tests

- pytest with `asyncio_mode = auto`; `pytest_httpx` for HTTP; an in-memory
  SQLite engine per test (copy `_make_engine` / `_session_factory` from
  `tests/unit/test_alerts.py`); the `TestClient` pattern from
  `tests/unit/test_api_finding.py` for routes. Tests never touch the real
  `orchestrator.db` or the network.
- Arrange, act, assert; one behaviour per test; the test name states the
  behaviour (`test_unknown_target_returns_404_without_touching_metrics`).
- Run with `python -m pytest tests/unit/ -m "not integration"`. The
  integration suite needs the running stack and is run by hand before a
  release (`docs/operations.md`, release checklist).
- Fix the implementation, not the test, unless the test is wrong, and say so
  in the PR when it is.
