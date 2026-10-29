"""
Session-wide test isolation.

Two things here must run BEFORE `orchestrator.config` is imported, which is
why the environment is set at module top rather than in a fixture: `Settings()`
is instantiated at import time, and `orchestrator.database.engine` is built
from it in the same breath.

1. The database URL. Six API-level test modules start the FastAPI app through
   its lifespan, which runs `alembic upgrade head` and opens the engine. With
   the default URL that meant writing `./orchestrator.db` into the repository
   root on every test run, and — because the default pool keeps a checked-in
   aiosqlite connection between tests while pytest-asyncio closes the event
   loop per test — the connection's worker thread later died with
   `RuntimeError: Event loop is closed`, surfacing as an unhandled-thread
   warning attributed to whichever test happened to run next.

   `:memory:` is not an option: `orchestrator/database.py` documents that
   Alembic opens its own synchronous connection, which for an in-memory URL
   is a different database. A per-session temp file keeps the migration path
   real and the repository clean.

2. `ORCHESTRATOR_API_KEY` pinned empty. Several API tests assume auth is
   disabled and only hold because no `.env` exists in the working directory;
   a developer with a real `.env` in the repo root would see spurious 401s.
   Tests that exercise auth set the key explicitly.

3. `ORCHESTRATOR_ENV_FILE` pinned empty. Unit tests must never read a
   developer's local `.env`; this keeps outcomes identical across machines
   even when local files set optional LLM provider/model keys.

4. Settings variables scrubbed. Pinning three variables by name was not
   enough: a shell that had sourced `.env` (`set -a; . ./.env`) exported
   `OPENCTI_ENABLED`, `ORCHESTRATOR_TARGETS_FILE`, `ORCHESTRATOR_SECRET_KEY`
   and `ORCHESTRATOR_LOG_LEVEL` as well, and
   `test_issue8_sink_failure_reraises_on_second_run` failed only because the
   sink was already enabled outside pytest. CI runs with a clean environment,
   so scrubbing is what makes a local run mean the same thing as a green build.

   Not scrubbed when the session can reach `tests/integration`: that module
   reads the real stack's endpoint and API key from the environment at import
   time, so deleting them would quietly test localhost defaults instead. The
   decision and the prefix list live in `tests/env_guard.py`, which is where
   they are tested.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import tempfile
from pathlib import Path

from tests.env_guard import keeps_environment, scrub

_REPO_ROOT = Path(__file__).resolve().parents[1]
if not keeps_environment(sys.argv[1:], _REPO_ROOT):
    scrub()

_TEST_DB_DIR = tempfile.mkdtemp(prefix="osint-orchestrator-tests-")
os.environ["ORCHESTRATOR_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB_DIR}/orchestrator-test.db"
os.environ.setdefault("ORCHESTRATOR_API_KEY", "")
os.environ["ORCHESTRATOR_ENV_FILE"] = ""

import pytest  # noqa: E402
import sqlalchemy.ext.asyncio as _sa_asyncio  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

# Engines created by tests themselves (in-memory StaticPool engines built inside
# test bodies) hold one aiosqlite connection for their whole life and are never
# disposed, so the connection's worker thread ends up bound to an event loop
# pytest-asyncio has already closed and dies with "Event loop is closed" — a
# warning attributed to whichever test runs next. Wrap the factory here, before
# any test module binds the name, so every engine is tracked and disposed at
# the end of the test that made it, while that test's loop is still alive.
_created_engines: list = []
_real_create_async_engine = _sa_asyncio.create_async_engine


def _tracking_create_async_engine(*args, **kwargs):
    engine = _real_create_async_engine(*args, **kwargs)
    _created_engines.append(engine)
    return engine


_sa_asyncio.create_async_engine = _tracking_create_async_engine

import orchestrator.database as _database  # noqa: E402
from orchestrator.config import settings  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _isolated_database_engine():
    """
    Replace the import-time engine with one that holds no connections between
    uses. `get_session()` reads `orchestrator.database.engine` at call time,
    so swapping the module attribute is enough for every consumer.

    NullPool means each `AsyncSession` opens and closes its own connection
    inside the test's own event loop, so no aiosqlite worker thread can
    outlive the loop it was created on.
    """
    original = _database.engine
    _database.engine = create_async_engine(
        settings.orchestrator_database_url, poolclass=NullPool, echo=False
    )
    try:
        yield
    finally:
        engine, _database.engine = _database.engine, original
        asyncio.run(engine.dispose())


@pytest.fixture(autouse=True)
async def _dispose_engines_created_by_the_test():
    """Dispose every engine a test created, inside the test's own event loop."""
    before = len(_created_engines)
    try:
        yield
    finally:
        created = _created_engines[before:]
        del _created_engines[before:]
        for engine in created:
            # Teardown must never mask the test result.
            with contextlib.suppress(Exception):
                await engine.dispose()
