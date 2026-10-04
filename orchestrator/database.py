"""
SQLModel async database setup.

Schema migrations are managed by Alembic.  ``create_db_and_tables`` runs
``alembic upgrade head`` on every startup.  For databases that were created
before Alembic was introduced (tables exist but no ``alembic_version`` row),
the function stamps the baseline revision first so that Alembic does not try
to recreate tables that already exist.

.. note::
    ``sqlite+aiosqlite:///:memory:`` is **not** supported for production use
    with this migration approach.  Alembic opens its own synchronous
    connection, which maps to a *different* in-memory database than the async
    engine; the tables it creates are immediately discarded.  Use a file-based
    URL (or an in-memory SQLite via SQLModel's ``create_all`` in unit tests
    that patch ``get_session`` directly).
"""

from __future__ import annotations

import importlib.resources
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel.ext.asyncio.session import AsyncSession

from orchestrator.config import settings

log = logging.getLogger(__name__)

engine = create_async_engine(settings.orchestrator_database_url, echo=False)

# Baseline revision — must match the first migration in versions/.
_BASELINE_REVISION = "0001"


def _make_alembic_config() -> AlembicConfig:
    """Build an Alembic Config that resolves script_location from the installed package."""
    # importlib.resources gives us the package directory even when installed
    # from a wheel (i.e. without a file-system migrations/ tree in cwd).
    migrations_path = importlib.resources.files("orchestrator.migrations")
    script_location = str(migrations_path)

    cfg = AlembicConfig()
    cfg.set_main_option("script_location", script_location)

    # Derive the sync URL from the async URL (strip async driver prefix).
    async_url: str = settings.orchestrator_database_url
    if async_url.startswith("sqlite+aiosqlite"):
        sync_url = async_url.replace("sqlite+aiosqlite", "sqlite", 1)
    elif async_url.startswith("postgresql+asyncpg"):
        sync_url = async_url.replace("postgresql+asyncpg", "postgresql+psycopg2", 1)
    else:
        sync_url = async_url

    cfg.set_main_option("sqlalchemy.url", sync_url)
    return cfg


def _is_legacy_database(sync_conn) -> bool:
    """Return True if the database has app tables but no alembic_version table."""
    inspector = inspect(sync_conn)
    tables = set(inspector.get_table_names())
    has_version_table = "alembic_version" in tables
    has_app_tables = bool(tables & {"runs", "findings", "seen_observables"})
    return has_app_tables and not has_version_table


async def create_db_and_tables() -> None:
    """Apply all pending Alembic migrations, creating schema from scratch if needed.

    For databases that pre-date Alembic (app tables present, no
    ``alembic_version`` table) this function stamps the baseline revision
    **after** closing the async connection so that Alembic's own synchronous
    connection does not race the async one for the SQLite write lock.
    """
    # Check for the legacy case while holding a short-lived async connection,
    # then release it fully before calling stamp (which opens its own sync
    # connection).  This avoids a potential SQLite write-lock conflict between
    # the two connections.
    async with engine.begin() as conn:
        legacy = await conn.run_sync(_is_legacy_database)
    # Connection is now fully closed.

    if legacy:
        log.info(
            "Legacy database detected (app tables present, no alembic_version). "
            "Stamping at baseline revision %s.",
            _BASELINE_REVISION,
        )
        alembic_command.stamp(_make_alembic_config(), _BASELINE_REVISION)

    # Run all pending migrations (Alembic opens its own connection from the URL).
    alembic_command.upgrade(_make_alembic_config(), "head")
    log.info("Database schema is up to date.")


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """The only sanctioned way to get a database session (async context manager).

    ``expire_on_commit=False`` keeps attributes readable after commit —
    callers run outside a request scope (scheduler jobs, background tasks)
    and would otherwise hit lazy-refresh errors on a closed session.
    """
    async with AsyncSession(engine, expire_on_commit=False) as session:
        yield session
