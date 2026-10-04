"""
Alembic environment for osint-orchestrator.

Supports async engines (aiosqlite / asyncpg) via ``run_sync``.
``render_as_batch=True`` enables SQLite-safe ALTER TABLE operations.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

# Import all SQLModel table classes so their metadata is populated.
import orchestrator.models  # noqa: F401
from orchestrator.config import settings

# ---------------------------------------------------------------------------
# Alembic Config object — provides access to alembic.ini values.
# ---------------------------------------------------------------------------
config = context.config

# Override the SQLAlchemy URL from application settings.
# Strip the async driver prefix so Alembic can use the *sync* driver for
# autogenerate and schema inspection (only the URL needs to be sync here;
# the application engine remains async).
_async_url: str = settings.orchestrator_database_url
if _async_url.startswith("sqlite+aiosqlite"):
    _sync_url = _async_url.replace("sqlite+aiosqlite", "sqlite", 1)
elif _async_url.startswith("postgresql+asyncpg"):
    _sync_url = _async_url.replace("postgresql+asyncpg", "postgresql+psycopg2", 1)
else:
    _sync_url = _async_url

# Only override if alembic.ini / caller has not already set a URL.
# This lets database.py (and tests) pass a URL via cfg.set_main_option without
# env.py silently overriding it with the value from application settings.
if not config.get_main_option("sqlalchemy.url", None):
    config.set_main_option("sqlalchemy.url", _sync_url)

# Set up Python logging from the alembic.ini [loggers] section if present.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# The metadata that autogenerate will compare against.
target_metadata = SQLModel.metadata


# ---------------------------------------------------------------------------
# Offline migration (no live DB connection needed)
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout/file)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migration (uses a live sync connection via run_sync)
# ---------------------------------------------------------------------------


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using a synchronous engine."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
