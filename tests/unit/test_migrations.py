"""
Unit tests for Alembic-based database migration.

Covers:
- Fresh database: alembic_version at head, all expected tables and columns.
- Legacy database (no alembic_version): stamped and upgraded without data loss.
- Idempotency: calling create_db_and_tables() twice does not fail.
- Autogenerate check: head database has no outstanding schema differences.
"""

from __future__ import annotations

import importlib.resources
from io import StringIO
from typing import Any
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from alembic import command as alembic_command
from alembic.autogenerate import compare_metadata
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlmodel import SQLModel

# Expected tables in the baseline schema.
EXPECTED_TABLES = {
    "runs",
    "seen_observables",
    "run_observables",
    "findings",
    "alerts",
    "alert_deliveries",
    "opencti_outbox",
}

# Columns that must exist on each table (subset check, not exhaustive).
EXPECTED_COLUMNS: dict[str, set[str]] = {
    "runs": {"id", "target_id", "started_at", "finished_at", "status", "report_path"},
    "findings": {"id", "run_id", "summary", "raw_response"},
    "seen_observables": {"id", "target_id", "stix_id"},
    "run_observables": {"id", "run_id", "stix_id", "stix_type", "value"},
    "alerts": {"id", "run_id", "channel", "status"},
    "alert_deliveries": {"id", "run_id", "target_id", "channel", "status", "attempts"},
    "opencti_outbox": {"id", "run_id", "target_id", "status", "attempts", "bundle_json"},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alembic_cfg(db_url: str) -> AlembicConfig:
    """Build an in-memory AlembicConfig pointing at an in-process SQLite URL."""
    migrations_path = importlib.resources.files("orchestrator.migrations")
    cfg = AlembicConfig()
    cfg.set_main_option("script_location", str(migrations_path))
    cfg.set_main_option("sqlalchemy.url", db_url)
    # Suppress output during tests.
    cfg.stdout = StringIO()
    return cfg


def _sync_url(async_url: str) -> str:
    if async_url.startswith("sqlite+aiosqlite"):
        return async_url.replace("sqlite+aiosqlite", "sqlite", 1)
    return async_url


def _head_revision(db_url: str) -> str:
    cfg = _make_alembic_cfg(db_url)
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    assert head is not None
    return head


def _assert_tables_and_columns(engine_: Any) -> None:
    """Assert that all expected tables and their key columns are present."""
    insp = inspect(engine_)
    table_names = set(insp.get_table_names())
    assert table_names >= EXPECTED_TABLES, f"Missing tables: {EXPECTED_TABLES - table_names}"
    for table, cols in EXPECTED_COLUMNS.items():
        actual = {c["name"] for c in insp.get_columns(table)}
        assert cols <= actual, f"Table '{table}' missing columns: {cols - actual}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db_url(tmp_path):
    """Return a sync sqlite:// URL for a fresh temporary database file."""
    db_file = tmp_path / "test.db"
    return f"sqlite:///{db_file}"


@pytest.fixture()
def tmp_async_db_url(tmp_path):
    """Return an async sqlite+aiosqlite:// URL for a fresh temporary database file."""
    db_file = tmp_path / "test.db"
    return f"sqlite+aiosqlite:///{db_file}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fresh_database_reaches_head(tmp_async_db_url, tmp_db_url):
    """A new empty database: alembic_version at head, all tables and columns created."""
    with patch("orchestrator.database.settings") as mock_settings:
        mock_settings.orchestrator_database_url = tmp_async_db_url
        # Re-create the engine with the patched URL.
        import orchestrator.database as db_module

        with patch.object(
            db_module,
            "engine",
            sa.ext.asyncio.create_async_engine(tmp_async_db_url, echo=False),
        ):
            await db_module.create_db_and_tables()

    engine_ = create_engine(tmp_db_url)
    try:
        _assert_tables_and_columns(engine_)
        # Check alembic_version.
        with engine_.connect() as conn:
            rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
        assert len(rows) == 1, "Expected exactly one alembic_version row"
        assert rows[0][0] == _head_revision(tmp_db_url)
    finally:
        engine_.dispose()


@pytest.mark.asyncio
async def test_legacy_database_stamped_and_upgraded(tmp_async_db_url, tmp_db_url):
    """Legacy DB (all tables present, no alembic_version): stamped and data preserved.

    Simulates a database created by the old ``SQLModel.metadata.create_all +
    _ensure_backfill_safe_schema`` approach.  All five tables already exist;
    the only missing element is the ``alembic_version`` table.
    """
    # All five tables as they would have existed after the old backfill patches.
    legacy_meta = sa.MetaData()
    sa.Table(
        "runs",
        legacy_meta,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("collectors_run", sa.String(), nullable=False),
        sa.Column("new_observables", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("report_path", sa.String(), nullable=True),
    )
    sa.Table(
        "findings",
        legacy_meta,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("summary", sa.String(), nullable=False),
        sa.Column("new_since_last_run", sa.String(), nullable=False),
        sa.Column("risk_level", sa.String(), nullable=False),
        sa.Column("risk_justification", sa.String(), nullable=False),
        sa.Column("suggested_pivots", sa.String(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("raw_response", sa.String(), nullable=False),
    )
    sa.Table(
        "seen_observables",
        legacy_meta,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("stix_id", sa.String(), nullable=False),
        sa.Column("first_seen_run_id", sa.Integer(), nullable=False),
    )
    sa.Table(
        "run_observables",
        legacy_meta,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("stix_id", sa.String(), nullable=False),
        sa.Column("stix_type", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("is_new", sa.Boolean(), nullable=False),
        sa.Column("ingested", sa.Boolean(), nullable=False),
    )
    sa.Table(
        "alerts",
        legacy_meta,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
    )

    engine_ = create_engine(tmp_db_url)
    legacy_meta.create_all(engine_)

    # Insert a sentinel row.
    with engine_.connect() as conn:
        conn.execute(
            text(
                "INSERT INTO runs (target_id, started_at, status, collectors_run, new_observables)"
                " VALUES ('t1', '2026-01-01T00:00:00', 'success', '', 0)"
            )
        )
        conn.commit()
    engine_.dispose()

    # Now run create_db_and_tables with the patched async URL.
    with patch("orchestrator.database.settings") as mock_settings:
        mock_settings.orchestrator_database_url = tmp_async_db_url
        import orchestrator.database as db_module

        with patch.object(
            db_module,
            "engine",
            sa.ext.asyncio.create_async_engine(tmp_async_db_url, echo=False),
        ):
            await db_module.create_db_and_tables()

    engine2 = create_engine(tmp_db_url)
    try:
        # Data preserved.
        with engine2.connect() as conn:
            rows = conn.execute(text("SELECT target_id FROM runs")).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "t1"

        # All tables and columns now present.
        _assert_tables_and_columns(engine2)

        # Stamped at head.
        with engine2.connect() as conn:
            ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert ver == _head_revision(tmp_db_url)
    finally:
        engine2.dispose()


@pytest.mark.asyncio
async def test_idempotent(tmp_async_db_url, tmp_db_url):
    """Calling create_db_and_tables twice must not fail or change anything."""
    with patch("orchestrator.database.settings") as mock_settings:
        mock_settings.orchestrator_database_url = tmp_async_db_url
        import orchestrator.database as db_module

        patched_engine = sa.ext.asyncio.create_async_engine(tmp_async_db_url, echo=False)
        with patch.object(db_module, "engine", patched_engine):
            await db_module.create_db_and_tables()
            # Second call — must not raise.
            await db_module.create_db_and_tables()

    engine_ = create_engine(tmp_db_url)
    try:
        with engine_.connect() as conn:
            ver = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert ver == _head_revision(tmp_db_url)
    finally:
        engine_.dispose()


def test_autogenerate_no_differences(tmp_db_url):
    """
    With the database at head, autogenerate must detect zero schema differences
    against SQLModel.metadata.
    """
    # Ensure all models are imported so their tables are registered.
    import orchestrator.models  # noqa: F401

    cfg = _make_alembic_cfg(tmp_db_url)
    alembic_command.upgrade(cfg, "head")

    engine_ = create_engine(tmp_db_url)
    try:
        with engine_.connect() as conn:
            mc = MigrationContext.configure(
                conn,
                opts={"target_metadata": SQLModel.metadata, "render_as_batch": True},
            )
            diffs = compare_metadata(mc, SQLModel.metadata)
        assert diffs == [], f"Autogenerate found unexpected differences: {diffs}"
    finally:
        engine_.dispose()
