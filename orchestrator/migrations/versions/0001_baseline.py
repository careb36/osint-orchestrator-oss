"""Baseline schema: create all tables that SQLModel.metadata produces.

This migration captures the full schema as it exists at the time of
introduction of Alembic (equivalent to what ``SQLModel.metadata.create_all``
would create).  New databases start here; existing databases without an
``alembic_version`` table are stamped at this revision before any further
upgrades are applied.

Revision ID: 0001
Revises:
Create Date: 2026-09-09 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── runs ────────────────────────────────────────────────────────────────
    op.create_table(
        "runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("collectors_run", sa.String(), nullable=False),
        sa.Column("new_observables", sa.Integer(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("report_path", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_runs_target_id"), "runs", ["target_id"], unique=False)

    # ── seen_observables ────────────────────────────────────────────────────
    op.create_table(
        "seen_observables",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("stix_id", sa.String(), nullable=False),
        sa.Column("first_seen_run_id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_seen_observables_stix_id"),
        "seen_observables",
        ["stix_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_seen_observables_target_id"),
        "seen_observables",
        ["target_id"],
        unique=False,
    )

    # ── run_observables ─────────────────────────────────────────────────────
    op.create_table(
        "run_observables",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("stix_id", sa.String(), nullable=False),
        sa.Column("stix_type", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("is_new", sa.Boolean(), nullable=False),
        sa.Column("ingested", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_run_observables_run_id"),
        "run_observables",
        ["run_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_run_observables_stix_id"),
        "run_observables",
        ["stix_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_run_observables_stix_type"),
        "run_observables",
        ["stix_type"],
        unique=False,
    )

    # ── findings ────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_run_id"), "findings", ["run_id"], unique=True)
    op.create_index(op.f("ix_findings_target_id"), "findings", ["target_id"], unique=False)

    # ── alerts ──────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("channel", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alerts_run_id"), "alerts", ["run_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_alerts_run_id"), table_name="alerts")
    op.drop_table("alerts")

    op.drop_index(op.f("ix_findings_target_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_run_id"), table_name="findings")
    op.drop_table("findings")

    op.drop_index(op.f("ix_run_observables_stix_type"), table_name="run_observables")
    op.drop_index(op.f("ix_run_observables_stix_id"), table_name="run_observables")
    op.drop_index(op.f("ix_run_observables_run_id"), table_name="run_observables")
    op.drop_table("run_observables")

    op.drop_index(op.f("ix_seen_observables_target_id"), table_name="seen_observables")
    op.drop_index(op.f("ix_seen_observables_stix_id"), table_name="seen_observables")
    op.drop_table("seen_observables")

    op.drop_index(op.f("ix_runs_target_id"), table_name="runs")
    op.drop_table("runs")
