"""personal_access_and_dossiers

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-25 03:39:22.762014+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dossier_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dossier_id", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=False),
        sa.Column("actor_name", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("details_json", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("dossier_events", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_dossier_events_dossier_id"), ["dossier_id"], unique=False
        )

    op.create_table(
        "dossier_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dossier_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("snapshot_json", sa.String(), nullable=False),
        sa.Column("markdown", sa.String(), nullable=False),
        sa.Column("pdf", sa.LargeBinary(), nullable=False),
        sa.Column("signature", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("dossier_reports", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_dossier_reports_dossier_id"), ["dossier_id"], unique=False
        )
        batch_op.create_index("ux_dossier_version", ["dossier_id", "version"], unique=True)

    op.create_table(
        "dossier_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dossier_id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("dossier_runs", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_dossier_runs_dossier_id"), ["dossier_id"], unique=False
        )
        batch_op.create_index("ux_dossier_run", ["dossier_id", "run_id"], unique=True)

    op.create_table(
        "dossiers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("entity_name", sa.String(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("identifier", sa.String(), nullable=False),
        sa.Column("country", sa.String(), nullable=False),
        sa.Column("purpose", sa.String(), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "evidence_reviews",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dossier_id", sa.Integer(), nullable=False),
        sa.Column("evidence_id", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("evidence_reviews", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_evidence_reviews_dossier_id"), ["dossier_id"], unique=False
        )
        batch_op.create_index("ux_dossier_evidence", ["dossier_id", "evidence_id"], unique=True)

    op.create_table(
        "user_accounts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("display_name", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("password_hash", sa.String(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("failed_logins", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("user_accounts", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_user_accounts_username"), ["username"], unique=True)

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("user_sessions", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_user_sessions_user_id"), ["user_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("user_sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_user_sessions_user_id"))

    op.drop_table("user_sessions")
    with op.batch_alter_table("user_accounts", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_user_accounts_username"))

    op.drop_table("user_accounts")
    with op.batch_alter_table("evidence_reviews", schema=None) as batch_op:
        batch_op.drop_index("ux_dossier_evidence")
        batch_op.drop_index(batch_op.f("ix_evidence_reviews_dossier_id"))

    op.drop_table("evidence_reviews")
    op.drop_table("dossiers")
    with op.batch_alter_table("dossier_runs", schema=None) as batch_op:
        batch_op.drop_index("ux_dossier_run")
        batch_op.drop_index(batch_op.f("ix_dossier_runs_dossier_id"))

    op.drop_table("dossier_runs")
    with op.batch_alter_table("dossier_reports", schema=None) as batch_op:
        batch_op.drop_index("ux_dossier_version")
        batch_op.drop_index(batch_op.f("ix_dossier_reports_dossier_id"))

    op.drop_table("dossier_reports")
    with op.batch_alter_table("dossier_events", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_dossier_events_dossier_id"))

    op.drop_table("dossier_events")
