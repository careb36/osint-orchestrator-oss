"""Add persistent alert delivery retry queue.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-13 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("channel", sa.String(), nullable=False),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("payload_json", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_alert_deliveries_run_id"),
        "alert_deliveries",
        ["run_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_alert_deliveries_target_id"),
        "alert_deliveries",
        ["target_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_alert_deliveries_target_id"), table_name="alert_deliveries")
    op.drop_index(op.f("ix_alert_deliveries_run_id"), table_name="alert_deliveries")
    op.drop_table("alert_deliveries")
