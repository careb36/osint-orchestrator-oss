"""Alert cases: the triage item an operator acknowledges and resolves.

The ``alerts`` table is the delivery audit (one row per channel per attempt);
a run that meets an alert rule with no channel configured leaves nothing
there. ``alert_cases`` holds one row per such run with its triage state.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-15 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alert_cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("run_status", sa.String(), nullable=False),
        sa.Column("risk_level", sa.String(), nullable=False),
        sa.Column("new_observable_count", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(), nullable=True),
        sa.Column("note", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alert_cases_run_id"), "alert_cases", ["run_id"], unique=True)
    op.create_index(op.f("ix_alert_cases_target_id"), "alert_cases", ["target_id"], unique=False)
    op.create_index(op.f("ix_alert_cases_state"), "alert_cases", ["state"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_alert_cases_state"), table_name="alert_cases")
    op.drop_index(op.f("ix_alert_cases_target_id"), table_name="alert_cases")
    op.drop_index(op.f("ix_alert_cases_run_id"), table_name="alert_cases")
    op.drop_table("alert_cases")
