"""Add daily demo budget counters.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-04 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "demo_daily_usage",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("day", sa.String(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("client_ip_hash", sa.String(), nullable=False),
        sa.Column("run_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tavily_calls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("llm_calls", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_demo_daily_usage_day"),
        "demo_daily_usage",
        ["day"],
        unique=False,
    )
    op.create_index(
        op.f("ix_demo_daily_usage_scope"),
        "demo_daily_usage",
        ["scope"],
        unique=False,
    )
    op.create_index(
        op.f("ix_demo_daily_usage_client_ip_hash"),
        "demo_daily_usage",
        ["client_ip_hash"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_demo_daily_usage_client_ip_hash"), table_name="demo_daily_usage")
    op.drop_index(op.f("ix_demo_daily_usage_scope"), table_name="demo_daily_usage")
    op.drop_index(op.f("ix_demo_daily_usage_day"), table_name="demo_daily_usage")
    op.drop_table("demo_daily_usage")
