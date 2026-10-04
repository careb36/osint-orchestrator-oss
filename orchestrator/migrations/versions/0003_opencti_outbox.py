"""Add persistent OpenCTI outbox queue.

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-13 00:15:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "opencti_outbox",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("work_name", sa.String(), nullable=False),
        sa.Column("bundle_json", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_opencti_outbox_run_id"), "opencti_outbox", ["run_id"], unique=False)
    op.create_index(
        op.f("ix_opencti_outbox_target_id"), "opencti_outbox", ["target_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_opencti_outbox_target_id"), table_name="opencti_outbox")
    op.drop_index(op.f("ix_opencti_outbox_run_id"), table_name="opencti_outbox")
    op.drop_table("opencti_outbox")
