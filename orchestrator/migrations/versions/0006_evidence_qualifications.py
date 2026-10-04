"""Add persisted evidence qualification rows.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-04 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_qualifications",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("relevance", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("rationale", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("model", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_evidence_qualifications_run_id"),
        "evidence_qualifications",
        ["run_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_evidence_qualifications_target_id"),
        "evidence_qualifications",
        ["target_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_evidence_qualifications_target_id"), table_name="evidence_qualifications")
    op.drop_index(op.f("ix_evidence_qualifications_run_id"), table_name="evidence_qualifications")
    op.drop_table("evidence_qualifications")
