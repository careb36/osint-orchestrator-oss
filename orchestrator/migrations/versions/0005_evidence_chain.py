"""Add a manifest hash per run for evidence-chain verification.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-27 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("runs") as batch_op:
        batch_op.add_column(sa.Column("manifest_sha256", sa.String(), nullable=True))
        batch_op.create_index(
            batch_op.f("ix_runs_manifest_sha256"),
            ["manifest_sha256"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("runs") as batch_op:
        batch_op.drop_index(batch_op.f("ix_runs_manifest_sha256"))
        batch_op.drop_column("manifest_sha256")
