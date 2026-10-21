"""One active run per target, enforced by the database.

``run_control.create_pending_run`` admits a run after a SELECT for an active
one under an in-process lock, which serialises the API and the scheduler but
not a second process: ``python -m orchestrator.showcase`` runs outside the
API. A partial unique index on ``runs(target_id)`` for the PENDING and
RUNNING rows makes the second admission fail at INSERT wherever it comes
from. Any run still active when this migration runs belongs to a previous
process life (the orchestrator fails them at startup anyway) and is failed
first, so the index can be created.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-21 00:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEX_NAME = "ux_runs_one_active_per_target"
ACTIVE = "status IN ('PENDING', 'RUNNING')"


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE runs SET status = 'FAILED', finished_at = :now, "
            "error = 'interrupted: the orchestrator restarted while this run was in progress' "
            f"WHERE {ACTIVE}"
        ).bindparams(now=datetime.now(UTC))
    )
    op.create_index(
        INDEX_NAME,
        "runs",
        ["target_id"],
        unique=True,
        sqlite_where=sa.text(ACTIVE),
        postgresql_where=sa.text(ACTIVE),
    )


def downgrade() -> None:
    op.drop_index(INDEX_NAME, table_name="runs")
