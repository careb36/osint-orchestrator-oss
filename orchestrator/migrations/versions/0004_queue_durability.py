"""Queue durability: unique seen_observables, nullable outbox bundle_json.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-17 18:30:00.000000

- ``seen_observables`` gets ``UNIQUE (target_id, stix_id)``. The pipeline
  relied on a SELECT-then-INSERT to keep the table unique; the outbox drain
  now also inserts into it, so the database enforces the invariant. Any
  duplicates that slipped in are collapsed to their oldest row first.
- ``opencti_outbox.bundle_json`` becomes nullable: a SENT row keeps its
  audit trail but not the STIX payload (ADR-003: SQLite holds operational
  state only, STIX lives in OpenCTI).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UNIQUE_INDEX = "ix_seen_observables_target_stix"


def upgrade() -> None:
    # Collapse duplicates before the unique index can be created: keep the
    # oldest row (lowest id) of every (target_id, stix_id) pair.
    op.execute(
        "DELETE FROM seen_observables WHERE id NOT IN "
        "(SELECT MIN(id) FROM seen_observables GROUP BY target_id, stix_id)"
    )
    op.create_index(_UNIQUE_INDEX, "seen_observables", ["target_id", "stix_id"], unique=True)
    # SQLite cannot ALTER a column in place; batch mode rebuilds the table.
    with op.batch_alter_table("opencti_outbox") as batch_op:
        batch_op.alter_column("bundle_json", existing_type=sa.String(), nullable=True)


def downgrade() -> None:
    op.execute("UPDATE opencti_outbox SET bundle_json = '' WHERE bundle_json IS NULL")
    with op.batch_alter_table("opencti_outbox") as batch_op:
        batch_op.alter_column("bundle_json", existing_type=sa.String(), nullable=False)
    op.drop_index(_UNIQUE_INDEX, table_name="seen_observables")
