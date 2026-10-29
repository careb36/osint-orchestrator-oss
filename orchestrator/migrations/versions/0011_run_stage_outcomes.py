"""Persist stage outcomes without inventing successful outcomes for historical runs."""

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade():
    for name in (
        "collection_status",
        "qualification_status",
        "synthesis_status",
        "report_status",
        "integrity_status",
    ):
        op.add_column(
            "runs", sa.Column(name, sa.String(), nullable=False, server_default="not_recorded")
        )
    for name in ("evidence_collected", "evidence_qualified"):
        op.add_column("runs", sa.Column(name, sa.Integer(), nullable=True))


def downgrade():
    for name in (
        "evidence_qualified",
        "evidence_collected",
        "integrity_status",
        "report_status",
        "synthesis_status",
        "qualification_status",
        "collection_status",
    ):
        op.drop_column("runs", name)
