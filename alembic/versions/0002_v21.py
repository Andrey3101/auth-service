"""v2.1: согласие на обработку персональных данных (pd_consent_at, pd_consent_version).

Revision ID: 0002_v21
Revises: 0001_initial
Create Date: 2026-10-03

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_v21"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("pd_consent_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("pd_consent_version", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "pd_consent_version")
    op.drop_column("users", "pd_consent_at")
