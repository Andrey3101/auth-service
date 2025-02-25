from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

def upgrade():
    op.create_table(
        "audit_log",
        sa.Column("audit_id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("auth.users.user_id"), nullable=False),
        sa.Column("action", sa.String, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="auth"
    )

def downgrade():
    op.drop_table("audit_log", schema="auth")