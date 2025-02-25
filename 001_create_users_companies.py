from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

def upgrade():
    op.create_schema("auth", if_not_exists=True)
    op.create_table(
        "companies",
        sa.Column("company_id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("inn", sa.String(12), unique=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="auth"
    )
    op.create_table(
        "users",
        sa.Column("user_id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("email", sa.String, unique=True, nullable=False),
        sa.Column("password_hash", sa.String, nullable=False),
        sa.Column("company_id", UUID(as_uuid=True), sa.ForeignKey("auth.companies.company_id"), nullable=False),
        sa.Column("role", sa.String, sa.CheckConstraint("role IN ('super_admin', 'admin', 'user')"), default="user"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        schema="auth"
    )

def downgrade():
    op.drop_table("users", schema="auth")
    op.drop_table("companies", schema="auth")
    op.drop_schema("auth")