"""
Migracion: add must_change_password to users

Revision ID: 002_add_must_change_password
Revises: 001
Create Date: 2026-05-31
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "002_add_must_change_password"
down_revision = None  # ajustar al ID de la ultima migracion existente
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Anadir columna con valor por defecto False para filas existentes
    op.add_column(
        "users",
        sa.Column(
            "must_change_password",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "must_change_password")
