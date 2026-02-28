"""add camera public_key_pem

Añade la columna public_key_pem a la tabla cameras.
Almacena la clave pública ECDSA P-256 en formato PEM exportada
por el simulador de cámara en su primer arranque.

Usada por verifier.py para validar firmas ECDSA de segmentos.

Revision ID: f3a9c2b1d8e7
Revises: 843efd2cb4a8
Create Date: 2026-02-28 15:07:00.000000
"""
from alembic import op
import sqlalchemy as sa


# ── Identificadores de revisión ─────────────────────────────────

revision      = 'f3a9c2b1d8e7'
down_revision = '843efd2cb4a8'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    op.add_column(
        'cameras',
        sa.Column(
            'public_key_pem',
            sa.Text(),
            nullable=True,
            comment=(
                'Clave pública ECDSA P-256 en PEM. '
                'Generada por el simulador y registrada por el Admin. '
                'Usada para verificar firmas de segmentos (NIST FIPS 186-5).'
            )
        )
    )


def downgrade() -> None:
    op.drop_column('cameras', 'public_key_pem')
