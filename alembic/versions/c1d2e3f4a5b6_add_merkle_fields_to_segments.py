"""add_merkle_fields_to_segments

Añade las columnas necesarias para el árbol Merkle de integridad
de vídeo por segundo:
  - merkle_root: raíz del árbol Merkle sobre los hashes de cada segundo
  - second_hashes: array JSON con los 30 hashes SHA-256 (uno por segundo)

Revision ID: c1d2e3f4a5b6
Revises: f3a9c2b1d8e7
Create Date: 2026-03-01 11:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'c1d2e3f4a5b6'
down_revision: Union[str, None] = 'f3a9c2b1d8e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # merkle_root: raíz del árbol Merkle (SHA-256 hex, 64 chars)
    op.add_column(
        'segments',
        sa.Column('merkle_root', sa.String(length=64), nullable=True)
    )
    # second_hashes: lista JSON de hashes SHA-256 por segundo del segmento
    # Se almacena como JSONB en PostgreSQL para búsquedas eficientes
    op.add_column(
        'segments',
        sa.Column(
            'second_hashes',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True
        )
    )


def downgrade() -> None:
    op.drop_column('segments', 'second_hashes')
    op.drop_column('segments', 'merkle_root')
