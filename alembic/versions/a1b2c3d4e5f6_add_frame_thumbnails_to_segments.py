"""add_frame_thumbnails_to_segments

Añade la columna frame_thumbnails a la tabla segments.

Cada segmento almacena un frame JPEG (codificado en base64) por segundo
de grabación. Esto permite al verificador comparar visualmente el frame
original (guardado por la cámara) contra el frame del vídeo subido al
verificar integridad, mostrando exactamente qué segundo fue manipulado.

Tamaño estimado: ~20-40 KB/frame × 30 s/segmento ≈ 600 KB-1.2 MB por
segmento (JPEG quality 5 a 1280x720). Se usa JSONB para permitir consultas
indexadas sobre el array en el futuro.

Revision ID: a1b2c3d4e5f6
Revises: c1d2e3f4a5b6
Create Date: 2026-03-01 13:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'c1d2e3f4a5b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Array JSON de frames JPEG en base64 (uno por segundo del segmento).
    # Puede ser null en segmentos grabados antes de esta migración.
    # Cada elemento puede ser null si ffmpeg no pudo extraer ese frame.
    op.add_column(
        'segments',
        sa.Column(
            'frame_thumbnails',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            comment='Array JSON de frames JPEG (base64) por segundo. Referencia visual forense.'
        )
    )


def downgrade() -> None:
    op.drop_column('segments', 'frame_thumbnails')
