from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime

from app.db.session import get_db
from app.db.models import Video, Camera, Segment, Verification, VerificationResult
from app.core.dependencies import require_analyst
from app.services.report_generator import (
    generate_video_report_pdf,
    generate_video_csv,
    generate_verifications_csv,
)


router = APIRouter(
    prefix="/export",
    tags=["Export"],
    responses={
        401: {"description": "JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    }
)


# ── Helper interno ─────────────────────────────────

def _load_video_data(video_id: str, db: Session):
    """Carga video, cámara, segmentos y verificaciones en un solo helper."""
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")

    segments = (
        db.query(Segment)
        .filter(Segment.video_id == video_id)
        .order_by(Segment.segment_index)
        .all()
    )
    segment_ids = [s.id for s in segments]
    verifications = (
        db.query(Verification)
        .filter(Verification.segment_id.in_(segment_ids))
        .order_by(Verification.verified_at)
        .all()
    )
    return video, video.camera, segments, verifications


# ── 1. PDF forense por video ─────────────────────────

@router.get(
    "/report/{video_id}/pdf",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}},
                    "description": "Informe PDF forense descargable"}},
    summary="Exportar informe forense en PDF",
    description="""
Genera un informe PDF forense completo para un video, incluyendo:
- Metadatos del informe (fecha de generación, analista)
- Información del video (nombre, duración, resolución, codec)
- Información de la cámara (ID, nombre, ubicación)
- Resumen de integridad (total segmentos, válidos/inválidos/ausentes, tasa)
- **Veredicto** en color: `INTEGRO` o `MANIPULADO O INCOMPLETO`
- Tabla completa de segmentos con hashes SHA-256 y resultados de verificación

Requiere rol **Analyst** o **Admin**.
    """
)
def export_report_pdf(
    video_id:    str,
    db:          Session = Depends(get_db),
    current_user         = Depends(require_analyst),
):
    video, camera, segments, verifications = _load_video_data(video_id, db)

    pdf_bytes = generate_video_report_pdf(
        video=video,
        camera=camera,
        segments=segments,
        verifications=verifications,
        analyst=current_user,
    )

    filename = f"evideth_report_{video_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── 2. CSV de segmentos por video ─────────────────────

@router.get(
    "/report/{video_id}/csv",
    response_class=Response,
    responses={200: {"content": {"text/csv": {}},
                    "description": "CSV de segmentos descargable"}},
    summary="Exportar segmentos del video en CSV",
    description="""
Genera un CSV con todos los segmentos de un video y sus resultados de verificación.

**Columnas:** `segment_index`, `start/end_time_secs`, `sha256_hash`, `ecdsa_signature`,
`segment_status`, `hash_match`, `signature_valid`, `computed_hash`, `verification_result`,
`error_message`, `verified_at`, `ip_address`.

Compatible con Excel (UTF-8 BOM). Requiere rol **Analyst** o **Admin**.
    """
)
def export_report_csv(
    video_id:    str,
    db:          Session = Depends(get_db),
    current_user         = Depends(require_analyst),
):
    video, camera, segments, verifications = _load_video_data(video_id, db)

    csv_content = generate_video_csv(
        video=video, camera=camera,
        segments=segments, verifications=verifications,
    )
    filename = f"evideth_segments_{video_id[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_content.encode("utf-8-sig"),   # BOM para Excel
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── 3. CSV masivo de verificaciones (con filtros) ───────

@router.get(
    "/verifications/csv",
    response_class=Response,
    responses={200: {"content": {"text/csv": {}},
                    "description": "CSV de verificaciones descargable"}},
    summary="Exportar verificaciones en CSV",
    description="""
Exporta todas las verificaciones del sistema en formato CSV con filtros opcionales.

**Filtros:** `camera_id`, `result` (pass|fail|error), `date_from`, `date_to`

Compatible con Excel (UTF-8 BOM). Requiere rol **Analyst** o **Admin**.
    """
)
def export_verifications_csv(
    camera_id:  Optional[str]      = Query(None, description="Filtrar por camera_id físico"),
    result:     Optional[str]      = Query(None, description="pass | fail | error"),
    date_from:  Optional[datetime] = Query(None, description="Desde (ISO 8601)"),
    date_to:    Optional[datetime] = Query(None, description="Hasta (ISO 8601)"),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst),
):
    query = (
        db.query(Verification)
        .join(Segment,  Verification.segment_id == Segment.id)
        .join(Video,    Segment.video_id         == Video.id)
        .join(Camera,   Video.camera_id          == Camera.id)
    )

    if camera_id:
        query = query.filter(Camera.camera_id == camera_id)
    if result:
        try:
            query = query.filter(Verification.result == VerificationResult(result))
        except ValueError:
            raise HTTPException(status_code=400, detail="result debe ser: pass, fail, error")
    if date_from: query = query.filter(Verification.verified_at >= date_from)
    if date_to:   query = query.filter(Verification.verified_at <= date_to)

    verifications = query.order_by(Verification.verified_at.desc()).all()

    # Serializar a dicts (no ORM objects) antes de pasar al generador CSV
    verif_data = [
        {
            "id":              str(v.id),
            "segment_id":      str(v.segment_id),
            "camera_id":       (
                v.segment.video.camera.camera_id
                if v.segment and v.segment.video and v.segment.video.camera
                else ""
            ),
            "video_id":        str(v.segment.video_id) if v.segment else "",
            "result":          v.result,
            "hash_match":      v.hash_match,
            "signature_valid": v.signature_valid,
            "computed_hash":   v.computed_hash  or "",
            "stored_hash":     v.stored_hash    or "",
            "error_message":   v.error_message  or "",
            "verified_at":     v.verified_at,
            "ip_address":      v.ip_address     or "",
            "verified_by_id":  str(v.verified_by_id) if v.verified_by_id else "",
        }
        for v in verifications
    ]

    csv_content = generate_verifications_csv(verif_data)
    filename = f"evideth_verifications_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_content.encode("utf-8-sig"),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
