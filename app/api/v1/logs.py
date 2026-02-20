from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone

from app.db.session import get_db
from app.db.models import Verification, Video, Segment, Camera, VerificationResult
from app.core.dependencies import require_analyst


router = APIRouter(
    prefix="/logs",
    tags=["Activity Logs"],
    responses={
        401: {"description": "JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    }
)

_TZ_AWARE_MIN = datetime.min.replace(tzinfo=timezone.utc)


def _ts(dt: Optional[datetime]) -> datetime:
    """Normaliza un datetime a timezone-aware para poder ordenar de forma segura."""
    if dt is None:
        return _TZ_AWARE_MIN
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@router.get(
    "/activity",
    summary="Log de actividad del sistema",
    description="""
Devuelve un log cronológico unificado de todos los eventos del sistema.

**Tipos de eventos:**
- `verification`: verificación de integridad realizada por un analista
- `video_started`: cámara inició una grabación
- `video_finished`: cámara finalizó una grabación
- `segment_uploaded`: cámara registró un segmento de 30s

**Filtros:**
- `event_type`: tipo de evento (ver lista arriba)
- `camera_id`: filtrar por cámara específica
- `user_id`: filtrar por ID de usuario (solo aplica a eventos `verification`)
- `date_from` / `date_to`: rango de fechas ISO 8601
- `page` / `per_page`: paginación

Requiere rol **Analyst** o **Admin**.
    """
)
def get_activity_log(
    event_type: Optional[str]      = Query(None,  description="verification | video_started | video_finished | segment_uploaded"),
    camera_id:  Optional[str]      = Query(None,  description="Filtrar por camera_id físico"),
    user_id:    Optional[str]      = Query(None,  description="Filtrar por user ID (solo eventos 'verification')"),
    date_from:  Optional[datetime] = Query(None,  description="Desde (ISO 8601)"),
    date_to:    Optional[datetime] = Query(None,  description="Hasta (ISO 8601)"),
    page:       int                = Query(1,    ge=1),
    per_page:   int                = Query(20,   ge=1, le=100),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst)
):
    events = []

    # ── Eventos: verificaciones ───────────────────────
    if event_type in (None, "verification"):
        q = (
            db.query(Verification)
            .join(Segment,  Verification.segment_id == Segment.id)
            .join(Video,    Segment.video_id         == Video.id)
            .join(Camera,   Video.camera_id          == Camera.id)
        )
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if user_id:   q = q.filter(Verification.verified_by_id == user_id)
        if date_from: q = q.filter(Verification.verified_at >= date_from)
        if date_to:   q = q.filter(Verification.verified_at <= date_to)

        for v in q.all():
            cam = v.segment.video.camera if (v.segment and v.segment.video) else None
            events.append({
                "event_type": "verification",
                "timestamp":  v.verified_at,
                "camera_id":  cam.camera_id if cam else None,
                "video_id":   str(v.segment.video_id) if v.segment else None,
                "actor_id":   str(v.verified_by_id) if v.verified_by_id else None,
                "actor_type": "user",
                "ip_address": v.ip_address,
                "detail": {
                    "result":        v.result,
                    "hash_match":    v.hash_match,
                    "segment_index": v.segment.segment_index if v.segment else None,
                    "error_message": v.error_message,
                },
            })

    # ── Eventos: video iniciado ────────────────────────
    if event_type in (None, "video_started"):
        q = db.query(Video).join(Camera, Video.camera_id == Camera.id)
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if date_from: q = q.filter(Video.created_at >= date_from)
        if date_to:   q = q.filter(Video.created_at <= date_to)

        for v in q.all():
            events.append({
                "event_type": "video_started",
                "timestamp":  v.created_at,
                "camera_id":  v.camera.camera_id if v.camera else None,
                "video_id":   str(v.id),
                "actor_id":   v.camera.camera_id if v.camera else None,
                "actor_type": "camera",
                "ip_address": None,
                "detail": {
                    "filename":   v.filename,
                    "fps":        v.fps,
                    "resolution": v.resolution,
                    "codec":      v.codec,
                },
            })

    # ── Eventos: video finalizado ──────────────────────
    if event_type in (None, "video_finished"):
        q = (
            db.query(Video)
            .join(Camera, Video.camera_id == Camera.id)
            .filter(Video.ended_at.isnot(None))
        )
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if date_from: q = q.filter(Video.ended_at >= date_from)
        if date_to:   q = q.filter(Video.ended_at <= date_to)

        for v in q.all():
            events.append({
                "event_type": "video_finished",
                "timestamp":  v.ended_at,
                "camera_id":  v.camera.camera_id if v.camera else None,
                "video_id":   str(v.id),
                "actor_id":   v.camera.camera_id if v.camera else None,
                "actor_type": "camera",
                "ip_address": None,
                "detail": {
                    "filename":      v.filename,
                    "duration_secs": v.duration_secs,
                    "status":        v.status,
                },
            })

    # ── Eventos: segmento subido ───────────────────────
    if event_type in (None, "segment_uploaded"):
        q = (
            db.query(Segment)
            .join(Video,  Segment.video_id  == Video.id)
            .join(Camera, Video.camera_id   == Camera.id)
        )
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if date_from: q = q.filter(Segment.created_at >= date_from)
        if date_to:   q = q.filter(Segment.created_at <= date_to)

        for s in q.all():
            cam = s.video.camera if s.video else None
            events.append({
                "event_type": "segment_uploaded",
                "timestamp":  s.created_at,
                "camera_id":  cam.camera_id if cam else None,
                "video_id":   str(s.video_id),
                "actor_id":   cam.camera_id if cam else None,
                "actor_type": "camera",
                "ip_address": None,
                "detail": {
                    "segment_index":   s.segment_index,
                    "sha256_hash":     s.sha256_hash,
                    "status":          s.status,
                    "file_size_bytes": s.file_size_bytes,
                },
            })

    # ── Ordenar cronológicamente (desc) + paginar ───────
    events.sort(key=lambda e: _ts(e["timestamp"]), reverse=True)

    total = len(events)
    start = (page - 1) * per_page
    items = events[start: start + per_page]

    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
        "items":    items,
    }
