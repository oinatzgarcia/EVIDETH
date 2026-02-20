from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta

from app.db.session import get_db
from app.db.models import (
    User, Camera, Video, Segment, Verification,
    UserRole, VideoStatus, SegmentStatus, VerificationResult
)
from app.core.dependencies import require_analyst


router = APIRouter(
    prefix="/stats",
    tags=["Statistics"],
    responses={
        401: {"description": "JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    }
)


@router.get(
    "/",
    summary="Estadísticas globales del sistema",
    description="""
Devuelve estadísticas agregadas en tiempo real sobre todo el sistema.

**Secciones:**
- `cameras`: total, activas, inactivas y cuántas están online ahora mismo
- `videos`: total por estado (grabando, completado, corrupto, archivado)
- `segments`: total por estado + tasa de integridad
- `verifications`: total por resultado + tasa de éxito
- `users`: total activos por rol
- `last_24h`: actividad de las útimas 24 horas

Requiere rol **Analyst** o **Admin**.
    """
)
def get_stats(
    db: Session = Depends(get_db),
    current_user  = Depends(require_analyst)
):
    now = datetime.now(timezone.utc)

    # ── Cámaras ──────────────────────────────────────
    total_cameras  = db.query(func.count(Camera.id)).scalar() or 0
    active_cameras = db.query(func.count(Camera.id)).filter(Camera.is_active == True).scalar() or 0
    two_min_ago    = now - timedelta(minutes=2)
    online_cameras = db.query(func.count(Camera.id)).filter(
        Camera.is_active == True,
        Camera.last_seen >= two_min_ago
    ).scalar() or 0

    # ── Videos ──────────────────────────────────────
    total_videos   = db.query(func.count(Video.id)).scalar() or 0
    videos_by_status = {
        s.value: (db.query(func.count(Video.id)).filter(Video.status == s).scalar() or 0)
        for s in VideoStatus
    }

    # ── Segmentos ──────────────────────────────────
    total_segments = db.query(func.count(Segment.id)).scalar() or 0
    segs_by_status = {
        s.value: (db.query(func.count(Segment.id)).filter(Segment.status == s).scalar() or 0)
        for s in SegmentStatus
    }
    valid_segs     = segs_by_status.get("valid", 0)
    integrity_rate = round(valid_segs / total_segments * 100, 2) if total_segments > 0 else 0.0

    # ── Verificaciones ─────────────────────────────
    total_verifs   = db.query(func.count(Verification.id)).scalar() or 0
    verifs_by_result = {
        r.value: (db.query(func.count(Verification.id)).filter(Verification.result == r).scalar() or 0)
        for r in VerificationResult
    }
    pass_verifs    = verifs_by_result.get("pass", 0)
    success_rate   = round(pass_verifs / total_verifs * 100, 2) if total_verifs > 0 else 0.0

    # ── Usuarios ────────────────────────────────────
    total_users    = db.query(func.count(User.id)).scalar() or 0
    active_users   = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0
    users_by_role  = {
        r.value: (
            db.query(func.count(User.id))
            .filter(User.role == r, User.is_active == True)
            .scalar() or 0
        )
        for r in UserRole
    }

    # ── Actividad útimas 24 h ────────────────────────
    yesterday = now - timedelta(hours=24)
    verifs_24h   = db.query(func.count(Verification.id)).filter(
        Verification.verified_at >= yesterday
    ).scalar() or 0
    segments_24h = db.query(func.count(Segment.id)).filter(
        Segment.created_at >= yesterday
    ).scalar() or 0
    videos_24h   = db.query(func.count(Video.id)).filter(
        Video.created_at >= yesterday
    ).scalar() or 0

    return {
        "cameras": {
            "total":      total_cameras,
            "active":     active_cameras,
            "inactive":   total_cameras - active_cameras,
            "online_now": online_cameras,
        },
        "videos": {
            "total": total_videos,
            **videos_by_status,
        },
        "segments": {
            "total": total_segments,
            **segs_by_status,
            "integrity_rate_pct": integrity_rate,
        },
        "verifications": {
            "total": total_verifs,
            **verifs_by_result,
            "success_rate_pct": success_rate,
        },
        "users": {
            "total":   total_users,
            "active":  active_users,
            "by_role": users_by_role,
        },
        "last_24h": {
            "verifications":     verifs_24h,
            "segments_uploaded": segments_24h,
            "videos_started":    videos_24h,
        },
        "generated_at": now.isoformat(),
    }
