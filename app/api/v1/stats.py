from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timezone, timedelta

from app.db.session import get_db
from app.db.models import (
    User,
    Camera,
    Video,
    Segment,
    Verification,
    UserRole,
    VideoStatus,
    SegmentStatus,
    VerificationResult,
)
from app.core.dependencies import require_analyst


# Debe coincidir con CAMERA_ONLINE_THRESHOLD_SECONDS en cameras.py
CAMERA_ONLINE_THRESHOLD_SECONDS = 60


router = APIRouter(
    prefix="/stats",
    tags=["Statistics"],
    responses={
        401: {"description": "JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    },
)


@router.get(
    "/",
    summary="Estadísticas del sistema",
    description="""
Devuelve estadísticas agregadas en tiempo real.

- **Admin**: ve estadísticas globales de todo el sistema, incluida la sección `users`.
- **Analyst/Viewer**: ve estadísticas acotadas a sus propias cámaras
  (cámaras, videos, segmentos y verificaciones). La sección `users` no se incluye.

**Secciones:**
- `cameras`: total, activas, inactivas y online ahora mismo
- `videos`: total por estado
- `segments`: total por estado + tasa de integridad
- `verifications`: total por resultado + tasa de éxito
- `users`: total activos por rol (**solo Admin**)
- `last_24h`: actividad de las últimas 24 horas

Requiere rol **Analyst** o **Admin**.
    """,
)
def get_stats(db: Session = Depends(get_db), current_user=Depends(require_analyst)):
    now = datetime.now(timezone.utc)
    is_admin = current_user.role == UserRole.ADMIN

    # Umbral de online: consistente con cameras.py
    online_threshold = now - timedelta(seconds=CAMERA_ONLINE_THRESHOLD_SECONDS)

    # ── Subquery de cámaras accesibles para el usuario ──────────────────────
    # Admin: todas las cámaras. Analyst/Viewer: solo las propias.
    cam_q = db.query(Camera)
    if not is_admin:
        cam_q = cam_q.filter(Camera.owner_id == str(current_user.id))

    # IDs de cámaras accesibles — usado para filtrar videos/segmentos/verifs
    owned_cam_ids = db.query(Camera.id)
    if not is_admin:
        owned_cam_ids = owned_cam_ids.filter(Camera.owner_id == str(current_user.id))
    owned_cam_ids_sq = owned_cam_ids.subquery()

    # ── Cámaras ────────────────────────────────────────────────
    total_cameras = cam_q.count()
    active_cameras = cam_q.filter(Camera.is_active).count()
    online_cameras = cam_q.filter(
        Camera.is_active, Camera.last_seen >= online_threshold
    ).count()

    # ── Videos ────────────────────────────────────────────────
    vid_q = db.query(Video).filter(Video.camera_id.in_(owned_cam_ids_sq))
    total_videos = vid_q.count()
    videos_by_status = {
        s.value: (vid_q.filter(Video.status == s).count()) for s in VideoStatus
    }

    # ── Segmentos ─────────────────────────────────────────────
    owned_vid_ids_sq = (
        db.query(Video.id).filter(Video.camera_id.in_(owned_cam_ids_sq)).subquery()
    )

    seg_q = db.query(Segment).filter(Segment.video_id.in_(owned_vid_ids_sq))
    total_segments = seg_q.count()
    segs_by_status = {
        s.value: (seg_q.filter(Segment.status == s).count()) for s in SegmentStatus
    }
    valid_segs = segs_by_status.get("valid", 0)
    integrity_rate = (
        round(valid_segs / total_segments * 100, 2) if total_segments > 0 else 0.0
    )

    # ── Verificaciones ─────────────────────────────────────────
    owned_seg_ids_sq = (
        db.query(Segment.id).filter(Segment.video_id.in_(owned_vid_ids_sq)).subquery()
    )

    verif_q = db.query(Verification).filter(
        Verification.segment_id.in_(owned_seg_ids_sq)
    )
    total_verifs = verif_q.count()
    verifs_by_result = {
        r.value: (verif_q.filter(Verification.result == r).count())
        for r in VerificationResult
    }
    pass_verifs = verifs_by_result.get("pass", 0)
    success_rate = (
        round(pass_verifs / total_verifs * 100, 2) if total_verifs > 0 else 0.0
    )

    # ── Usuarios (solo Admin) ───────────────────────────────────
    # Analistas y viewers no necesitan conocer la distribución de usuarios
    # del sistema — es información sensible de la plataforma.
    users_section = None
    if is_admin:
        total_users = db.query(func.count(User.id)).scalar() or 0
        active_users = (
            db.query(func.count(User.id)).filter(User.is_active).scalar() or 0
        )
        users_by_role = {
            r.value: (
                db.query(func.count(User.id))
                .filter(User.role == r, User.is_active)
                .scalar()
                or 0
            )
            for r in UserRole
        }
        users_section = {
            "total": total_users,
            "active": active_users,
            "by_role": users_by_role,
        }

    # ── Actividad últimas 24 h (acotada por ownership) ───────────────
    yesterday = now - timedelta(hours=24)
    verifs_24h = verif_q.filter(Verification.verified_at >= yesterday).count()
    segments_24h = seg_q.filter(Segment.created_at >= yesterday).count()
    videos_24h = vid_q.filter(Video.created_at >= yesterday).count()

    response = {
        "cameras": {
            "total": total_cameras,
            "active": active_cameras,
            "inactive": total_cameras - active_cameras,
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
        "last_24h": {
            "verifications": verifs_24h,
            "segments_uploaded": segments_24h,
            "videos_started": videos_24h,
        },
        "generated_at": now.isoformat(),
    }

    if users_section:
        response["users"] = users_section

    return response
