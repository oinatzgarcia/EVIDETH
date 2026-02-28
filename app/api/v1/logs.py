from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone
import csv, io

from app.db.session import get_db
from app.db.models import Verification, Video, Segment, Camera, VerificationResult, UserRole
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


def _collect_events(db, event_type, camera_id, user_id, date_from, date_to, current_user=None) -> list:
    """
    Recoge eventos de las 4 fuentes y los devuelve como lista de dicts homógeneos.

    Control de acceso por propietario de cámara:
    - Admin: ve eventos de todas las cámaras.
    - Analyst/Viewer: solo ve eventos de sus propias cámaras.
    """
    is_admin  = current_user is None or current_user.role == UserRole.ADMIN
    owner_id  = None if is_admin else str(current_user.id)

    events = []

    # ── Verificaciones ───────────────────────────────────────────
    if event_type in (None, "verification"):
        q = (
            db.query(Verification)
            .join(Segment,  Verification.segment_id == Segment.id)
            .join(Video,    Segment.video_id         == Video.id)
            .join(Camera,   Video.camera_id          == Camera.id)
        )
        if owner_id:  q = q.filter(Camera.owner_id == owner_id)   # ◄ ownership
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if user_id:   q = q.filter(Verification.verified_by_id == user_id)
        if date_from: q = q.filter(Verification.verified_at >= date_from)
        if date_to:   q = q.filter(Verification.verified_at <= date_to)

        for v in q.all():
            cam = v.segment.video.camera if (v.segment and v.segment.video) else None
            events.append({
                "event_type":      "verification",
                "timestamp":       v.verified_at,
                "camera_id":       cam.camera_id if cam else None,
                "video_id":        str(v.segment.video_id) if v.segment else None,
                "actor_id":        str(v.verified_by_id) if v.verified_by_id else None,
                "actor_type":      "user",
                "ip_address":      v.ip_address,
                "result":          v.result,
                "hash_match":      v.hash_match,
                "segment_index":   v.segment.segment_index if v.segment else None,
                "error_message":   v.error_message,
                "filename":        None,
                "fps":             None,
                "resolution":      None,
                "codec":           None,
                "duration_secs":   None,
                "status":          None,
                "sha256_hash":     None,
                "file_size_bytes": None,
            })

    # ── Videos iniciados ──────────────────────────────────────────
    if event_type in (None, "video_started"):
        q = db.query(Video).join(Camera, Video.camera_id == Camera.id)
        if owner_id:  q = q.filter(Camera.owner_id == owner_id)   # ◄ ownership
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if date_from: q = q.filter(Video.created_at >= date_from)
        if date_to:   q = q.filter(Video.created_at <= date_to)

        for v in q.all():
            events.append({
                "event_type":      "video_started",
                "timestamp":       v.created_at,
                "camera_id":       v.camera.camera_id if v.camera else None,
                "video_id":        str(v.id),
                "actor_id":        v.camera.camera_id if v.camera else None,
                "actor_type":      "camera",
                "ip_address":      None,
                "result":          None,
                "hash_match":      None,
                "segment_index":   None,
                "error_message":   None,
                "filename":        v.filename,
                "fps":             v.fps,
                "resolution":      v.resolution,
                "codec":           v.codec,
                "duration_secs":   None,
                "status":          v.status,
                "sha256_hash":     None,
                "file_size_bytes": None,
            })

    # ── Videos finalizados ───────────────────────────────────────
    if event_type in (None, "video_finished"):
        q = (
            db.query(Video)
            .join(Camera, Video.camera_id == Camera.id)
            .filter(Video.ended_at.isnot(None))
        )
        if owner_id:  q = q.filter(Camera.owner_id == owner_id)   # ◄ ownership
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if date_from: q = q.filter(Video.ended_at >= date_from)
        if date_to:   q = q.filter(Video.ended_at <= date_to)

        for v in q.all():
            events.append({
                "event_type":      "video_finished",
                "timestamp":       v.ended_at,
                "camera_id":       v.camera.camera_id if v.camera else None,
                "video_id":        str(v.id),
                "actor_id":        v.camera.camera_id if v.camera else None,
                "actor_type":      "camera",
                "ip_address":      None,
                "result":          None,
                "hash_match":      None,
                "segment_index":   None,
                "error_message":   None,
                "filename":        v.filename,
                "fps":             None,
                "resolution":      None,
                "codec":           None,
                "duration_secs":   v.duration_secs,
                "status":          v.status,
                "sha256_hash":     None,
                "file_size_bytes": None,
            })

    # ── Segmentos subidos ──────────────────────────────────────────
    if event_type in (None, "segment_uploaded"):
        q = (
            db.query(Segment)
            .join(Video,  Segment.video_id  == Video.id)
            .join(Camera, Video.camera_id   == Camera.id)
        )
        if owner_id:  q = q.filter(Camera.owner_id == owner_id)   # ◄ ownership
        if camera_id: q = q.filter(Camera.camera_id == camera_id)
        if date_from: q = q.filter(Segment.created_at >= date_from)
        if date_to:   q = q.filter(Segment.created_at <= date_to)

        for s in q.all():
            cam = s.video.camera if s.video else None
            events.append({
                "event_type":      "segment_uploaded",
                "timestamp":       s.created_at,
                "camera_id":       cam.camera_id if cam else None,
                "video_id":        str(s.video_id),
                "actor_id":        cam.camera_id if cam else None,
                "actor_type":      "camera",
                "ip_address":      None,
                "result":          None,
                "hash_match":      None,
                "segment_index":   s.segment_index,
                "error_message":   None,
                "filename":        None,
                "fps":             None,
                "resolution":      None,
                "codec":           None,
                "duration_secs":   None,
                "status":          s.status,
                "sha256_hash":     s.sha256_hash,
                "file_size_bytes": s.file_size_bytes,
            })

    events.sort(key=lambda e: _ts(e["timestamp"]), reverse=True)
    return events


def _result_str(val) -> str:
    """Normaliza un valor de resultado (str o enum) a string en minúsculas."""
    if val is None:
        return ""
    return str(val.value if hasattr(val, "value") else val).lower()


def _compute_counts(events: list) -> dict:
    """
    Calcula los contadores de resumen a partir del conjunto completo de eventos
    (antes de aplicar filtros de event_type / result).
    """
    verification = sum(1 for e in events if e["event_type"] == "verification")
    tampered     = sum(
        1 for e in events
        if e["event_type"] == "verification"
        and _result_str(e.get("result")) in ("fail", "tampered")
    )
    recording    = sum(1 for e in events if e["event_type"] == "video_started")
    return {
        "verification": verification,
        "tampered":     tampered,
        "recording":    recording,
    }


# ── 1. Log de actividad paginado ────────────────────────────

@router.get(
    "/activity",
    summary="Log de actividad del sistema",
    description="""
Devuelve un log cronológico unificado de eventos del sistema.

- **Admin**: ve eventos de todas las cámaras.
- **Analyst/Viewer**: solo ve eventos de sus propias cámaras.

**Tipos de eventos:**
- `verification`: verificación de integridad realizada por un analista
- `video_started`: cámara inició una grabación
- `video_finished`: cámara finalizó una grabación
- `segment_uploaded`: cámara registró un segmento de 30s

**Filtros:**
- `event_type`, `result`, `camera_id`, `user_id`, `date_from`, `date_to`
- `page` / `per_page`: paginación

El campo `counts` refleja los totales del rango/cámara, independientemente
de los filtros `event_type` y `result`.

Requiere rol **Analyst** o **Admin**.
    """
)
def get_activity_log(
    event_type: Optional[str]      = Query(None,  description="verification | video_started | video_finished | segment_uploaded"),
    result:     Optional[str]      = Query(None,  description="Filtrar verifs por resultado: pass | fail | error"),
    camera_id:  Optional[str]      = Query(None,  description="Filtrar por camera_id físico"),
    user_id:    Optional[str]      = Query(None,  description="Filtrar por user ID (solo eventos 'verification')"),
    date_from:  Optional[datetime] = Query(None,  description="Desde (ISO 8601)"),
    date_to:    Optional[datetime] = Query(None,  description="Hasta (ISO 8601)"),
    page:       int                = Query(1,    ge=1),
    per_page:   int                = Query(20,   ge=1, le=100),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst)
):
    # 1. Recoge eventos con ownership filter (sin event_type ni result para contadores globales)
    all_events = _collect_events(db, None, camera_id, user_id, date_from, date_to, current_user)

    # 2. Contadores estables antes de filtrar por tipo/resultado
    counts = _compute_counts(all_events)

    # 3. Aplica filtros de event_type y result
    filtered = all_events
    if event_type:
        filtered = [e for e in filtered if e["event_type"] == event_type]
    if result:
        result_lower = result.lower()
        filtered = [
            e for e in filtered
            if e["event_type"] == "verification"
            and _result_str(e.get("result")) == result_lower
        ]

    # 4. Pagina
    total = len(filtered)
    start = (page - 1) * per_page
    items = filtered[start: start + per_page]

    def to_response(e):
        return {
            "event_type": e["event_type"],
            "timestamp":  e["timestamp"],
            "camera_id":  e["camera_id"],
            "video_id":   e["video_id"],
            "actor_id":   e["actor_id"],
            "actor_type": e["actor_type"],
            "ip_address": e["ip_address"],
            "detail":     {k: e[k] for k in (
                "result", "hash_match", "segment_index", "error_message",
                "filename", "fps", "resolution", "codec",
                "duration_secs", "status", "sha256_hash", "file_size_bytes"
            ) if e.get(k) is not None},
        }

    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
        "counts":   counts,
        "items":    [to_response(e) for e in items],
    }


# ── 2. Exportación CSV del log de actividad ──────────────────────

@router.get(
    "/activity/export",
    summary="Exportar log de actividad a CSV",
    description="""
Descarga el log de actividad en formato CSV.

- **Admin**: exporta eventos de todas las cámaras.
- **Analyst/Viewer**: exporta solo eventos de sus propias cámaras.

El fichero se genera en streaming (sin cargar todo en RAM).
Requiere rol **Analyst** o **Admin**.
    """
)
def export_activity_log(
    event_type: Optional[str]      = Query(None,  description="verification | video_started | video_finished | segment_uploaded"),
    result:     Optional[str]      = Query(None,  description="Filtrar verifs por resultado: pass | fail | error"),
    camera_id:  Optional[str]      = Query(None,  description="Filtrar por camera_id físico"),
    user_id:    Optional[str]      = Query(None,  description="Filtrar por user ID"),
    date_from:  Optional[datetime] = Query(None,  description="Desde (ISO 8601)"),
    date_to:    Optional[datetime] = Query(None,  description="Hasta (ISO 8601)"),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst)
):
    events = _collect_events(db, event_type, camera_id, user_id, date_from, date_to, current_user)

    if result:
        result_lower = result.lower()
        events = [
            e for e in events
            if e["event_type"] == "verification"
            and _result_str(e.get("result")) == result_lower
        ]

    CSV_COLS = [
        "timestamp", "event_type", "camera_id", "video_id",
        "actor_id", "actor_type", "ip_address",
        "result", "hash_match", "segment_index", "error_message",
        "filename", "fps", "resolution", "codec", "duration_secs", "status",
        "sha256_hash", "file_size_bytes",
    ]

    def iter_csv():
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)

        writer.writerow(CSV_COLS)
        yield buf.getvalue()
        buf.seek(0); buf.truncate(0)

        for e in events:
            ts = e["timestamp"]
            writer.writerow([
                ts.isoformat() if ts else "",
                e["event_type"] or "",
                e["camera_id"]  or "",
                e["video_id"]   or "",
                e["actor_id"]   or "",
                e["actor_type"] or "",
                e["ip_address"] or "",
                _result_str(e["result"]) if e["result"] is not None else "",
                e["hash_match"]      if e["hash_match"]      is not None else "",
                e["segment_index"]   if e["segment_index"]   is not None else "",
                e["error_message"]   or "",
                e["filename"]        or "",
                e["fps"]             if e["fps"]             is not None else "",
                e["resolution"]      or "",
                e["codec"]           or "",
                e["duration_secs"]   if e["duration_secs"]   is not None else "",
                str(e["status"].value if hasattr(e["status"], "value") else e["status"] or ""),
                e["sha256_hash"]     or "",
                e["file_size_bytes"] if e["file_size_bytes"] is not None else "",
            ])
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"evideth_activity_log_{ts}.csv"

    return StreamingResponse(
        iter_csv(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )
