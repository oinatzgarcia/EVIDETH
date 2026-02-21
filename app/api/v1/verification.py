from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone
import tempfile, os, shutil, csv, io

from app.db.session import get_db
from app.db.models import Video, Camera, Verification, Segment, VerificationResult
from app.core.dependencies import require_analyst
from app.services.verifier import verify_video
from app.schemas.verification import VerificationReport


router = APIRouter(
    prefix="/verification",
    tags=["Verification"],
    responses={
        401: {"description": "JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    }
)


# ── Helper: construye la query de verificaciones con los filtros comunes ──

def _build_verification_query(db, camera_id, result, date_from, date_to):
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
    if date_from:
        query = query.filter(Verification.verified_at >= date_from)
    if date_to:
        query = query.filter(Verification.verified_at <= date_to)
    return query


# ── 1. Listado global con filtros + paginación ────────────

@router.get(
    "/",
    summary="Listar verificaciones",
    description="""
Devuelve todas las verificaciones del sistema con filtros y paginación.

**Filtros:**
- `camera_id`: ID físico de la cámara
- `result`: resultado (`pass`, `fail`, `error`)
- `date_from` / `date_to`: rango de fechas (ISO 8601)
- `page` / `per_page`: paginación
    """
)
def list_verifications(
    camera_id:  Optional[str]      = Query(None, description="Filtrar por camera_id"),
    result:     Optional[str]      = Query(None, description="pass | fail | error"),
    date_from:  Optional[datetime] = Query(None, description="Desde (ISO 8601)"),
    date_to:    Optional[datetime] = Query(None, description="Hasta (ISO 8601)"),
    page:       int                = Query(1,    ge=1),
    per_page:   int                = Query(20,   ge=1, le=100),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst)
):
    query = _build_verification_query(db, camera_id, result, date_from, date_to)

    total = query.count()
    items = (
        query.order_by(Verification.verified_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
        "items": [
            {
                "id":              str(v.id),
                "segment_id":      str(v.segment_id),
                "result":          v.result,
                "hash_match":      v.hash_match,
                "signature_valid": v.signature_valid,
                "computed_hash":   v.computed_hash,
                "stored_hash":     v.stored_hash,
                "error_message":   v.error_message,
                "verified_at":     v.verified_at,
                "ip_address":      v.ip_address,
                "verified_by_id":  str(v.verified_by_id) if v.verified_by_id else None,
                "video_id":        str(v.segment.video_id) if v.segment else None,
                "camera_id": (
                    v.segment.video.camera.camera_id
                    if v.segment and v.segment.video and v.segment.video.camera
                    else None
                ),
            }
            for v in items
        ],
    }


# ── 2. Exportación CSV ───────────────────────────────
# Definido ANTES de /{verification_id} para evitar conflicto de rutas.

@router.get(
    "/export",
    summary="Exportar verificaciones a CSV",
    description="""
Descarga un fichero CSV con todas las verificaciones que cumplan los filtros.

**Columnas exportadas:**
`id`, `camera_id`, `video_id`, `segment_id`, `segment_index`,
`result`, `hash_match`, `signature_valid`,
`computed_hash`, `stored_hash`, `error_message`,
`verified_at` (ISO 8601), `verified_by_id`, `ip_address`

**Filtros:** mismos que `GET /verification/`

El fichero se genera en streaming (sin cargar todo en RAM).
Requiere rol **Analyst** o **Admin**.
    """
)
def export_verifications(
    camera_id:  Optional[str]      = Query(None, description="Filtrar por camera_id"),
    result:     Optional[str]      = Query(None, description="pass | fail | error"),
    date_from:  Optional[datetime] = Query(None, description="Desde (ISO 8601)"),
    date_to:    Optional[datetime] = Query(None, description="Hasta (ISO 8601)"),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst)
):
    verifications = (
        _build_verification_query(db, camera_id, result, date_from, date_to)
        .order_by(Verification.verified_at.desc())
        .all()
    )

    HEADERS = [
        "id", "camera_id", "video_id", "segment_id", "segment_index",
        "result", "hash_match", "signature_valid",
        "computed_hash", "stored_hash", "error_message",
        "verified_at", "verified_by_id", "ip_address",
    ]

    def iter_csv():
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)

        # Cabecera
        writer.writerow(HEADERS)
        yield buf.getvalue()
        buf.seek(0); buf.truncate(0)

        # Filas
        for v in verifications:
            cam = (
                v.segment.video.camera
                if v.segment and v.segment.video and v.segment.video.camera
                else None
            )
            writer.writerow([
                str(v.id),
                cam.camera_id if cam else "",
                str(v.segment.video_id) if v.segment else "",
                str(v.segment_id) if v.segment_id else "",
                v.segment.segment_index if v.segment else "",
                v.result if v.result else "",
                v.hash_match,
                v.signature_valid,
                v.computed_hash or "",
                v.stored_hash or "",
                v.error_message or "",
                v.verified_at.isoformat() if v.verified_at else "",
                str(v.verified_by_id) if v.verified_by_id else "",
                v.ip_address or "",
            ])
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)

    # Nombre de fichero con timestamp UTC para evitar colisiones
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"evideth_verifications_{ts}.csv"

    return StreamingResponse(
        iter_csv(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # Necesario para que el frontend pueda leer el header en CORS
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


# ── 3. Subida y verificación de video ──────────────────

@router.post(
    "/upload",
    response_model=VerificationReport,
    summary="Subir video para verificación de integridad"
)
async def upload_and_verify(
    request:     Request,
    video:       UploadFile = File(...),
    camera_id:   str        = Form(...),
    video_db_id: str        = Form(...),
    db:          Session    = Depends(get_db),
    current_user            = Depends(require_analyst)
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")

    video_db = db.query(Video).filter(
        Video.id == video_db_id, Video.camera_id == camera.id
    ).first()
    if not video_db:
        raise HTTPException(status_code=404, detail="Video no encontrado en BD")

    ext = os.path.splitext(video.filename)[1].lower()
    if ext not in {".mp4", ".avi", ".mkv", ".mov"}:
        raise HTTPException(status_code=400, detail="Formato no permitido")

    temp_dir   = tempfile.mkdtemp(prefix="evideth_upload_")
    video_path = os.path.join(temp_dir, f"upload{ext}")

    try:
        with open(video_path, "wb") as f:
            shutil.copyfileobj(video.file, f)

        report = verify_video(
            video_path=video_path,
            camera_id=camera_id,
            video_db_id=video_db_id,
            db=db,
            verified_by_id=str(current_user.id),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        return report
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=f"Error procesando video: {str(e)}")
    finally:
        if os.path.exists(video_path):
            os.remove(video_path)
        try:
            os.rmdir(temp_dir)
        except Exception:
            pass


# ── 4. Historial de un video con filtros + paginación ──

@router.get(
    "/history/{video_id}",
    summary="Historial de verificaciones de un video",
    description="""
Devuelve las verificaciones realizadas sobre un video con filtros y paginación.

**Filtros:**
- `result`: resultado (`pass`, `fail`, `error`)
- `page` / `per_page`: paginación
    """
)
def verification_history(
    video_id: str,
    result:   Optional[str] = Query(None, description="pass | fail | error"),
    page:     int           = Query(1,    ge=1),
    per_page: int           = Query(20,   ge=1, le=100),
    db:       Session       = Depends(get_db),
    current_user            = Depends(require_analyst)
):
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")

    segment_ids = [s.id for s in db.query(Segment).filter(Segment.video_id == video_id).all()]

    query = db.query(Verification).filter(Verification.segment_id.in_(segment_ids))

    if result:
        try:
            query = query.filter(Verification.result == VerificationResult(result))
        except ValueError:
            raise HTTPException(status_code=400, detail="result debe ser: pass, fail, error")

    total = query.count()
    verifications = (
        query.order_by(Verification.verified_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "video_id":      video_id,
        "total":         total,
        "page":          page,
        "per_page":      per_page,
        "pages":         (total + per_page - 1) // per_page,
        "verifications": [
            {
                "id":              str(v.id),
                "segment_id":      str(v.segment_id),
                "result":          v.result,
                "hash_match":      v.hash_match,
                "signature_valid": v.signature_valid,
                "verified_at":     v.verified_at,
                "ip_address":      v.ip_address,
            }
            for v in verifications
        ],
    }


# ── 5. Detalle de una verificación por ID ──────────────
# DEBE ir después de /export e /history/{id} para no capturar esos paths.

@router.get(
    "/{verification_id}",
    summary="Obtener verificación por ID",
    description="Detalle completo con segmento, video y cámara asociados."
)
def get_verification(
    verification_id: str,
    db:              Session = Depends(get_db),
    current_user             = Depends(require_analyst)
):
    v = db.query(Verification).filter(Verification.id == verification_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Verificación no encontrada")

    segment = v.segment
    video   = segment.video  if segment else None
    camera  = video.camera   if video   else None

    return {
        "id":              str(v.id),
        "result":          v.result,
        "hash_match":      v.hash_match,
        "signature_valid": v.signature_valid,
        "computed_hash":   v.computed_hash,
        "stored_hash":     v.stored_hash,
        "error_message":   v.error_message,
        "verified_at":     v.verified_at,
        "ip_address":      v.ip_address,
        "user_agent":      v.user_agent,
        "verified_by_id":  str(v.verified_by_id) if v.verified_by_id else None,
        "segment": {
            "id":              str(segment.id),
            "segment_index":   segment.segment_index,
            "start_time_secs": segment.start_time_secs,
            "end_time_secs":   segment.end_time_secs,
            "sha256_hash":     segment.sha256_hash,
            "status":          segment.status,
        } if segment else None,
        "video":  {"id": str(video.id),   "filename": video.filename,   "status": video.status}  if video  else None,
        "camera": {"camera_id": camera.camera_id, "name": camera.name,  "location": camera.location} if camera else None,
    }
