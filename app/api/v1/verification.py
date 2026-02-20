from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
import tempfile, os, shutil

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


# ── 1. Listado global de verificaciones (Analyst+) ───
# NOTA: Definido ANTES de /{verification_id} para evitar que FastAPI
# intente resolver 'upload' o 'history' como un UUID.

@router.get(
    "/",
    summary="Listar verificaciones",
    description="""
Devuelve todas las verificaciones del sistema con paginación y filtros.

Filtros disponibles:
- `camera_id`: ID físico de la cámara
- `result`: resultado de la verificación (`pass`, `fail`, `error`)
- `date_from` / `date_to`: rango de fechas ISO 8601 (ej: `2026-01-01T00:00:00Z`)
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
    query = (
        db.query(Verification)
        .join(Segment,  Verification.segment_id == Segment.id)
        .join(Video,    Segment.video_id == Video.id)
        .join(Camera,   Video.camera_id  == Camera.id)
    )

    if camera_id:
        query = query.filter(Camera.camera_id == camera_id)

    if result:
        try:
            result_enum = VerificationResult(result)
            query = query.filter(Verification.result == result_enum)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="result debe ser uno de: pass, fail, error"
            )

    if date_from:
        query = query.filter(Verification.verified_at >= date_from)
    if date_to:
        query = query.filter(Verification.verified_at <= date_to)

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
                "id":               str(v.id),
                "segment_id":       str(v.segment_id),
                "result":           v.result,
                "hash_match":       v.hash_match,
                "signature_valid":  v.signature_valid,
                "computed_hash":    v.computed_hash,
                "stored_hash":      v.stored_hash,
                "error_message":    v.error_message,
                "verified_at":      v.verified_at,
                "ip_address":       v.ip_address,
                "verified_by_id":   str(v.verified_by_id) if v.verified_by_id else None,
                "video_id":         str(v.segment.video_id) if v.segment else None,
                "camera_id":        (
                    v.segment.video.camera.camera_id
                    if v.segment and v.segment.video and v.segment.video.camera
                    else None
                ),
            }
            for v in items
        ]
    }


# ── 2. Subida y verificación de video ──────────────────

@router.post(
    "/upload",
    response_model=VerificationReport,
    summary="Subir video para verificación de integridad",
    description="""
Sube un archivo de video y lo verifica contra los hashes almacenados en BD.

**Proceso:**
1. Segmenta el video en chunks de 30 segundos
2. Calcula SHA-256 de cada chunk
3. Compara con los hashes firmados por la cámara
4. Devuelve informe detallado de integridad

Requiere rol **Analyst** o **Admin**.
    """
)
async def upload_and_verify(
    request: Request,
    video: UploadFile = File(..., description="Archivo de video a verificar"),
    camera_id: str = Form(..., description="ID de la cámara que grabó el video"),
    video_db_id: str = Form(..., description="ID del video en la base de datos"),
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")

    video_db = db.query(Video).filter(
        Video.id == video_db_id,
        Video.camera_id == camera.id
    ).first()
    if not video_db:
        raise HTTPException(status_code=404, detail="Video no encontrado en BD o no pertenece a esta cámara")

    allowed_extensions = {".mp4", ".avi", ".mkv", ".mov"}
    ext = os.path.splitext(video.filename)[1].lower()
    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"Formato no permitido. Use: {allowed_extensions}")

    temp_dir   = tempfile.mkdtemp(prefix="evideth_upload_")
    video_path = os.path.join(temp_dir, f"upload{ext}")

    try:
        with open(video_path, "wb") as f:
            shutil.copyfileobj(video.file, f)

        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")

        report = verify_video(
            video_path=video_path,
            camera_id=camera_id,
            video_db_id=video_db_id,
            db=db,
            verified_by_id=str(current_user.id),
            ip_address=ip,
            user_agent=ua
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


# ── 3. Historial de verificaciones de un video ─────────

@router.get(
    "/history/{video_id}",
    summary="Historial de verificaciones",
    description="Devuelve todas las verificaciones realizadas sobre un video específico."
)
def verification_history(
    video_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")

    segments     = db.query(Segment).filter(Segment.video_id == video_id).all()
    segment_ids  = [s.id for s in segments]

    verifications = db.query(Verification).filter(
        Verification.segment_id.in_(segment_ids)
    ).order_by(Verification.verified_at.desc()).all()

    return {
        "video_id":            video_id,
        "total_verifications": len(verifications),
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
        ]
    }


# ── 4. Detalle de una verificación por ID ──────────────

@router.get(
    "/{verification_id}",
    summary="Obtener verificación por ID",
    description="Devuelve el detalle completo de una verificación específica, incluyendo el segmento, video y cámara asociados."
)
def get_verification(
    verification_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    v = db.query(Verification).filter(Verification.id == verification_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Verificación no encontrada")

    segment = v.segment
    video   = segment.video  if segment else None
    camera  = video.camera   if video   else None

    return {
        "id":               str(v.id),
        "result":           v.result,
        "hash_match":       v.hash_match,
        "signature_valid":  v.signature_valid,
        "computed_hash":    v.computed_hash,
        "stored_hash":      v.stored_hash,
        "error_message":    v.error_message,
        "verified_at":      v.verified_at,
        "ip_address":       v.ip_address,
        "user_agent":       v.user_agent,
        "verified_by_id":   str(v.verified_by_id) if v.verified_by_id else None,
        "segment": {
            "id":              str(segment.id),
            "segment_index":   segment.segment_index,
            "start_time_secs": segment.start_time_secs,
            "end_time_secs":   segment.end_time_secs,
            "sha256_hash":     segment.sha256_hash,
            "status":          segment.status,
        } if segment else None,
        "video": {
            "id":       str(video.id),
            "filename": video.filename,
            "status":   video.status,
        } if video else None,
        "camera": {
            "camera_id": camera.camera_id,
            "name":      camera.name,
            "location":  camera.location,
        } if camera else None,
    }
