from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from sqlalchemy.orm import Session
from typing import Optional
import tempfile, os, shutil

from app.db.session import get_db
from app.db.models import Video, Camera, Verification, Segment
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


# ── 1. Subida y verificación de video ────────────────

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
    # Valida que la cámara existe
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")

    # Valida que el video existe en BD y pertenece a la cámara
    video_db = db.query(Video).filter(
        Video.id == video_db_id,
        Video.camera_id == camera.id
    ).first()
    if not video_db:
        raise HTTPException(status_code=404, detail="Video no encontrado en BD o no pertenece a esta cámara")

    # Valida extensión del archivo
    allowed_extensions = {".mp4", ".avi", ".mkv", ".mov"}
    ext = os.path.splitext(video.filename)[1].lower()
    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"Formato no permitido. Use: {allowed_extensions}")

    # Guarda el video en disco temporal
    temp_dir = tempfile.mkdtemp(prefix="evideth_upload_")
    video_path = os.path.join(temp_dir, f"upload{ext}")

    try:
        with open(video_path, "wb") as f:
            shutil.copyfileobj(video.file, f)

        # Obtiene IP y user agent para auditoría
        ip = request.client.host if request.client else None
        ua = request.headers.get("user-agent")

        # Ejecuta verificación completa
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
        # Limpia el video subido siempre
        if os.path.exists(video_path):
            os.remove(video_path)
        try:
            os.rmdir(temp_dir)
        except Exception:
            pass


# ── 2. Historial de verificaciones de un video ────────

@router.get(
    "/history/{video_id}",
    summary="Historial de verificaciones",
    description="Devuelve todas las verificaciones realizadas sobre un video."
)
def verification_history(
    video_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")

    segments = db.query(Segment).filter(Segment.video_id == video_id).all()
    segment_ids = [s.id for s in segments]

    verifications = db.query(Verification).filter(
        Verification.segment_id.in_(segment_ids)
    ).order_by(Verification.verified_at.desc()).all()

    return {
        "video_id": video_id,
        "total_verifications": len(verifications),
        "verifications": [
            {
                "id": str(v.id),
                "segment_id": str(v.segment_id),
                "result": v.result,
                "hash_match": v.hash_match,
                "signature_valid": v.signature_valid,
                "verified_at": v.verified_at,
                "ip_address": v.ip_address,
            }
            for v in verifications
        ]
    }
