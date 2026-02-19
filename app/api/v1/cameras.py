from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone
from app.db.session import get_db
from app.db.models import Camera, Segment, Video, SegmentStatus, VideoStatus
from app.core.security import generate_api_key, hash_api_key
from app.core.dependencies import require_admin, require_analyst, get_current_camera
from pydantic import BaseModel, field_validator
import re


router = APIRouter(
    prefix="/cameras",
    tags=["Cameras"],
    responses={
        401: {"description": "API Key o JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    }
)


# ── Schemas ───────────────────────────────────────────

class CameraCreate(BaseModel):
    camera_id: str
    name: str
    location: Optional[str] = None
    description: Optional[str] = None

    @field_validator('camera_id')
    @classmethod
    def validate_camera_id(cls, v):
        if not re.match(r'^[A-Za-z0-9_-]{3,100}$', v):
            raise ValueError('camera_id solo permite letras, números, guiones y guiones bajos (3-100 chars)')
        return v


class CameraResponse(BaseModel):
    camera_id: str
    name: str
    location: Optional[str]
    is_active: bool
    api_key: Optional[str] = None      # Solo se devuelve al crear

    model_config = {"from_attributes": True}


class SegmentUpload(BaseModel):
    video_id: str
    segment_index: int
    start_time_secs: int
    end_time_secs: int
    sha256_hash: str
    ecdsa_signature: Optional[str] = None
    public_key_id: Optional[str] = None
    file_size_bytes: Optional[int] = None

    @field_validator('sha256_hash')
    @classmethod
    def validate_sha256(cls, v):
        if not re.match(r'^[a-fA-F0-9]{64}$', v):
            raise ValueError('sha256_hash debe ser exactamente 64 caracteres hexadecimales')
        return v.lower()

    @field_validator('segment_index')
    @classmethod
    def validate_index(cls, v):
        if v < 0:
            raise ValueError('segment_index debe ser >= 0')
        return v

    @field_validator('end_time_secs')
    @classmethod
    def validate_duration(cls, v, info):
        start = info.data.get('start_time_secs', 0)
        if v <= start:
            raise ValueError('end_time_secs debe ser mayor que start_time_secs')
        if (v - start) > 60:
            raise ValueError('La duración del segmento no puede superar 60 segundos')
        return v

    @field_validator('file_size_bytes')
    @classmethod
    def validate_size(cls, v):
        if v is not None:
            if v <= 0:
                raise ValueError('file_size_bytes debe ser > 0')
            if v > 500 * 1024 * 1024:
                raise ValueError('file_size_bytes supera el límite de 500 MB')
        return v


class SegmentResponse(BaseModel):
    id: str
    segment_index: int
    sha256_hash: str
    status: str
    signed_at: Optional[datetime]
    created_at: Optional[datetime]

    model_config = {"from_attributes": True}


class VideoCreate(BaseModel):
    filename: str
    fps: Optional[float] = None
    resolution: Optional[str] = None
    codec: Optional[str] = None


class VideoResponse(BaseModel):
    id: str
    filename: str
    status: str
    fps: Optional[float]
    resolution: Optional[str]
    codec: Optional[str]
    started_at: Optional[datetime]
    created_at: Optional[datetime]

    model_config = {"from_attributes": True}


# ── 1. Registrar cámara (solo Admin) ─────────────────

@router.post(
    "/",
    response_model=CameraResponse,
    status_code=201,
    summary="Registrar nueva cámara",
    description="""
Registra una nueva cámara en el sistema. **Solo Admin**.

La API Key generada se devuelve **una única vez** — guárdala en un lugar seguro.
La cámara usará esta API Key en el header `X-API-Key` para todas sus peticiones.
    """
)
def register_camera(
    data: CameraCreate,
    db: Session = Depends(get_db),
    current_user = Depends(require_admin)
):
    if db.query(Camera).filter(Camera.camera_id == data.camera_id).first():
        raise HTTPException(status_code=400, detail="camera_id ya registrado")

    raw_key = generate_api_key()

    camera = Camera(
        camera_id=data.camera_id,
        name=data.name,
        location=data.location,
        description=data.description,
        api_key=hash_api_key(raw_key),
        owner_id=str(current_user.id)
    )
    db.add(camera)
    db.commit()
    db.refresh(camera)

    return CameraResponse(
        camera_id=camera.camera_id,
        name=camera.name,
        location=camera.location,
        is_active=camera.is_active,
        api_key=raw_key
    )


# ── 2. Listar cámaras (Admin + Analyst) ──────────────

@router.get(
    "/",
    response_model=list[CameraResponse],
    summary="Listar cámaras activas",
    description="Devuelve todas las cámaras activas del sistema. Requiere rol Analyst o Admin."
)
def list_cameras(
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    return db.query(Camera).filter(Camera.is_active == True).all()


# ── 3. Estado de cámara (Admin + Analyst) ────────────

@router.get(
    "/{camera_id}/status",
    summary="Estado de una cámara",
    description="""
Devuelve el estado actual de la cámara:
- Última conexión (`last_seen`)
- Si está **online** (heartbeat < 2 minutos)
- Video activo en grabación
- Estadísticas de segmentos e integridad
    """
)
def camera_status(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")

    active_video = db.query(Video).filter(
        Video.camera_id == camera.id,
        Video.status == VideoStatus.RECORDING
    ).first()

    total_segments = db.query(Segment).join(Video).filter(
        Video.camera_id == camera.id
    ).count()

    invalid_segments = db.query(Segment).join(Video).filter(
        Video.camera_id == camera.id,
        Segment.status == SegmentStatus.INVALID
    ).count()

    is_online = (
        camera.last_seen is not None and
        (datetime.now(timezone.utc) - camera.last_seen).seconds < 120   # ✅ fix
    )

    return {
        "camera_id": camera.camera_id,
        "name": camera.name,
        "location": camera.location,
        "is_active": camera.is_active,
        "last_seen": camera.last_seen,
        "online": is_online,
        "active_video": {
            "id": active_video.id,
            "filename": active_video.filename,
            "started_at": active_video.started_at
        } if active_video else None,
        "stats": {
            "total_segments": total_segments,
            "invalid_segments": invalid_segments,
            "integrity_ok": invalid_segments == 0
        }
    }


# ── 4. Iniciar grabación de video (API Key) ───────────

@router.post(
    "/videos",
    response_model=VideoResponse,
    status_code=201,
    summary="Iniciar grabación de video",
    description="La cámara llama a este endpoint al comenzar una grabación. Requiere `X-API-Key`."
)
def start_video(
    data: VideoCreate,
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera)
):
    video = Video(
        filename=data.filename,
        camera_id=camera.id,
        fps=data.fps,
        resolution=data.resolution,
        codec=data.codec,
        status=VideoStatus.RECORDING,
        started_at=datetime.now(timezone.utc)       # ✅ fix
    )
    db.add(video)
    camera.last_seen = datetime.now(timezone.utc)   # ✅ fix
    db.commit()
    db.refresh(video)
    return video


# ── 5. Envío de segmento (API Key) ────────────────────

@router.post(
    "/segments",
    response_model=SegmentResponse,
    status_code=201,
    summary="Enviar segmento de video",
    description="""
La cámara envía el hash SHA-256 y firma ECDSA de cada segmento de 30 segundos.

- El hash debe tener exactamente **64 caracteres hexadecimales**
- El segmento no puede durar más de **60 segundos**
- Requiere `X-API-Key` en el header
    """
)
def upload_segment(
    data: SegmentUpload,
    request: Request,
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera)
):
    video = db.query(Video).filter(
        Video.id == data.video_id,
        Video.camera_id == camera.id
    ).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado o no pertenece a esta cámara")

    existing = db.query(Segment).filter(
        Segment.video_id == data.video_id,
        Segment.segment_index == data.segment_index
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Segmento #{data.segment_index} ya registrado")

    segment = Segment(
        video_id=data.video_id,
        segment_index=data.segment_index,
        duration_secs=data.end_time_secs - data.start_time_secs,
        start_time_secs=data.start_time_secs,
        end_time_secs=data.end_time_secs,
        file_size_bytes=data.file_size_bytes,
        sha256_hash=data.sha256_hash,
        ecdsa_signature=data.ecdsa_signature,
        public_key_id=data.public_key_id,
        status=SegmentStatus.VALID if data.ecdsa_signature else SegmentStatus.PENDING,
        signed_at=datetime.now(timezone.utc) if data.ecdsa_signature else None   # ✅ fix
    )
    db.add(segment)
    camera.last_seen = datetime.now(timezone.utc)   # ✅ fix
    db.commit()
    db.refresh(segment)
    return segment


# ── 6. Heartbeat de cámara (API Key) ─────────────────

@router.post(
    "/heartbeat",
    status_code=200,
    summary="Heartbeat de cámara",
    description="La cámara envía este ping periódicamente para indicar que está online. Actualiza `last_seen`."
)
def heartbeat(
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera)
):
    camera.last_seen = datetime.now(timezone.utc)   # ✅ fix
    db.commit()
    return {
        "status": "ok",
        "camera_id": camera.camera_id,
        "timestamp": camera.last_seen
    }


# ── 7. Finalizar grabación de video (API Key) ─────────

@router.patch(
    "/videos/{video_id}/finish",
    response_model=VideoResponse,
    summary="Finalizar grabación de video",
    description="La cámara llama a este endpoint al terminar la grabación. Calcula la duración total automáticamente."
)
def finish_video(
    video_id: str,
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera)
):
    video = db.query(Video).filter(
        Video.id == video_id,
        Video.camera_id == camera.id
    ).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")
    if video.status != VideoStatus.RECORDING:
        raise HTTPException(status_code=400, detail="El video no está en estado RECORDING")

    video.status = VideoStatus.COMPLETED
    video.ended_at = datetime.now(timezone.utc)     # ✅ fix
    if video.started_at:
        video.duration_secs = int((video.ended_at - video.started_at).total_seconds())

    db.commit()
    db.refresh(video)
    return video


# ── 8. Listar videos de una cámara (JWT — Analyst+) ───

@router.get(
    "/{camera_id}/videos",
    response_model=list[VideoResponse],
    summary="Listar videos de una cámara",
    description="Devuelve todos los videos registrados para una cámara, ordenados por fecha descendente."
)
def list_videos(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")

    return db.query(Video).filter(Video.camera_id == camera.id).order_by(
        Video.started_at.desc()
    ).all()
