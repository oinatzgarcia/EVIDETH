from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime, timezone
from app.db.session import get_db
from app.db.models import Camera, Segment, Video, SegmentStatus, VideoStatus, UserRole
from app.core.security import generate_api_key, hash_api_key
from app.core.dependencies import require_admin, require_analyst, get_current_camera
from pydantic import BaseModel, field_validator
import re
import json

try:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except ImportError:
    load_pem_public_key = None


CAMERA_ONLINE_THRESHOLD_SECONDS = 60

router = APIRouter(
    prefix="/cameras",
    tags=["Cameras"],
    responses={
        401: {"description": "API Key o JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    },
)


# ── Schemas ──────────────────────────────────────────────────


class CameraCreate(BaseModel):
    camera_id: str
    name: str
    location: Optional[str] = None
    description: Optional[str] = None

    @field_validator("camera_id")
    @classmethod
    def validate_camera_id(cls, v):
        if not re.match(r"^[A-Za-z0-9_-]{3,100}$", v):
            raise ValueError(
                "camera_id solo permite letras, números, guiones y guiones bajos (3-100 chars)"
            )
        return v


class CameraResponse(BaseModel):
    camera_id: str
    name: str
    location: Optional[str]
    is_active: bool
    owner_id: Optional[str] = None
    owner_name: Optional[str] = None
    api_key: Optional[str] = None
    has_public_key: Optional[bool] = None

    model_config = {"from_attributes": True}


class CameraDetailResponse(BaseModel):
    id: str
    camera_id: str
    name: str
    location: Optional[str]
    description: Optional[str]
    is_active: bool
    last_seen: Optional[datetime]
    created_at: Optional[datetime]
    owner_id: Optional[str]
    owner_name: Optional[str] = None
    has_public_key: Optional[bool] = None

    model_config = {"from_attributes": True}


class CameraUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None


class CameraPublicKeyUpdate(BaseModel):
    public_key_pem: str

    @field_validator("public_key_pem")
    @classmethod
    def validate_pem(cls, v):
        v = v.strip()
        if not v.startswith("-----BEGIN PUBLIC KEY-----"):
            raise ValueError(
                "public_key_pem debe ser una clave pública EC en formato PEM "
                "(debe empezar con '-----BEGIN PUBLIC KEY-----')"
            )
        if load_pem_public_key is not None:
            try:
                load_pem_public_key(v.encode())
            except Exception as e:
                raise ValueError(f"PEM inválido: {e}")
        return v


class SegmentUpload(BaseModel):
    video_id: str
    segment_index: int
    start_time_secs: int
    end_time_secs: int
    sha256_hash: str
    ecdsa_signature: Optional[str] = None
    public_key_id: Optional[str] = None
    file_size_bytes: Optional[int] = None
    merkle_root: Optional[str] = None
    second_hashes: Optional[List[str]] = None
    frame_thumbnails: Optional[List[Optional[str]]] = None

    @field_validator("sha256_hash")
    @classmethod
    def validate_sha256(cls, v):
        if not re.match(r"^[a-fA-F0-9]{64}$", v):
            raise ValueError("sha256_hash debe ser exactamente 64 caracteres hexadecimales")
        return v.lower()

    @field_validator("merkle_root")
    @classmethod
    def validate_merkle_root(cls, v):
        if v is not None and not re.match(r"^[a-fA-F0-9]{64}$", v):
            raise ValueError("merkle_root debe ser exactamente 64 caracteres hexadecimales")
        return v.lower() if v else v

    @field_validator("second_hashes")
    @classmethod
    def validate_second_hashes(cls, v):
        if v is not None:
            for h in v:
                if not re.match(r"^[a-fA-F0-9]{64}$", h):
                    raise ValueError(
                        f"Cada hash en second_hashes debe ser 64 chars hex; inválido: {h[:16]}..."
                    )
        return v

    @field_validator("segment_index")
    @classmethod
    def validate_index(cls, v):
        if v < 0:
            raise ValueError("segment_index debe ser >= 0")
        return v

    @field_validator("end_time_secs")
    @classmethod
    def validate_duration(cls, v, info):
        start = info.data.get("start_time_secs", 0)
        if v <= start:
            raise ValueError("end_time_secs debe ser mayor que start_time_secs")
        if (v - start) > 60:
            raise ValueError("La duración del segmento no puede superar 60 segundos")
        return v

    @field_validator("file_size_bytes")
    @classmethod
    def validate_size(cls, v):
        if v is not None:
            if v <= 0:
                raise ValueError("file_size_bytes debe ser > 0")
            if v > 500 * 1024 * 1024:
                raise ValueError("file_size_bytes supera el límite de 500 MB")
        return v


class SegmentResponse(BaseModel):
    id: str
    segment_index: int
    sha256_hash: str
    merkle_root: Optional[str]
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


# ── Helpers ──────────────────────────────────────────────────


def _to_camera_response(camera: Camera, api_key: Optional[str] = None) -> CameraResponse:
    return CameraResponse(
        camera_id=camera.camera_id,
        name=camera.name,
        location=camera.location,
        is_active=camera.is_active,
        owner_id=camera.owner_id,
        owner_name=camera.owner.full_name if camera.owner else None,
        api_key=api_key,
        has_public_key=bool(camera.public_key_pem),
    )


def _to_camera_detail(camera: Camera) -> CameraDetailResponse:
    return CameraDetailResponse(
        id=camera.id,
        camera_id=camera.camera_id,
        name=camera.name,
        location=camera.location,
        description=camera.description,
        is_active=camera.is_active,
        last_seen=camera.last_seen,
        created_at=camera.created_at,
        owner_id=camera.owner_id,
        owner_name=camera.owner.full_name if camera.owner else None,
        has_public_key=bool(camera.public_key_pem),
    )


def _is_camera_online(camera: Camera) -> bool:
    if camera.last_seen is None:
        return False
    last = camera.last_seen
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - last).total_seconds() < CAMERA_ONLINE_THRESHOLD_SECONDS


# ── 1. Registrar cámara (Admin) ──────────────────────────────


@router.post(
    "/",
    response_model=CameraResponse,
    status_code=201,
    summary="Registrar nueva cámara",
)
def register_camera(
    data: CameraCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
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
        owner_id=str(current_user.id),
    )
    db.add(camera)
    db.commit()
    db.refresh(camera)
    return _to_camera_response(camera, api_key=raw_key)


# ── 2. Listar cámaras (Analyst+) ─────────────────────────────


@router.get("/", summary="Listar cámaras")
def list_cameras(
    location: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(True),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    query = db.query(Camera)
    if current_user.role != UserRole.ADMIN:
        query = query.filter(Camera.owner_id == str(current_user.id))
    if is_active is not None:
        query = query.filter(Camera.is_active == is_active)
    if location:
        query = query.filter(Camera.location.ilike(f"%{location}%"))

    total = query.count()
    cameras = (
        query.order_by(Camera.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "items": [_to_camera_response(c) for c in cameras],
    }


# ── 3. Estado de cámara (Analyst+) ───────────────────────────


@router.get("/{camera_id}/status", summary="Estado de una cámara")
def camera_status(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    if current_user.role != UserRole.ADMIN and camera.owner_id != str(current_user.id):
        raise HTTPException(status_code=403, detail="No tienes acceso a esta cámara")

    active_video = db.query(Video).filter(
        Video.camera_id == camera.id, Video.status == VideoStatus.RECORDING
    ).first()

    total_segments = (
        db.query(Segment).join(Video).filter(Video.camera_id == camera.id).count()
    )
    invalid_segments = (
        db.query(Segment)
        .join(Video)
        .filter(Video.camera_id == camera.id, Segment.status == SegmentStatus.INVALID)
        .count()
    )

    return {
        "camera_id": camera.camera_id,
        "name": camera.name,
        "location": camera.location,
        "is_active": camera.is_active,
        "last_seen": camera.last_seen,
        "online": _is_camera_online(camera),
        "has_public_key": bool(camera.public_key_pem),
        "active_video": (
            {
                "id": active_video.id,
                "filename": active_video.filename,
                "started_at": active_video.started_at,
            }
            if active_video
            else None
        ),
        "stats": {
            "total_segments": total_segments,
            "invalid_segments": invalid_segments,
            "integrity_ok": invalid_segments == 0,
        },
    }


# ── 4. Iniciar grabación de video (API Key) ───────────────────


@router.post(
    "/videos",
    response_model=VideoResponse,
    status_code=201,
    summary="Iniciar grabación de video",
)
def start_video(
    data: VideoCreate,
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera),
):
    video = Video(
        filename=data.filename,
        camera_id=camera.id,
        fps=data.fps,
        resolution=data.resolution,
        codec=data.codec,
        status=VideoStatus.RECORDING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(video)
    camera.last_seen = datetime.now(timezone.utc)
    db.commit()
    db.refresh(video)
    return video


# ── 5. Envío de segmento (API Key) ────────────────────────────


@router.post(
    "/segments",
    response_model=SegmentResponse,
    status_code=201,
    summary="Enviar segmento de video",
)
def upload_segment(
    data: SegmentUpload,
    request: Request,
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera),
):
    video = db.query(Video).filter(
        Video.id == data.video_id, Video.camera_id == camera.id
    ).first()
    if not video:
        raise HTTPException(
            status_code=404, detail="Video no encontrado o no pertenece a esta cámara"
        )

    if db.query(Segment).filter(
        Segment.video_id == data.video_id,
        Segment.segment_index == data.segment_index,
    ).first():
        raise HTTPException(
            status_code=409, detail=f"Segmento #{data.segment_index} ya registrado"
        )

    second_hashes_json = json.dumps(data.second_hashes) if data.second_hashes else None
    frame_thumbnails_json = (
        json.dumps(data.frame_thumbnails) if data.frame_thumbnails else None
    )
    has_full_crypto = bool(data.ecdsa_signature and data.merkle_root)
    status = SegmentStatus.VALID if has_full_crypto else SegmentStatus.PENDING

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
        merkle_root=data.merkle_root,
        second_hashes=second_hashes_json,
        frame_thumbnails=frame_thumbnails_json,
        status=status,
        signed_at=datetime.now(timezone.utc) if data.ecdsa_signature else None,
    )
    db.add(segment)
    camera.last_seen = datetime.now(timezone.utc)
    db.commit()
    db.refresh(segment)
    return segment


# ── 6. Heartbeat (API Key) ────────────────────────────────────


@router.post("/heartbeat", status_code=200, summary="Heartbeat de cámara")
def heartbeat(
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera),
):
    camera.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok", "camera_id": camera.camera_id, "timestamp": camera.last_seen}


# ── 7. Finalizar grabación (API Key) ──────────────────────────


@router.patch(
    "/videos/{video_id}/finish",
    response_model=VideoResponse,
    summary="Finalizar grabación de video",
)
def finish_video(
    video_id: str,
    db: Session = Depends(get_db),
    camera: Camera = Depends(get_current_camera),
):
    video = db.query(Video).filter(
        Video.id == video_id, Video.camera_id == camera.id
    ).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")
    if video.status != VideoStatus.RECORDING:
        raise HTTPException(status_code=400, detail="El video no está en estado RECORDING")

    video.status = VideoStatus.COMPLETED
    video.ended_at = datetime.now(timezone.utc)
    if video.started_at:
        video.duration_secs = int((video.ended_at - video.started_at).total_seconds())
    db.commit()
    db.refresh(video)
    return video


# ── 8. Listar segmentos de un video (Analyst+) ───────────────
#
# GET /cameras/videos/{video_id}/segments
# Permite a un analista consultar los segmentos de un video específico.
# El video puede pertenecer a cualquier cámara accesible por el usuario.


@router.get(
    "/videos/{video_id}/segments",
    summary="Listar segmentos de un video",
    description="""
Devuelve todos los segmentos registrados para un video, ordenados por índice.
El analista puede usarlo para verificar la cobertura temporal y los hashes.
Solo **Analyst** o **Admin**.
    """,
)
def list_video_segments(
    video_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")

    # Verificar acceso: admin ve todo, analista solo sus cámaras
    camera = db.query(Camera).filter(Camera.id == video.camera_id).first()
    if current_user.role != UserRole.ADMIN and camera.owner_id != str(current_user.id):
        raise HTTPException(status_code=403, detail="No tienes acceso a este video")

    total = db.query(Segment).filter(Segment.video_id == video_id).count()
    segments = (
        db.query(Segment)
        .filter(Segment.video_id == video_id)
        .order_by(Segment.segment_index)
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "video_id": video_id,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "segments": [SegmentResponse.model_validate(s) for s in segments],
    }


# ── 9. Listar videos de una cámara (Analyst+) ────────────────


@router.get("/{camera_id}/videos", summary="Listar videos de una cámara")
def list_videos(
    camera_id: str,
    status: Optional[str] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    if current_user.role != UserRole.ADMIN and camera.owner_id != str(current_user.id):
        raise HTTPException(status_code=403, detail="No tienes acceso a esta cámara")

    query = db.query(Video).filter(Video.camera_id == camera.id)
    if status:
        try:
            query = query.filter(Video.status == VideoStatus(status))
        except ValueError:
            raise HTTPException(status_code=400, detail="status inválido")
    if date_from:
        query = query.filter(Video.started_at >= date_from)
    if date_to:
        query = query.filter(Video.started_at <= date_to)

    total = query.count()
    videos = (
        query.order_by(Video.started_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "items": [VideoResponse.model_validate(v) for v in videos],
    }


# ── 10. Obtener cámara por ID (Analyst+) ──────────────────────


@router.get(
    "/{camera_id}", response_model=CameraDetailResponse, summary="Obtener cámara por ID"
)
def get_camera(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_analyst),
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    if current_user.role != UserRole.ADMIN and camera.owner_id != str(current_user.id):
        raise HTTPException(status_code=403, detail="No tienes acceso a esta cámara")
    return _to_camera_detail(camera)


# ── 11. Actualizar cámara (Admin) ─────────────────────────────


@router.patch(
    "/{camera_id}", response_model=CameraDetailResponse, summary="Actualizar cámara"
)
def update_camera(
    camera_id: str,
    data: CameraUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    if data.name is not None:
        camera.name = data.name
    if data.location is not None:
        camera.location = data.location
    if data.description is not None:
        camera.description = data.description
    db.commit()
    db.refresh(camera)
    return _to_camera_detail(camera)


# ── 12. Registrar clave pública ECDSA (Admin) ─────────────────


@router.post(
    "/{camera_id}/public-key",
    status_code=200,
    summary="Registrar clave pública ECDSA de la cámara",
)
def register_public_key(
    camera_id: str,
    data: CameraPublicKeyUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")

    camera.public_key_pem = data.public_key_pem
    db.commit()
    return {
        "detail": f"Clave pública registrada para cámara '{camera_id}'",
        "camera_id": camera_id,
        "has_public_key": True,
    }


# ── 13. Desactivar cámara — DELETE (Admin) ────────────────────


@router.delete("/{camera_id}", status_code=200, summary="Desactivar cámara (DELETE)")
def deactivate_camera(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    if not camera.is_active:
        raise HTTPException(status_code=400, detail="La cámara ya está inactiva")
    camera.is_active = False
    db.commit()
    return {"detail": f"Cámara {camera.camera_id} desactivada correctamente"}


# ── 14. Desactivar cámara — PATCH /deactivate (Admin) ────────
#
# Alias REST semántico: PATCH /{camera_id}/deactivate
# Coexiste con DELETE /{camera_id} para compatibilidad con clientes REST
# que prefieren acciones explícitas sobre métodos HTTP destructivos.
# Ref: RFC 7231 §4.3.5 (DELETE) vs acción nombrada PATCH.


@router.patch(
    "/{camera_id}/deactivate",
    status_code=200,
    summary="Desactivar cámara (PATCH)",
    description="""
Desactiva una cámara (soft delete). Los datos históricos y segmentos se
preservan para auditoría forense. El heartbeat y envío de segmentos quedan
bloqueados para cámaras inactivas. Solo **Admin**.
    """,
)
def deactivate_camera_patch(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_admin),
):
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    if not camera.is_active:
        raise HTTPException(status_code=400, detail="La cámara ya está inactiva")
    camera.is_active = False
    db.commit()
    return {
        "detail": f"Cámara {camera.camera_id} desactivada correctamente",
        "camera_id": camera_id,
        "is_active": False,
    }
