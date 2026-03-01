from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import tempfile, os, shutil, csv, io
import filetype

from app.db.session import get_db
from app.db.models import Video, Camera, Verification, Segment, VerificationResult, UserRole
from app.core.dependencies import require_analyst
from app.services.verifier import verify_video
from app.schemas.verification import VerificationReport
from app.utils.pdf_generator import ForensicPDFGenerator


router = APIRouter(
    prefix="/verification",
    tags=["Verification"],
    responses={
        401: {"description": "JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    }
)


# ── Constantes de validación de formato ──────────────────────────────────

ALLOWED_EXTENSIONS = {".mp4", ".avi", ".mkv", ".mov"}

# MIME types aceptados tal como los devuelve la librería `filetype`.
# `filetype` lee los magic bytes del fichero, independientemente del nombre
# o del Content-Type declarado por el cliente.
ALLOWED_MIMETYPES = {
    "video/mp4",
    "video/x-msvideo",    # AVI
    "video/x-matroska",   # MKV
    "video/quicktime",    # MOV
    "video/webm",         # MKV/WebM
    "application/octet-stream",   # Fallback: filetype no identifica el tipo
                                   # (MKV antiguo, variante no catalogada)
}

# Tamaño máximo admitido: 2 GB
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024

# Bytes leídos para detección de magic bytes
# (filetype solo necesita los primeros bytes, 2 KB es más que suficiente)
MAGIC_READ_BYTES = 2048


# ── Helper: valida extensión + magic bytes del fichero subido ──────────

def _validate_video_file(upload: UploadFile) -> str:
    """
    Valida el formato del fichero en dos fases:

    1. Extensión del nombre (rápida, primera línea de defensa).
    2. Magic bytes — lee los primeros bytes del contenido real con
       `filetype` (pura Python, sin dependencias nativas) para detectar
       el tipo real independientemente del nombre o cabecera Content-Type.

    Devuelve la extensión normalizada (.mp4, .avi, etc.).
    Lanza HTTPException 400 si el fichero no es un video admitido.

    Importante: después de llamar a esta función el cursor del
    fichero queda en la posición 0 (listo para una lectura completa).
    """
    # ── Fase 1: extensión ───────────────────────────────────────
    filename = upload.filename or ""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Extensión no admitida: '{ext or '(ninguna)'}'. "
                f"Formatos válidos: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            )
        )

    # ── Fase 2: magic bytes (contenido real) ────────────────────────
    header = upload.file.read(MAGIC_READ_BYTES)
    upload.file.seek(0)                          # ◄ reset para lectura posterior

    if not header:
        raise HTTPException(status_code=400, detail="El fichero está vacío")

    # filetype.guess() devuelve None si los magic bytes no coinciden con
    # ningún tipo conocido; en ese caso se usa 'application/octet-stream'
    # que está en ALLOWED_MIMETYPES como fallback segúro.
    kind = filetype.guess(header)
    detected_mime = kind.mime if kind is not None else "application/octet-stream"

    if detected_mime not in ALLOWED_MIMETYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"El contenido del fichero no es un video válido. "
                f"Tipo detectado: '{detected_mime}'. "
                f"Tipos admitidos: video/mp4, video/x-msvideo, "
                f"video/x-matroska, video/quicktime"
            )
        )

    return ext


# ── Helper: construye la query con filtros comunes + ownership ────────

def _build_verification_query(db, camera_id, result, date_from, date_to, current_user=None):
    """
    Construye la query base de verificaciones aplicando filtros y control
    de acceso por propietario de cámara.

    - Admin: ve verificaciones de todas las cámaras.
    - Analyst/Viewer: solo ve verificaciones de sus propias cámaras.
    """
    query = (
        db.query(Verification)
        .join(Segment,  Verification.segment_id == Segment.id)
        .join(Video,    Segment.video_id         == Video.id)
        .join(Camera,   Video.camera_id          == Camera.id)
    )

    if current_user and current_user.role != UserRole.ADMIN:
        query = query.filter(Camera.owner_id == str(current_user.id))

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


def _check_camera_access(camera: Camera, current_user) -> None:
    """Lanza 403 si el usuario no es admin y no es propietario de la cámara."""
    if current_user.role != UserRole.ADMIN and camera.owner_id != str(current_user.id):
        raise HTTPException(
            status_code=403,
            detail="No tienes acceso a esta cámara"
        )


# ── Helper: construir datos del reporte (usado por JSON y PDF) ────────

def _build_verification_report_data(video_id: str, db: Session, current_user) -> Dict[str, Any]:
    """
    Construye los datos del reporte de verificación.
    Reutilizable por endpoints JSON y PDF.
    """
    video = db.query(Video).filter(Video.id == video_id).first()
    
    if not video:
        raise HTTPException(
            status_code=404,
            detail=f"Video with ID {video_id} not found"
        )
    
    camera = db.query(Camera).filter(Camera.id == video.camera_id).first()
    if camera:
        _check_camera_access(camera, current_user)
    
    segments = (
        db.query(Segment)
        .filter(Segment.video_id == video_id)
        .order_by(Segment.segment_index)
        .all()
    )
    
    total_segments = len(segments)
    segments_detail = []
    passed_segments = 0
    failed_segments = 0
    
    for seg in segments:
        latest_verification = (
            db.query(Verification)
            .filter(Verification.segment_id == seg.id)
            .order_by(Verification.verified_at.desc())
            .first()
        )
        
        if latest_verification:
            segment_passed = latest_verification.result == VerificationResult.PASS
            if segment_passed:
                passed_segments += 1
            else:
                failed_segments += 1
            
            segment_data = {
                "segment_index": seg.segment_index,
                "start_time_secs": seg.start_time_secs,
                "end_time_secs": seg.end_time_secs,
                "result": "pass" if segment_passed else "fail",
                "hash": seg.sha256_hash,
                "hash_calculated": latest_verification.computed_hash,
                "hash_expected": seg.sha256_hash,
                "signature_valid": latest_verification.signature_valid,
                "verified_at": latest_verification.verified_at.isoformat() if latest_verification.verified_at else None,
            }
        else:
            segment_data = {
                "segment_index": seg.segment_index,
                "start_time_secs": seg.start_time_secs,
                "end_time_secs": seg.end_time_secs,
                "result": "missing",
                "hash": seg.sha256_hash,
                "hash_calculated": None,
                "hash_expected": seg.sha256_hash,
                "signature_valid": None,
                "verified_at": None,
            }
        
        segments_detail.append(segment_data)
    
    missing_segments = total_segments - (passed_segments + failed_segments)
    integrity_ok = failed_segments == 0 and missing_segments == 0
    
    if integrity_ok:
        verdict = "Video integrity verified successfully - All segments passed cryptographic validation"
    else:
        if failed_segments > 0:
            verdict = f"Video tampering detected - {failed_segments} segment(s) failed verification"
        else:
            verdict = f"Incomplete verification - {missing_segments} segment(s) not yet verified"
    
    latest_verification_time = None
    if segments:
        latest_verif = (
            db.query(Verification)
            .join(Segment)
            .filter(Segment.video_id == video_id)
            .order_by(Verification.verified_at.desc())
            .first()
        )
        if latest_verif and latest_verif.verified_at:
            latest_verification_time = latest_verif.verified_at.isoformat()
    
    return {
        "video_id": video_id,
        "camera_id": camera.camera_id if camera else None,
        "filename": video.filename,
        "duration_secs": video.duration_secs,
        "verified_at": latest_verification_time or datetime.utcnow().isoformat(),
        "created_at": video.created_at.isoformat() if video.created_at else None,
        "integrity_ok": integrity_ok,
        "verdict": verdict,
        "summary": {
            "total_segments": total_segments,
            "passed": passed_segments,
            "failed": failed_segments,
            "missing": missing_segments,
        },
        "segments": segments_detail
    }


# ── 1. Listado global con filtros + paginación ───────────────────

@router.get(
    "/",
    summary="Listar verificaciones",
    description="""
Devuelve las verificaciones del sistema con filtros y paginación.

- **Admin**: ve todas las verificaciones del sistema.
- **Analyst/Viewer**: solo ve verificaciones de sus propias cámaras.

**Filtros:**
- `camera_id`: ID físico de la cámara
- `result`: resultado (`pass`, `fail`, `error`)
- `date_from` / `date_to`: rango de fechas (ISO 8601)
- `page` / `per_page`: paginación
    """
)
def list_verifications(
    camera_id:  Optional[str]      = Query(None),
    result:     Optional[str]      = Query(None),
    date_from:  Optional[datetime] = Query(None),
    date_to:    Optional[datetime] = Query(None),
    page:       int                = Query(1,  ge=1),
    per_page:   int                = Query(20, ge=1, le=100),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst)
):
    query = _build_verification_query(db, camera_id, result, date_from, date_to, current_user)

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


# ── 2. Exportación CSV ───────────────────────────────────────

@router.get(
    "/export",
    summary="Exportar verificaciones a CSV",
)
def export_verifications(
    camera_id:  Optional[str]      = Query(None),
    result:     Optional[str]      = Query(None),
    date_from:  Optional[datetime] = Query(None),
    date_to:    Optional[datetime] = Query(None),
    db:         Session            = Depends(get_db),
    current_user = Depends(require_analyst)
):
    verifications = (
        _build_verification_query(db, camera_id, result, date_from, date_to, current_user)
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
        writer.writerow(HEADERS)
        yield buf.getvalue()
        buf.seek(0); buf.truncate(0)

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

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"evideth_verifications_{ts}.csv"

    return StreamingResponse(
        iter_csv(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


# ── 3. Subida y verificación de video ───────────────────────────

@router.post(
    "/upload",
    response_model=VerificationReport,
    summary="Subir video para verificación de integridad",
    description="""
Verifica la integridad de un video subido comparando cada segmento contra
los hashes y firmas almacenados en BD.

**Validación de formato (dos fases):**
1. Extensión del nombre: `.mp4`, `.avi`, `.mkv`, `.mov`
2. Magic bytes del contenido real (`filetype`, pura Python) — detecta
   ficheros renombrados independientemente del nombre o Content-Type.

- **Admin**: puede verificar cualquier cámara del sistema.
- **Analyst/Viewer**: solo puede verificar cámaras que le pertenecen.
    """
)
async def upload_and_verify(
    request:     Request,
    video:       UploadFile = File(...),
    camera_id:   str        = Form(...),
    video_db_id: str        = Form(...),
    db:          Session    = Depends(get_db),
    current_user            = Depends(require_analyst)
):
    # ── 1. Tamaño máximo ───────────────────────────────────────────────
    if video.size is not None and video.size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Fichero demasiado grande. Máximo admitido: {MAX_UPLOAD_BYTES // (1024**3)} GB"
        )

    # ── 2. Validación de formato: extensión + magic bytes ──────────────
    ext = _validate_video_file(video)

    # ── 3. Ownership check ─────────────────────────────────────────────
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    _check_camera_access(camera, current_user)

    video_db = db.query(Video).filter(
        Video.id == video_db_id, Video.camera_id == camera.id
    ).first()
    if not video_db:
        raise HTTPException(status_code=404, detail="Video no encontrado en BD")

    # ── 4. Guardar en fichero temporal y verificar ─────────────────────
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


# ── 4. Obtener reporte completo de verificación por video_id (JSON) ──────

@router.get(
    "/report/{video_id}",
    response_model=Dict[str, Any],
    summary="Obtener reporte de verificación completo (JSON)",
    description="""
Retorna el reporte completo de verificación de un video específico en formato JSON.

Incluye:
- Información del video (camera_id, filename, timestamps)
- Resumen de segmentos (total, passed, failed, missing)
- Detalle de cada segmento con sus hashes y resultados de verificación
- Veredicto de integridad global

Este endpoint es útil para descargar el reporte en formato JSON después
de realizar una verificación.
    """
)
def get_verification_report(
    video_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    return _build_verification_report_data(video_id, db, current_user)


# ── 4B. Descargar reporte forense en PDF ──────────────────────────────────

@router.get(
    "/report/{video_id}/pdf",
    summary="Descargar reporte forense en PDF",
    description="""
Genera y descarga un reporte forense profesional en formato PDF.

El PDF incluye:
- Portada con clasificación del documento
- Resumen ejecutivo de la verificación
- Detalles técnicos del video y cámara
- Tabla completa de análisis de segmentos
- Cadena de custodia (chain of custody)
- Detalles criptográficos (SHA-256, ECDSA P-256)
- Disclaimer legal para uso como prueba forense

Formato profesional válido como evidencia legal.
    """
)
def download_forensic_pdf(
    video_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(require_analyst)
):
    # Reutilizar la función helper para obtener los datos
    report_data = _build_verification_report_data(video_id, db, current_user)
    
    # Generar el PDF
    generator = ForensicPDFGenerator()
    pdf_buffer = generator.generate_report(report_data)
    
    # Nombre del archivo con timestamp
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"EVIDETH_Forensic_Report_{video_id[:8]}_{ts}.pdf"
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


# ── 5. Historial de un video ───────────────────────────────────

@router.get("/history/{video_id}", summary="Historial de verificaciones de un video")
def verification_history(
    video_id: str,
    result:   Optional[str] = Query(None),
    page:     int           = Query(1,  ge=1),
    per_page: int           = Query(20, ge=1, le=100),
    db:       Session       = Depends(get_db),
    current_user            = Depends(require_analyst)
):
    video = db.query(Video).filter(Video.id == video_id).first()
    if not video:
        raise HTTPException(status_code=404, detail="Video no encontrado")

    camera = db.query(Camera).filter(Camera.id == video.camera_id).first()
    if camera:
        _check_camera_access(camera, current_user)

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


# ── 6. Detalle de una verificación por ID ───────────────────────

@router.get("/{verification_id}", summary="Obtener verificación por ID")
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

    if camera:
        _check_camera_access(camera, current_user)

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
