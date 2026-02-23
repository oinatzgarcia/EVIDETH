#!/usr/bin/env python3
"""
scripts/seed_test_video.py

Registra un vídeo de prueba en la BD de EVIDETH con todos sus segmentos
y hashes criptográficos reales. Devuelve los IDs listos para usar en
el formulario del frontend o en llamadas directas al API.

Uso:
    python scripts/seed_test_video.py

Requiere:
    - Servidor parado (acceso directo a BD vía SQLAlchemy)
    - ffmpeg instalado
    - .env con DATABASE_URL configurado

Salida de ejemplo:
    ✔ Cámara:    CAM-TEST-001
    ✔ Video ID:  3f4a9b2c-...
    ✔ Segmentos: 2  (0–30 s | 30–35 s)
    ✔ Fichero:   /tmp/evideth_test/test_video.mp4
"""

import os
import sys
import uuid
import json
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone

# Añadir la raíz del proyecto al path para importar módulos de EVIDETH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal, engine
from app.db import models
from app.services.video_processor import segment_video, calculate_sha256
from app.utils.merkle import build_merkle_root


# ── Configuración del vídeo de prueba ────────────────────────────

TEST_CAMERA_ID   = "CAM-TEST-001"
TEST_VIDEO_SECS  = 35        # 35 s → 2 segmentos: 0–30 s y 30–35 s
TEST_RESOLUTION  = "640x480"
TEST_FPS         = 25
OUTPUT_DIR       = tempfile.mkdtemp(prefix="evideth_seed_")


def generate_test_video(output_path: str, duration: int) -> None:
    """
    Genera un vídeo de prueba con ffmpeg usando lavfi (sin cámara real).
    El contenido es un patrón de color animado — suficiente para tener
    bytes distintos en cada segundo y probar la detección Merkle.
    """
    cmd = [
        "ffmpeg", "-y",
        "-f", "lavfi",
        "-i", f"testsrc=duration={duration}:size={TEST_RESOLUTION}:rate={TEST_FPS}",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        "-t", str(duration),
        output_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ffmpeg error al generar vídeo: {result.stderr}")


def get_or_create_camera(db, api_key_plain: str = "test-api-key-12345") -> models.Camera:
    """Reutiliza la cámara de test si ya existe."""
    cam = db.query(models.Camera).filter(
        models.Camera.camera_id == TEST_CAMERA_ID
    ).first()
    if cam:
        print(f"  → Cámara existente reutilizada: {cam.camera_id}")
        return cam

    api_key_hash = hashlib.sha256(api_key_plain.encode()).hexdigest()
    cam = models.Camera(
        id=str(uuid.uuid4()),
        camera_id=TEST_CAMERA_ID,
        name="Cámara de Test E2E",
        location="Lab EVIDETH",
        description="Generada automáticamente por seed_test_video.py",
        api_key=api_key_hash,
        is_active=True,
    )
    db.add(cam)
    db.flush()
    print(f"  → Nueva cámara creada: {cam.camera_id}")
    return cam


def register_video_with_segments(db, camera: models.Camera, video_path: str) -> models.Video:
    """Crea el registro de Video + Segment en BD con hashes reales."""
    sha256_full = calculate_sha256(video_path)
    file_size   = os.path.getsize(video_path)

    video = models.Video(
        id=str(uuid.uuid4()),
        filename=os.path.basename(video_path),
        file_size_bytes=file_size,
        fps=float(TEST_FPS),
        resolution=TEST_RESOLUTION,
        codec="H264",
        sha256_full=sha256_full,
        status=models.VideoStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        camera_id=camera.id,
        duration_secs=TEST_VIDEO_SECS,
    )
    db.add(video)
    db.flush()

    # Segmentar y calcular hashes
    seg_dir = os.path.join(OUTPUT_DIR, "segments")
    os.makedirs(seg_dir, exist_ok=True)
    computed_segments = segment_video(video_path, seg_dir)

    for seg in computed_segments:
        second_hashes = seg.get("second_hashes", [])
        merkle_root   = seg.get("merkle_root")

        segment = models.Segment(
            id=str(uuid.uuid4()),
            video_id=video.id,
            segment_index=seg["segment_index"],
            duration_secs=seg["duration_secs"],
            start_time_secs=seg["start_time_secs"],
            end_time_secs=seg["end_time_secs"],
            file_size_bytes=seg["file_size_bytes"],
            sha256_hash=seg["sha256_hash"],
            merkle_root=merkle_root,
            second_hashes=json.dumps(second_hashes) if second_hashes else None,
            status=models.SegmentStatus.VALID,
            signed_at=datetime.now(timezone.utc),
        )
        db.add(segment)

    db.commit()
    return video


def main():
    print("\n┌──────────────────────────────────────────────┐")
    print("| EVIDETH — seed_test_video.py                |")  
    print("└──────────────────────────────────────────────┘\n")

    # 1. Crear tablas si no existen
    models.Base.metadata.create_all(bind=engine)

    # 2. Generar vídeo
    video_path = os.path.join(OUTPUT_DIR, "test_video.mp4")
    print(f"[1/3] Generando vídeo de {TEST_VIDEO_SECS} s con ffmpeg...")
    generate_test_video(video_path, TEST_VIDEO_SECS)
    size_mb = os.path.getsize(video_path) / 1_048_576
    print(f"      ✔ {video_path}  ({size_mb:.1f} MB)")

    # 3. Registrar en BD
    print(f"\n[2/3] Registrando en la base de datos...")
    db = SessionLocal()
    try:
        camera = get_or_create_camera(db)
        video  = register_video_with_segments(db, camera, video_path)
        segs   = db.query(models.Segment).filter(
            models.Segment.video_id == video.id
        ).order_by(models.Segment.segment_index).all()
    finally:
        db.close()

    # 4. Imprimir resumen
    print(f"\n[3/3] ✔✔ Listo. Usa estos datos en el frontend o en el API:\n")
    print(f"  camera_id   = {camera.camera_id}")
    print(f"  video_db_id = {video.id}")
    print(f"  fichero     = {video_path}")
    print(f"  segmentos   = {len(segs)}")
    for s in segs:
        merkle_str = f"  Merkle: {s.merkle_root[:16]}..." if s.merkle_root else "  (sin Merkle)"
        print(f"    [{s.segment_index}] {s.start_time_secs:3d}–{s.end_time_secs:3d} s  "
              f"SHA256: {s.sha256_hash[:16]}...{merkle_str}")

    print(f"\n  ── Ejemplo curl ───────────────────────────────")
    print(f"  curl -X POST http://localhost:8000/api/v1/verification/upload \\")
    print(f"       -H 'Authorization: Bearer <TU_JWT>' \\")
    print(f"       -F 'video=@{video_path}' \\")
    print(f"       -F 'camera_id={camera.camera_id}' \\")
    print(f"       -F 'video_db_id={video.id}'")
    print()


if __name__ == "__main__":
    main()
