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
"""

import os
import sys
import uuid
import json
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal, engine
from app.db import models
from app.services.video_processor import segment_video, calculate_sha256


TEST_CAMERA_ID  = "CAM-TEST-001"
TEST_VIDEO_SECS = 35
TEST_RESOLUTION = "640x480"
TEST_FPS        = 25
OUTPUT_DIR      = tempfile.mkdtemp(prefix="evideth_seed_")


def generate_test_video(output_path: str, duration: int) -> None:
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
        raise RuntimeError(f"ffmpeg error: {result.stderr}")


def get_or_create_camera(db, api_key_plain: str = "test-api-key-12345") -> models.Camera:
    cam = db.query(models.Camera).filter(
        models.Camera.camera_id == TEST_CAMERA_ID
    ).first()
    if cam:
        print(f"  → Cámara existente reutilizada: {cam.camera_id}")
        return cam

    cam = models.Camera(
        id=str(uuid.uuid4()),
        camera_id=TEST_CAMERA_ID,
        name="Cámara de Test E2E",
        location="Lab EVIDETH",
        description="Generada automáticamente por seed_test_video.py",
        api_key=hashlib.sha256(api_key_plain.encode()).hexdigest(),
        is_active=True,
    )
    db.add(cam)
    db.flush()
    print(f"  → Nueva cámara creada: {cam.camera_id}")
    return cam


def register_video_with_segments(db, camera: models.Camera, video_path: str) -> models.Video:
    video = models.Video(
        id=str(uuid.uuid4()),
        filename=os.path.basename(video_path),
        file_size_bytes=os.path.getsize(video_path),
        fps=float(TEST_FPS),
        resolution=TEST_RESOLUTION,
        codec="H264",
        sha256_full=calculate_sha256(video_path),
        status=models.VideoStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        camera_id=camera.id,
        duration_secs=TEST_VIDEO_SECS,
    )
    db.add(video)
    db.flush()

    seg_dir = os.path.join(OUTPUT_DIR, "segments")
    os.makedirs(seg_dir, exist_ok=True)
    computed = segment_video(video_path, seg_dir)

    for seg in computed:
        second_hashes = seg.get("second_hashes", [])
        db.add(models.Segment(
            id=str(uuid.uuid4()),
            video_id=video.id,
            segment_index=seg["segment_index"],
            duration_secs=seg["duration_secs"],
            start_time_secs=seg["start_time_secs"],
            end_time_secs=seg["end_time_secs"],
            file_size_bytes=seg["file_size_bytes"],
            sha256_hash=seg["sha256_hash"],
            merkle_root=seg.get("merkle_root"),
            second_hashes=json.dumps(second_hashes) if second_hashes else None,
            status=models.SegmentStatus.VALID,
            signed_at=datetime.now(timezone.utc),
        ))

    db.commit()
    return video


def main():
    print("\n┌──────────────────────────────────────────────┐")
    print("| EVIDETH — seed_test_video.py                |")
    print("└──────────────────────────────────────────────┘\n")

    models.Base.metadata.create_all(bind=engine)

    # 1. Generar vídeo
    video_path = os.path.join(OUTPUT_DIR, "test_video.mp4")
    print(f"[1/3] Generando vídeo de {TEST_VIDEO_SECS} s con ffmpeg...")
    generate_test_video(video_path, TEST_VIDEO_SECS)
    size_mb = os.path.getsize(video_path) / 1_048_576
    print(f"      ✔ {video_path}  ({size_mb:.1f} MB)")

    # 2. Registrar en BD
    print(f"\n[2/3] Registrando en la base de datos...")
    db = SessionLocal()
    try:
        camera = get_or_create_camera(db)
        video  = register_video_with_segments(db, camera, video_path)
        segs   = db.query(models.Segment).filter(
            models.Segment.video_id == video.id
        ).order_by(models.Segment.segment_index).all()

        # ⚠ IMPORTANTE: extraer valores a Python puro ANTES de cerrar la sesión.
        # Acceder a atributos ORM fuera de la sesión causa DetachedInstanceError.
        out_camera_id  = camera.camera_id
        out_video_id   = video.id
        out_seg_data   = [
            {
                "index": s.segment_index,
                "start": s.start_time_secs,
                "end":   s.end_time_secs,
                "sha256": s.sha256_hash,
                "merkle": s.merkle_root,
            }
            for s in segs
        ]
    finally:
        db.close()

    # 3. Imprimir resumen
    print(f"\n[3/3] ✔✔ Listo. Usa estos datos en el frontend o en el API:\n")
    print(f"  camera_id   = {out_camera_id}")
    print(f"  video_db_id = {out_video_id}")
    print(f"  fichero     = {video_path}")
    print(f"  segmentos   = {len(out_seg_data)}")
    for s in out_seg_data:
        merkle_str = f"  Merkle: {s['merkle'][:16]}..." if s['merkle'] else "  (sin Merkle)"
        print(f"    [{s['index']}] {s['start']:3d}–{s['end']:3d} s  "
              f"SHA256: {s['sha256'][:16]}...{merkle_str}")

    print(f"\n  ── Ejemplo curl ────────────────────────────")
    print(f"  curl -X POST http://localhost:8000/api/v1/verification/upload \\")
    print(f"       -H 'Authorization: Bearer <TU_JWT>' \\")
    print(f"       -F 'video=@{video_path}' \\")
    print(f"       -F 'camera_id={out_camera_id}' \\")
    print(f"       -F 'video_db_id={out_video_id}'")
    print()


if __name__ == "__main__":
    main()
