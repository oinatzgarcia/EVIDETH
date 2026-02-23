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


def generate_corrupted_video(src: str) -> str:
    """
    Genera una versión manipulada del vídeo reemplazando los frames
    del segundo 3 al 4 con un rectángulo negro.

    POR QUÉ no basta con cambiar 1 byte del fichero .mp4:
        ffmpeg usa -c copy para re-muxear el contenedor MP4 al segmentar.
        Si el byte corrupto cae en metadatos del contenedor (moov atom),
        ffmpeg lo normaliza y el stream H.264 resultante es idéntico.
        El SHA-256 del segmento coincide y el verificador dice PASS.

    POR QUÉ funciona re-codificar frames:
        Al modificar el contenido real de los frames (datos H.264),
        el SHA-256 del segmento extraído con ffmpeg es diferente.
        El verificador compara SHA-256 de segmento → FAIL garantizado.
    """
    dst = src.replace(".mp4", "_corrupted.mp4")
    cmd = [
        "ffmpeg", "-y", "-i", src,
        # Pinta un rectángulo negro sobre TODOS los frames del segundo 3-4
        "-vf", "drawbox=enable='between(t,3,4)':x=0:y=0:w=iw:h=ih:color=black:t=fill",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        dst
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ffmpeg error al generar vídeo corrompido: {result.stderr}")
    return dst


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

    # 1. Generar vídeo original
    video_path = os.path.join(OUTPUT_DIR, "test_video.mp4")
    print(f"[1/4] Generando vídeo de {TEST_VIDEO_SECS} s con ffmpeg...")
    generate_test_video(video_path, TEST_VIDEO_SECS)
    size_mb = os.path.getsize(video_path) / 1_048_576
    print(f"      ✔ {video_path}  ({size_mb:.1f} MB)")

    # 2. Generar vídeo manipulado (para test FAIL)
    print(f"\n[2/4] Generando vídeo manipulado (frames 3–4 s en negro)...")
    corrupted_path = generate_corrupted_video(video_path)
    size_corr = os.path.getsize(corrupted_path) / 1_048_576
    print(f"      ✔ {corrupted_path}  ({size_corr:.1f} MB)")

    # 3. Registrar en BD
    print(f"\n[3/4] Registrando en la base de datos...")
    db = SessionLocal()
    try:
        camera = get_or_create_camera(db)
        video  = register_video_with_segments(db, camera, video_path)
        segs   = db.query(models.Segment).filter(
            models.Segment.video_id == video.id
        ).order_by(models.Segment.segment_index).all()

        # Extraer valores a Python puro ANTES de cerrar la sesión
        out_camera_id = camera.camera_id
        out_video_id  = video.id
        out_seg_data  = [
            {
                "index":  s.segment_index,
                "start":  s.start_time_secs,
                "end":    s.end_time_secs,
                "sha256": s.sha256_hash,
                "merkle": s.merkle_root,
            }
            for s in segs
        ]
    finally:
        db.close()

    # 4. Imprimir resumen
    print(f"\n[4/4] ✔✔ Listo. Usa estos datos en el frontend o en el API:\n")
    print(f"  camera_id   = {out_camera_id}")
    print(f"  video_db_id = {out_video_id}")
    print(f"  segmentos   = {len(out_seg_data)}")
    for s in out_seg_data:
        merkle_str = f"  Merkle: {s['merkle'][:16]}..." if s['merkle'] else "  (sin Merkle)"
        print(f"    [{s['index']}] {s['start']:3d}–{s['end']:3d} s  "
              f"SHA256: {s['sha256'][:16]}...{merkle_str}")

    print(f"\n  ── Test PASS (vídeo íntegro) ──────────────────────")
    print(f"  Sube este fichero  →  debe dar VERDE (ÍNTEGRO):")
    print(f"    {video_path}")

    print(f"\n  ── Test FAIL (vídeo manipulado) ──────────────────")
    print(f"  Sube este fichero  →  debe dar ROJO (MANIPULADO):")
    print(f"    {corrupted_path}")
    print(f"  (frames del segundo 3–4 reemplazados por negro)")

    print(f"\n  ── Ejemplo curl ────────────────────────────")
    print(f"  curl -X POST http://localhost:8000/api/v1/verification/upload \\")
    print(f"       -H 'Authorization: Bearer <TU_JWT>' \\")
    print(f"       -F 'video=@{video_path}' \\")
    print(f"       -F 'camera_id={out_camera_id}' \\")
    print(f"       -F 'video_db_id={out_video_id}'")
    print()


if __name__ == "__main__":
    main()
