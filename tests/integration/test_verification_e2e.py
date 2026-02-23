"""
tests/integration/test_verification_e2e.py

Test de integración end-to-end del sistema de verificación EVIDETH.

Cubre el ciclo completo del sistema:
  1. Generar vídeo de prueba con ffmpeg
  2. Registrar cámara + video + segmentos en BD (SQLite en memoria)
  3. CASO PASS: verificar el mismo vídeo → integrity_ok=True
  4. CASO FAIL: corromper 1 byte del vídeo → integrity_ok=False
  5. CASO MERKLE: verificar que los segundos manipulados se identifican

Ejecución:
    pytest tests/integration/test_verification_e2e.py -v
"""

import os
import sys
import uuid
import json
import hashlib
import subprocess
import tempfile
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db import models
from app.db.session import Base
from app.services.video_processor import segment_video, calculate_sha256
from app.services.verifier import verify_video
from app.utils.merkle import build_merkle_root, get_merkle_proof, verify_merkle_proof


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def db_session():
    """BD SQLite en memoria — se crea y destruye por módulo de test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


@pytest.fixture(scope="module")
def test_video_path():
    """Genera un vídeo de 35 s con ffmpeg y devuelve su ruta."""
    tmpdir = tempfile.mkdtemp(prefix="evideth_test_")
    path   = os.path.join(tmpdir, "test_video.mp4")

    cmd = [
        "ffmpeg", "-y",
        "-f", "lavfi",
        "-i", "testsrc=duration=35:size=320x240:rate=15",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        "-t", "35",
        path
    ]
    result = subprocess.run(cmd, capture_output=True)
    assert result.returncode == 0, f"ffmpeg falló: {result.stderr.decode()}"
    assert os.path.exists(path)
    return path


@pytest.fixture(scope="module")
def registered_video(db_session, test_video_path):
    """
    Registra cámara + video + segmentos en la BD con hashes reales.
    Devuelve (camera, video, segments).
    """
    tmpdir = tempfile.mkdtemp(prefix="evideth_segs_")

    # Cámara
    camera = models.Camera(
        id=str(uuid.uuid4()),
        camera_id="CAM-TEST-E2E",
        name="Test Camera",
        location="pytest",
        api_key=hashlib.sha256(b"test-key").hexdigest(),
        is_active=True,
    )
    db_session.add(camera)
    db_session.flush()

    # Video
    video = models.Video(
        id=str(uuid.uuid4()),
        filename="test_video.mp4",
        sha256_full=calculate_sha256(test_video_path),
        file_size_bytes=os.path.getsize(test_video_path),
        fps=15.0,
        resolution="320x240",
        codec="H264",
        status=models.VideoStatus.COMPLETED,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        camera_id=camera.id,
        duration_secs=35,
    )
    db_session.add(video)
    db_session.flush()

    # Segmentos con hashes reales
    computed = segment_video(test_video_path, tmpdir)
    db_segments = []
    for seg in computed:
        s = models.Segment(
            id=str(uuid.uuid4()),
            video_id=video.id,
            segment_index=seg["segment_index"],
            duration_secs=seg["duration_secs"],
            start_time_secs=seg["start_time_secs"],
            end_time_secs=seg["end_time_secs"],
            file_size_bytes=seg["file_size_bytes"],
            sha256_hash=seg["sha256_hash"],
            merkle_root=seg.get("merkle_root"),
            second_hashes=json.dumps(seg["second_hashes"]) if seg.get("second_hashes") else None,
            status=models.SegmentStatus.VALID,
            signed_at=datetime.now(timezone.utc),
        )
        db_session.add(s)
        db_segments.append(s)

    db_session.commit()
    return camera, video, db_segments


# ── Tests unitarios: Módulo Merkle ──────────────────────────────────────────

class TestMerkleTree:
    def test_single_leaf(self):
        h = hashlib.sha256(b"hello").hexdigest()
        assert build_merkle_root([h]) == h

    def test_two_leaves(self):
        h0 = hashlib.sha256(b"a").hexdigest()
        h1 = hashlib.sha256(b"b").hexdigest()
        root = build_merkle_root([h0, h1])
        assert len(root) == 64
        assert root != h0 and root != h1

    def test_odd_leaves_deterministic(self):
        """Con número impar de hojas, el resultado debe ser determinista."""
        leaves = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(3)]
        r1 = build_merkle_root(leaves)
        r2 = build_merkle_root(leaves)
        assert r1 == r2

    def test_proof_verification_valid(self):
        leaves = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(8)]
        root   = build_merkle_root(leaves)
        for idx in range(8):
            proof = get_merkle_proof(leaves, idx)
            assert verify_merkle_proof(leaves[idx], proof, root), \
                f"Prueba fallida para hoja {idx}"

    def test_proof_fails_with_wrong_leaf(self):
        leaves = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)]
        root   = build_merkle_root(leaves)
        proof  = get_merkle_proof(leaves, 0)
        wrong_leaf = hashlib.sha256(b"tampered").hexdigest()
        assert not verify_merkle_proof(wrong_leaf, proof, root)

    def test_different_content_different_root(self):
        leaves_a = [hashlib.sha256(b"frame_a").hexdigest()] * 30
        leaves_b = list(leaves_a)
        leaves_b[14] = hashlib.sha256(b"frame_TAMPERED").hexdigest()  # segundo 14
        assert build_merkle_root(leaves_a) != build_merkle_root(leaves_b)

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            build_merkle_root([])


# ── Tests de integración: Verificador ──────────────────────────────────────────

class TestVerificationE2E:

    def test_pass_original_video(self, db_session, registered_video, test_video_path):
        """
        CASO PASS: subir el vídeo original debe dar integrity_ok=True.
        """
        camera, video, _ = registered_video
        report = verify_video(
            video_path=video_path_copy(test_video_path),
            camera_id=camera.camera_id,
            video_db_id=video.id,
            db=db_session,
        )
        assert report["integrity_ok"] is True, \
            f"Esperaba PASS pero obtuvo: {report['verdict']}\n" \
            f"Segmentos: {[(s['segment_index'], s['result']) for s in report['segments']]}"
        assert report["verdict"] == "ÍNTEGRO"
        assert report["summary"]["passed"] > 0
        assert report["summary"]["failed"] == 0

    def test_fail_corrupted_video(self, db_session, registered_video, test_video_path):
        """
        CASO FAIL: modificar 1 byte en el vídeo → debe detectar manipulación.
        El byte se modifica en la mitad del archivo (zona de datos de vídeo).
        """
        camera, video, _ = registered_video
        corrupted_path = corrupt_video(test_video_path)

        report = verify_video(
            video_path=corrupted_path,
            camera_id=camera.camera_id,
            video_db_id=video.id,
            db=db_session,
        )
        assert report["integrity_ok"] is False, \
            "Esperaba FAIL (manipulación) pero el verificador no la detectó"
        assert report["verdict"] == "MANIPULADO O INCOMPLETO"
        assert report["summary"]["failed"] > 0

    def test_merkle_identifies_tampered_seconds(self, db_session, registered_video, test_video_path):
        """
        CASO MERKLE: si hay second_hashes almacenados, el informe debe incluir
        second_results con los segundos específicos manipulados.
        """
        camera, video, segments = registered_video

        # Solo ejecutamos si hay Merkle data en al menos un segmento
        has_merkle = any(s.merkle_root is not None for s in segments)
        if not has_merkle:
            pytest.skip("No hay Merkle data almacenada — daemon pendiente")

        corrupted_path = corrupt_video(test_video_path)
        report = verify_video(
            video_path=corrupted_path,
            camera_id=camera.camera_id,
            video_db_id=video.id,
            db=db_session,
        )

        # Comprobar que al menos un segmento tiene second_results
        segs_with_merkle = [
            s for s in report["segments"]
            if s.get("second_results") is not None
        ]
        assert len(segs_with_merkle) > 0, \
            "Esperaba second_results en al menos un segmento manipulado"

        # Comprobar que se identifican segundos concretos
        tampered_seconds = [
            sec["second_index"]
            for seg in segs_with_merkle
            for sec in seg["second_results"]
            if sec["tampered"]
        ]
        assert len(tampered_seconds) > 0, \
            "Merkle deberia identificar segundos específicos manipulados"

    def test_video_not_in_db_raises(self, db_session, test_video_path):
        """
        CASO GUARD: vídeo con UUID inexistente → ValueError.
        """
        with pytest.raises(ValueError, match="No hay segmentos"):
            verify_video(
                video_path=test_video_path,
                camera_id="CAM-TEST-E2E",
                video_db_id=str(uuid.uuid4()),  # UUID que no existe
                db=db_session,
            )


# ── Helpers ─────────────────────────────────────────────────────────────────────

def video_path_copy(src: str) -> str:
    """Devuelve el mismo path (el test no modifica el original)."""
    return src


def corrupt_video(src: str) -> str:
    """
    Copia el vídeo y modifica 1 byte en el primer segmento de datos.
    Devuelve la ruta del vídeo corrompido.
    """
    import shutil
    dst = src.replace(".mp4", "_corrupted.mp4")
    shutil.copy2(src, dst)

    file_size = os.path.getsize(dst)
    # Modificar un byte en el 20% del fichero (zona de datos de vídeo)
    corrupt_offset = int(file_size * 0.20)

    with open(dst, "r+b") as f:
        f.seek(corrupt_offset)
        original_byte = f.read(1)
        f.seek(corrupt_offset)
        # XOR con 0xFF para invertir el byte (garantiza cambio)
        f.write(bytes([original_byte[0] ^ 0xFF]))

    return dst
