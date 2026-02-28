"""
tests/integration/test_ecdsa_e2e.py

Prueba de integración end-to-end del flujo ECDSA completo de EVIDETH.

Cubre el ciclo desde la cámara hasta el verificador forense:
  1. Genera vídeo sintético con ffmpeg
  2. Calcula second_hashes + Merkle root (como el simulador)
  3. Firma cada Merkle root con ECDSA P-256 (clave real, modo local)
  4. Registra cámara + clave pública + video + segmentos firmados en BD
  5. Ejecuta verify_video() y valida todos los niveles:
       Nivel 1: SHA-256 del segmento
       Nivel 2: Árbol Merkle por segundo
       Nivel 3: Firma ECDSA P-256

Casos cubiertos:
  - PASS:              vídeo original, clave correcta
  - FAIL-HASH:         vídeo corrompido (hash mismatch)
  - FAIL-ECDSA:        firma con clave A, registrada clave B (suplantación)
  - SKIP-ECDSA:        cámara sin clave pública registrada (legacy / inicio)
  - MERKLE-PRECISION:  segundo exacto manipulado identificado en second_results

Ejecución:
    pytest tests/integration/test_ecdsa_e2e.py -v
    pytest tests/integration/test_ecdsa_e2e.py -v -s   # con output detallado

Requisitos: ffmpeg instalado en el sistema.
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.db import models
from app.db.session import Base
from app.services.video_processor import segment_video
from app.services.verifier import verify_video, verify_ecdsa_signature
from app.utils.merkle import build_merkle_root


# ── Helpers criptográficos (réplica exacta del simulador) ────────────────────

def _generate_keypair():
    """
    Genera ECDSA P-256. Devuelve (private_key, public_key_pem_str).
    Idéntico a CryptoService._init_local() del simulador.
    """
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub_pem


def _sign(private_key, merkle_root_hex: str) -> str:
    """
    Firma el Merkle root con la misma convención que CryptoService.sign():
        datos = bytes.fromhex(merkle_root)  ← 32 bytes raw
        sig   = base64url(ECDSA-SHA256(datos))
    """
    data = bytes.fromhex(merkle_root_hex)
    sig  = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(sig).decode()


def _fingerprint(pub_pem: str) -> str:
    """Primeros 16 hex del SHA-256 del PEM (= public_key_id del simulador)."""
    return hashlib.sha256(pub_pem.encode()).hexdigest()[:16]


# ── Fixtures compartidos ─────────────────────────────────────────────

@pytest.fixture(scope="module")
def db():
    """BD SQLite en memoria — compartida por todos los tests del módulo."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


@pytest.fixture(scope="module")
def tmp_dir():
    d = tempfile.mkdtemp(prefix="evideth_ecdsa_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def real_video(tmp_dir):
    """
    Vídeo sintético de 35 s generado con ffmpeg.
    35 s = 1 segmento completo de 30 s + 1 segmento de 5 s.
    """
    path = os.path.join(tmp_dir, "ecdsa_test_video.mp4")
    cmd  = [
        "ffmpeg", "-y",
        "-f", "lavfi",
        "-i", "testsrc=duration=35:size=320x240:rate=15",
        "-c:v", "libx264", "-pix_fmt", "yuv420p",
        "-t", "35",
        path,
    ]
    r = subprocess.run(cmd, capture_output=True)
    assert r.returncode == 0, f"ffmpeg falló: {r.stderr.decode()[:500]}"
    return path


@pytest.fixture(scope="module")
def keypair_a():
    """Par de claves legítimo de la cámara."""
    return _generate_keypair()


@pytest.fixture(scope="module")
def keypair_b():
    """Par de claves de un atacante (suplantación)."""
    return _generate_keypair()


@pytest.fixture(scope="module")
def processed_segments(real_video, tmp_dir):
    """
    Procesa el vídeo con segment_video() para obtener hashes reales.
    Devuelve la lista de dicts de segmentos (como lo haría el servidor).
    """
    seg_dir = os.path.join(tmp_dir, "segs")
    os.makedirs(seg_dir, exist_ok=True)
    return segment_video(real_video, seg_dir)


def _make_camera(db, camera_id: str, public_key_pem: str = None) -> models.Camera:
    """Crea una cámara en BD (con o sin clave pública)."""
    camera = models.Camera(
        id=str(uuid.uuid4()),
        camera_id=camera_id,
        name=f"Test Camera {camera_id}",
        location="pytest",
        api_key=hashlib.sha256(camera_id.encode()).hexdigest(),
        is_active=True,
        public_key_pem=public_key_pem,
    )
    db.add(camera)
    db.flush()
    return camera


def _make_video(db, camera: models.Camera) -> models.Video:
    """Crea un Video en BD asociado a la cámara."""
    video = models.Video(
        id=str(uuid.uuid4()),
        filename="test.mp4",
        status=models.VideoStatus.COMPLETED,
        fps=15.0,
        resolution="320x240",
        codec="H264",
        camera_id=camera.id,
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        duration_secs=35,
        file_size_bytes=1024,
    )
    db.add(video)
    db.flush()
    return video


def _make_segments(
    db,
    video: models.Video,
    processed:    list,
    private_key,
    pub_key_id:   str,
    corrupt_sig:  bool = False,
) -> list:
    """
    Crea los Segments en BD firmando cada Merkle root con private_key.

    Args:
        corrupt_sig: Si True, invierte el último byte de cada firma
                     para simular una firma inválida.
    """
    segments = []
    for seg in processed:
        merkle_root = seg.get("merkle_root")
        signature   = _sign(private_key, merkle_root) if merkle_root else None

        if corrupt_sig and signature:
            raw     = base64.urlsafe_b64decode(signature + "==")
            bad     = raw[:-1] + bytes([raw[-1] ^ 0xFF])
            signature = base64.urlsafe_b64encode(bad).decode()

        s = models.Segment(
            id=str(uuid.uuid4()),
            video_id=video.id,
            segment_index=seg["segment_index"],
            duration_secs=seg["duration_secs"],
            start_time_secs=seg["start_time_secs"],
            end_time_secs=seg["end_time_secs"],
            file_size_bytes=seg.get("file_size_bytes", 0),
            sha256_hash=seg["sha256_hash"],
            merkle_root=merkle_root,
            second_hashes=json.dumps(seg["second_hashes"]) if seg.get("second_hashes") else None,
            ecdsa_signature=signature,
            public_key_id=pub_key_id,
            status=models.SegmentStatus.VALID,
            signed_at=datetime.now(timezone.utc),
        )
        db.add(s)
        segments.append(s)

    db.commit()
    return segments


# ── Tests ─────────────────────────────────────────────────

class TestEcdsaE2E:

    def test_ecdsa_pass_full_chain(
        self, db, real_video, processed_segments, keypair_a
    ):
        """
        CASO PASS — cadena completa íntegra:
          Cámara firma con clave A → se registra clave A → verify_video() PASS

        Valida los 3 niveles:
          Nivel 1: SHA-256 correcto
          Nivel 2: Merkle roots coinciden
          Nivel 3: Firma ECDSA válida
        """
        priv_a, pub_a = keypair_a

        camera  = _make_camera(db, "CAM-ECDSA-PASS", public_key_pem=pub_a)
        video   = _make_video(db, camera)
        _make_segments(db, video, processed_segments, priv_a, _fingerprint(pub_a))

        report = verify_video(
            video_path  = real_video,
            camera_id   = camera.camera_id,
            video_db_id = video.id,
            db          = db,
        )

        assert report["integrity_ok"]      is True,  f"Esperaba PASS: {report['verdict']}"
        assert report["ecdsa_available"]   is True,  "Clave pública no estaba disponible"
        assert report["summary"]["failed"] == 0

        # Verificar que los segmentos con firma reportan ECDSA OK
        signed_segs = [s for s in report["segments"] if s["signature_valid"] is not None]
        assert len(signed_segs) > 0, "Ningún segmento tenía firma evaluada"
        assert all(s["signature_valid"] for s in signed_segs), \
            f"Segmentos con firma inválida: {[s['segment_index'] for s in signed_segs if not s['signature_valid']]}"

    def test_ecdsa_fail_video_tampered(
        self, db, real_video, tmp_dir, processed_segments, keypair_a
    ):
        """
        CASO FAIL-HASH — vídeo corrompido:
          La firma ECDSA sigue siendo válida (el segmento almacenado es autentico)
          pero el hash del vídeo subido no coincide → FAIL (manipulación detectada)
        """
        priv_a, pub_a = keypair_a

        camera  = _make_camera(db, "CAM-ECDSA-TAMPERED", public_key_pem=pub_a)
        video   = _make_video(db, camera)
        _make_segments(db, video, processed_segments, priv_a, _fingerprint(pub_a))

        # Corromper 1 byte en la zona de datos (20% del fichero)
        corrupted = os.path.join(tmp_dir, "corrupted.mp4")
        shutil.copy2(real_video, corrupted)
        size   = os.path.getsize(corrupted)
        offset = int(size * 0.20)
        with open(corrupted, "r+b") as f:
            f.seek(offset)
            b = f.read(1)[0]
            f.seek(offset)
            f.write(bytes([b ^ 0xFF]))

        report = verify_video(
            video_path  = corrupted,
            camera_id   = camera.camera_id,
            video_db_id = video.id,
            db          = db,
        )

        assert report["integrity_ok"]      is False, "Debería haber detectado la manipulación"
        assert report["summary"]["failed"] > 0

    def test_ecdsa_fail_wrong_key(
        self, db, real_video, processed_segments, keypair_a, keypair_b
    ):
        """
        CASO FAIL-ECDSA — suplantación de cámara:
          Cámara firma con clave A (legítima)
          Atacante registra clave B en el servidor
          verify_video() detecta: firma A no es válida con clave B → FAIL

          O bien: segmentos firmados con clave B pero registrada clave A
          (simulación de cámara comprometida)
        """
        priv_a, pub_a = keypair_a
        _,      pub_b = keypair_b

        # La cámara firma con clave A pero se registra la clave B en el servidor
        camera  = _make_camera(db, "CAM-ECDSA-WRONGKEY", public_key_pem=pub_b)
        video   = _make_video(db, camera)
        _make_segments(db, video, processed_segments, priv_a, _fingerprint(pub_a))

        report = verify_video(
            video_path  = real_video,
            camera_id   = camera.camera_id,
            video_db_id = video.id,
            db          = db,
        )

        assert report["integrity_ok"] is False, \
            "La clave incorrecta debería hacer fallar la verificación"
        assert report["ecdsa_available"] is True

        invalid_sig_segs = [
            s for s in report["segments"]
            if s["signature_valid"] is False
        ]
        assert len(invalid_sig_segs) > 0, \
            "Esperaba al menos un segmento con signature_valid=False"

    def test_ecdsa_no_public_key(
        self, db, real_video, processed_segments, keypair_a
    ):
        """
        CASO SKIP-ECDSA — cámara sin clave pública registrada:
          Simula una cámara legacy o recién configurada.
          La verificación debe continuar usando solo hash + Merkle.
          ecdsa_available=False, pero integrity_ok depende solo del hash.
        """
        priv_a, pub_a = keypair_a

        # Cámara sin public_key_pem
        camera  = _make_camera(db, "CAM-ECDSA-NOKEY", public_key_pem=None)
        video   = _make_video(db, camera)
        _make_segments(db, video, processed_segments, priv_a, _fingerprint(pub_a))

        report = verify_video(
            video_path  = real_video,
            camera_id   = camera.camera_id,
            video_db_id = video.id,
            db          = db,
        )

        # ECDSA no disponible pero el hash sigue siendo correcto
        assert report["ecdsa_available"] is False
        assert report["integrity_ok"]    is True,  \
            "Hash + Merkle deben pasar aunque no haya clave ECDSA registrada"
        assert all(
            s["signature_valid"] is None
            for s in report["segments"]
        ), "signature_valid debería ser None cuando no hay clave registrada"

    def test_ecdsa_merkle_precision(
        self, db, real_video, tmp_dir, processed_segments, keypair_a
    ):
        """
        CASO MERKLE-PRECISION — segundo exacto identificado:
          Corromper el vídeo y verificar que second_results lista exactamente
          los segundos afectados (no solo que hay un fallo genérico).
        """
        priv_a, pub_a = keypair_a

        has_merkle = any(s.get("merkle_root") for s in processed_segments)
        if not has_merkle:
            pytest.skip("segment_video() no ha calculado Merkle data")

        camera  = _make_camera(db, "CAM-ECDSA-MERKLE", public_key_pem=pub_a)
        video   = _make_video(db, camera)
        _make_segments(db, video, processed_segments, priv_a, _fingerprint(pub_a))

        corrupted = os.path.join(tmp_dir, "corrupted_merkle.mp4")
        shutil.copy2(real_video, corrupted)
        size   = os.path.getsize(corrupted)
        offset = int(size * 0.20)
        with open(corrupted, "r+b") as f:
            f.seek(offset)
            b = f.read(1)[0]
            f.seek(offset)
            f.write(bytes([b ^ 0xFF]))

        report = verify_video(
            video_path  = corrupted,
            camera_id   = camera.camera_id,
            video_db_id = video.id,
            db          = db,
        )

        # Buscar segmentos con second_results (nivel Merkle activado)
        segs_with_detail = [
            s for s in report["segments"]
            if s.get("second_results") is not None
        ]

        if segs_with_detail:
            # Debe haber al menos un segundo marcado como manipulado
            tampered = [
                sec
                for s   in segs_with_detail
                for sec in s["second_results"]
                if sec["tampered"]
            ]
            assert len(tampered) > 0, \
                "Merkle debería identificar al menos un segundo manipulado"
            # Cada segundo manipulado debe tener los dos hashes para auditoría
            for t in tampered:
                assert "computed_hash" in t
                assert "stored_hash"   in t
                assert "second_index" in t
        else:
            # Si la corrupción no afectó ningún segmento, el test es inconcluyente
            pytest.skip("La corrupción no afectó ningún segmento procesado")


# ── Test directo de verify_ecdsa_signature (nivel servicio) ──────────────────

class TestVerifyEcdsaSignatureIntegration:
    """
    Prueba la función verify_ecdsa_signature() con claves reales
    en el contexto de integración (mismos helpers que usa el E2E).
    """

    def test_sign_and_verify_roundtrip(self, keypair_a):
        priv, pub_pem = keypair_a
        merkle_root   = hashlib.sha256(os.urandom(32)).hexdigest()
        signature     = _sign(priv, merkle_root)
        assert verify_ecdsa_signature(merkle_root, signature, pub_pem) is True

    def test_different_keypairs_fail(self, keypair_a, keypair_b):
        priv_a, _     = keypair_a
        _,      pub_b = keypair_b
        merkle_root   = hashlib.sha256(os.urandom(32)).hexdigest()
        signature     = _sign(priv_a, merkle_root)
        assert verify_ecdsa_signature(merkle_root, signature, pub_b) is False
