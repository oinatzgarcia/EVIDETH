#!/usr/bin/env python3
"""
EVIDETH Camera Simulator
========================
Simula una cámara de seguridad:
  1. Genera vídeo sintético con OpenCV (frames con timestamp y camera ID)
  2. Divide la grabación en segmentos de SEGMENT_DURATION segundos
  3. Calcula el hash SHA-256 de cada segmento completo          (Nivel 1)
  4. Calcula hash SHA-256 de cada segundo del segmento con ffmpeg
  5. Construye el árbol Merkle sobre los hashes por segundo      (Nivel 2)
  6. Firma el Merkle root con ECDSA P-256 (clave local o Azure Key Vault)
  7. Envía todo al servidor EVIDETH
  8. Mantiene un heartbeat cada HEARTBEAT_INTERVAL segundos
  9. Reintenta los envíos fallidos mediante una cola persistente

CONVENCIN ECDSA:
    datos firmados = bytes.fromhex(merkle_root)   [32 bytes raw]
    algoritmo      = ECDSA con SHA-256 interno
    codificación   = base64url del DER signature
    Verificación en servidor:
        public_key.verify(sig, bytes.fromhex(merkle_root), ec.ECDSA(hashes.SHA256()))

Variables de entorno (ver .env.example):
    API_URL            URL base del backend
    CAMERA_API_KEY     X-API-Key de esta cámara
    CAMERA_ID          Identificador de cámara
    SEGMENT_DURATION   Segundos por segmento (default: 30)
    FPS                Frames por segundo     (default: 25)
    WIDTH / HEIGHT     Resolución del frame   (default: 1280x720)
    SIGNING_MODE       'local' | 'azure'      (default: local)
    PRIVATE_KEY_FILE   Ruta clave PEM         (SIGNING_MODE=local)
    AZURE_VAULT_URL    URL del Key Vault      (SIGNING_MODE=azure)
    AZURE_KEY_NAME     Nombre de la clave     (SIGNING_MODE=azure)
    TAMPER_MODE        'true' corrompe 1 de cada 3 segmentos para la demo
    HEARTBEAT_INTERVAL Segundos entre heartbeats (default: 30)
    MAX_RETRIES        Reintentos por petición (default: 3)
    RETRY_DELAY        Segundos base entre reintentos (default: 5)
    SAVE_SEGMENTS_DIR  Directorio donde copiar los segmentos generados
                       (vacío = no guardar). útil para pruebas de verificación.
    MAX_SEGMENTS       Máximo de segmentos a generar y parar (0 = infinito).
                       Ejemplo: MAX_SEGMENTS=1 genera 1 segmento de 30s y para.
"""

import os
import sys
import shutil
import time
import queue
import hashlib
import base64
import tempfile
import threading
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import cv2
import numpy as np
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from loguru import logger
from dotenv import load_dotenv

load_dotenv()


# ── Configuración ────────────────────────────────────────────

API_URL            = os.environ["API_URL"].rstrip("/")
CAMERA_API_KEY     = os.environ["CAMERA_API_KEY"]
CAMERA_ID          = os.environ["CAMERA_ID"]
SEGMENT_DURATION   = int(os.getenv("SEGMENT_DURATION",    "30"))
FPS                = int(os.getenv("FPS",                 "25"))
WIDTH              = int(os.getenv("WIDTH",               "1280"))
HEIGHT             = int(os.getenv("HEIGHT",              "720"))
SIGNING_MODE       = os.getenv("SIGNING_MODE",            "local")
PRIVATE_KEY_FILE   = os.getenv("PRIVATE_KEY_FILE",        "/keys/camera_private.pem")
TAMPER_MODE        = os.getenv("TAMPER_MODE",             "false").lower() == "true"
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL",  "30"))
MAX_RETRIES        = int(os.getenv("MAX_RETRIES",         "3"))
RETRY_DELAY        = int(os.getenv("RETRY_DELAY",         "5"))
SAVE_SEGMENTS_DIR  = os.getenv("SAVE_SEGMENTS_DIR",       "").strip()
MAX_SEGMENTS       = int(os.getenv("MAX_SEGMENTS",        "0"))   # 0 = infinito

# En Windows, TemporaryDirectory puede fallar al limpiar si OpenCV
# todavía tiene el handle abierto. ignore_cleanup_errors evita el crash.
IS_WINDOWS = sys.platform == "win32"

HEADERS    = {"X-API-Key": CAMERA_API_KEY}
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


# ── Merkle tree ───────────────────────────────────────────────

def _sha256_concat(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def build_merkle_root(leaf_hashes: List[str]) -> str:
    if not leaf_hashes:
        raise ValueError("Lista de hojas vacía")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            _sha256_concat(level[i], level[i + 1])
            for i in range(0, len(level), 2)
        ]
    return level[0]


# ── Hashing ─────────────────────────────────────────────────

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_second_hashes(seg_path: str, duration_secs: int) -> List[str]:
    leaf_hashes: List[str] = []
    # ignore_cleanup_errors=True: evita crash en Windows si ffmpeg deja handles abiertos
    with tempfile.TemporaryDirectory(prefix="evideth_sec_", ignore_cleanup_errors=IS_WINDOWS) as tmp:
        for sec in range(duration_secs):
            out = os.path.join(tmp, f"sec_{sec:04d}.mp4")
            cmd = [
                "ffmpeg", "-y",
                "-i",  seg_path,
                "-ss", str(sec),
                "-t",  "1",
                "-c",  "copy",
                "-avoid_negative_ts", "1",
                out,
            ]
            r = subprocess.run(cmd, capture_output=True)
            if (
                r.returncode != 0
                or not os.path.exists(out)
                or os.path.getsize(out) == 0
            ):
                logger.warning(f"  segundo {sec}: no extraíble → usando centinela")
                leaf_hashes.append(_EMPTY_HASH)
            else:
                leaf_hashes.append(sha256_file(out))
    return leaf_hashes


# ── CryptoService ──────────────────────────────────────────────

class CryptoService:
    def __init__(self):
        if SIGNING_MODE == "azure":
            self._init_azure()
        else:
            self._init_local()

    def _init_local(self):
        key_path = Path(PRIVATE_KEY_FILE)
        if key_path.exists():
            with open(key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            logger.info(f"Clave privada cargada desde {key_path}")
        else:
            self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            key_path.parent.mkdir(parents=True, exist_ok=True)
            pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_path.write_bytes(pem)
            logger.info(f"Nueva clave ECDSA P-256 generada → {key_path}")

        pub_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_export = key_path.parent / "camera_public.pem"
        pub_export.write_bytes(pub_pem)
        self.public_key_id = hashlib.sha256(pub_pem).hexdigest()[:16]
        logger.info(f"public_key_id : {self.public_key_id}")
        logger.info(f"Clave pública → {pub_export}")

    def _init_azure(self):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
        vault_url   = os.environ["AZURE_VAULT_URL"]
        key_name    = os.environ["AZURE_KEY_NAME"]
        credential  = DefaultAzureCredential()
        key_client  = KeyClient(vault_url=vault_url, credential=credential)
        key         = key_client.get_key(key_name)
        self._crypto_client = CryptographyClient(key, credential=credential)
        self._sign_algo     = SignatureAlgorithm.es256
        self.public_key_id  = key_name
        logger.info(f"Azure Key Vault — clave: {key_name}")

    def sign(self, merkle_root: str) -> str:
        data = bytes.fromhex(merkle_root)
        if SIGNING_MODE == "azure":
            digest = hashlib.sha256(data).digest()
            result = self._crypto_client.sign(self._sign_algo, digest)
            return base64.urlsafe_b64encode(result.signature).decode()
        else:
            sig = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            return base64.urlsafe_b64encode(sig).decode()


# ── APIClient ─────────────────────────────────────────────────

class APIClient:
    def start_video(self, filename: str) -> str:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = requests.post(
                    f"{API_URL}/cameras/videos",
                    json={"filename": filename, "fps": FPS,
                          "resolution": f"{WIDTH}x{HEIGHT}", "codec": "mp4v"},
                    headers=HEADERS, timeout=10,
                )
                r.raise_for_status()
                video_id = r.json()["id"]
                logger.info(f"Vídeo registrado: {video_id}")
                return video_id
            except Exception as exc:
                logger.warning(f"start_video intento {attempt}/{MAX_RETRIES}: {exc}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
        raise RuntimeError("start_video falló tras máximo de reintentos")

    def send_segment(self, payload: dict) -> bool:
        idx = payload["segment_index"]
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = requests.post(
                    f"{API_URL}/cameras/segments",
                    json=payload, headers=HEADERS, timeout=15,
                )
                if r.status_code == 409:
                    logger.warning(f"Segmento #{idx} ya registrado (409)")
                    return True
                if not r.ok:
                    # Loguear el body del error para facilitar el debugging
                    try:
                        err_body = r.json()
                    except Exception:
                        err_body = r.text[:500]
                    logger.warning(
                        f"send_segment #{idx} intento {attempt}/{MAX_RETRIES}: "
                        f"{r.status_code} {r.reason}\n"
                        f"  └─ Body: {err_body}"
                    )
                    if attempt < MAX_RETRIES:
                        time.sleep(RETRY_DELAY * attempt)
                    continue
                r.raise_for_status()
                srv_root = r.json().get("merkle_root", "N/A")
                logger.success(
                    f"Segmento #{idx} aceptado — "
                    f"hash: {payload['sha256_hash'][:16]}... — "
                    f"merkle_root: {str(srv_root)[:16]}..."
                )
                return True
            except Exception as exc:
                logger.warning(f"send_segment #{idx} intento {attempt}/{MAX_RETRIES}: {exc}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
        return False

    def finish_video(self, video_id: str) -> None:
        try:
            r = requests.patch(
                f"{API_URL}/cameras/videos/{video_id}/finish",
                headers=HEADERS, timeout=10,
            )
            r.raise_for_status()
            logger.info(f"Vídeo {video_id} finalizado")
        except Exception as exc:
            logger.error(f"finish_video error: {exc}")

    def heartbeat(self) -> None:
        try:
            r = requests.post(f"{API_URL}/cameras/heartbeat", headers=HEADERS, timeout=5)
            r.raise_for_status()
            logger.debug("Heartbeat OK")
        except Exception as exc:
            logger.warning(f"Heartbeat fallido: {exc}")


# ── VideoGenerator ───────────────────────────────────────────

class VideoGenerator:
    def record_segment(self, out_path: str, segment_index: int, start_epoch: int) -> None:
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(out_path, fourcc, float(FPS), (WIDTH, HEIGHT))
        if not writer.isOpened():
            raise RuntimeError(f"VideoWriter no pudo abrir: {out_path}")
        total_frames = FPS * SEGMENT_DURATION
        t0 = time.time()
        for frame_n in range(total_frames):
            abs_sec = start_epoch + frame_n // FPS
            writer.write(self._build_frame(frame_n, segment_index, abs_sec))
            elapsed  = time.time() - t0
            expected = frame_n / FPS
            if expected > elapsed:
                time.sleep(expected - elapsed)
        writer.release()
        # Windows necesita un momento para liberar el handle del fichero
        if IS_WINDOWS:
            time.sleep(0.3)
        size_mb = os.path.getsize(out_path) / (1024 * 1024)
        logger.debug(f"Segmento {segment_index} escrito → {out_path} ({size_mb:.1f} MB)")

    def _build_frame(self, frame_n: int, segment_index: int, abs_sec: int) -> np.ndarray:
        frame = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)
        for y in range(0, HEIGHT, 60):
            cv2.line(frame, (0, y), (WIDTH, y), (8, 20, 8), 1)
        for x in range(0, WIDTH, 60):
            cv2.line(frame, (x, 0), (x, HEIGHT), (8, 20, 8), 1)
        cx, cy = WIDTH // 2, HEIGHT // 2
        pulse  = int(abs((frame_n % (FPS * 2)) - FPS) * 1.5)
        col    = (0, min(80 + pulse, 255), 0)
        cv2.circle(frame, (cx, cy), 80, col, 1)
        cv2.circle(frame, (cx, cy),  4, col, -1)
        cv2.line(frame, (cx - 40, cy), (cx + 40, cy), col, 1)
        cv2.line(frame, (cx, cy - 40), (cx, cy + 40), col, 1)
        corner_len, corner_col = 20, (0, 120, 0)
        for ox, oy, sx, sy in [
            (0, 0, 1, 1), (WIDTH-1, 0, -1, 1),
            (0, HEIGHT-1, 1, -1), (WIDTH-1, HEIGHT-1, -1, -1),
        ]:
            cv2.line(frame, (ox, oy), (ox + sx*corner_len, oy), corner_col, 1)
            cv2.line(frame, (ox, oy), (ox, oy + sy*corner_len), corner_col, 1)
        now_str = datetime.fromtimestamp(abs_sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        font = cv2.FONT_HERSHEY_SIMPLEX
        cv2.putText(frame, f"EVIDETH — {CAMERA_ID}",
                    (20, 38), font, 0.85, (0, 200, 255), 1, cv2.LINE_AA)
        cv2.putText(frame, f"SEG {segment_index:04d}  FRM {frame_n:06d}  [{WIDTH}x{HEIGHT} @ {FPS}fps]",
                    (20, 70), font, 0.55, (0, 140, 180), 1, cv2.LINE_AA)
        cv2.putText(frame, now_str,
                    (20, HEIGHT-18), font, 0.55, (0, 180, 80), 1, cv2.LINE_AA)
        cv2.putText(frame, "SHA-256 · ECDSA P-256 · Merkle · EVIDETH",
                    (WIDTH-420, HEIGHT-18), font, 0.45, (40, 60, 40), 1, cv2.LINE_AA)
        if TAMPER_MODE and segment_index % 3 == 0:
            cv2.rectangle(frame, (cx-220, cy-40), (cx+220, cy+50), (0, 0, 180), 2)
            cv2.putText(frame, "!! TAMPERED !!",
                        (cx-175, cy+15), font, 1.4, (0, 0, 255), 3, cv2.LINE_AA)
        return frame


# ── CameraSimulator (daemon principal) ───────────────────────────

class CameraSimulator:
    def __init__(self):
        self.api    = APIClient()
        self.crypto = CryptoService()
        self.gen    = VideoGenerator()
        self._failed: queue.Queue = queue.Queue()
        self._stop  = threading.Event()
        self._saved_files: list  = []

    def run(self) -> None:
        limit_str = f"{MAX_SEGMENTS} segmento(s)" if MAX_SEGMENTS > 0 else "infinito (Ctrl+C para parar)"
        logger.info("=" * 60)
        logger.info("EVIDETH Camera Simulator")
        logger.info(f"  Cámara     : {CAMERA_ID}")
        logger.info(f"  Backend    : {API_URL}")
        logger.info(f"  Segmento   : {SEGMENT_DURATION}s @ {FPS}fps {WIDTH}x{HEIGHT}")
        logger.info(f"  Firma      : {SIGNING_MODE.upper()} sobre merkle_root")
        logger.info(f"  Tamper     : {'ACTIVADO ⚠️' if TAMPER_MODE else 'desactivado'}")
        logger.info(f"  Guardar    : {SAVE_SEGMENTS_DIR if SAVE_SEGMENTS_DIR else 'desactivado'}")
        logger.info(f"  Límite     : {limit_str}")
        logger.info("=" * 60)

        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        threading.Thread(target=self._retry_loop,     daemon=True, name="retry").start()

        segment_index = 0
        boot_epoch    = int(time.time())

        try:
            while not self._stop.is_set():
                if MAX_SEGMENTS > 0 and segment_index >= MAX_SEGMENTS:
                    logger.info(f"✅ MAX_SEGMENTS={MAX_SEGMENTS} alcanzado — simulador detenido")
                    break
                self._process_segment(segment_index, boot_epoch)
                segment_index += 1
        except KeyboardInterrupt:
            logger.info("Simulador detenido (Ctrl+C)")
        finally:
            self._stop.set()
            self._print_summary(segment_index)

    def _print_summary(self, total: int) -> None:
        logger.info("=" * 60)
        logger.info(f"RESUMEN: {total} segmento(s) generados y enviados")
        if self._saved_files:
            logger.info(f"Vídeos guardados en: {SAVE_SEGMENTS_DIR}")
            for path in self._saved_files:
                logger.info(f"  💾 {path}")
            logger.info("")
            logger.info("Para verificar integridad (Swagger UI):")
            logger.info("  POST /api/v1/verification/upload/{video_id}")
            logger.info("  → Adjuntar fichero .mp4 del listado anterior")
        logger.info("=" * 60)

    def _process_segment(self, idx: int, boot_epoch: int) -> None:
        ts    = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fname = f"{CAMERA_ID}_{ts}_seg{idx:04d}.mp4"

        video_id   = self.api.start_video(fname)
        start_secs = idx * SEGMENT_DURATION

        # ignore_cleanup_errors=True evita PermissionError en Windows
        with tempfile.TemporaryDirectory(
            prefix="evideth_sim_",
            ignore_cleanup_errors=IS_WINDOWS,
        ) as tmp:
            seg_path = os.path.join(tmp, fname)

            logger.info(f"--- Grabando segmento {idx}/{MAX_SEGMENTS if MAX_SEGMENTS > 0 else '∞'} ({SEGMENT_DURATION}s) ---")
            self.gen.record_segment(seg_path, idx, boot_epoch + start_secs)

            if TAMPER_MODE and idx % 3 == 0:
                self._tamper_file(seg_path)
                logger.warning(f"[TAMPER] Segmento {idx} corrompido (demo)")

            sha256    = sha256_file(seg_path)
            file_size = os.path.getsize(seg_path)

            logger.info(f"  Calculando hashes por segundo ({SEGMENT_DURATION} chunks)...")
            second_hashes = extract_second_hashes(seg_path, SEGMENT_DURATION)
            merkle_root   = build_merkle_root(second_hashes)
            signature     = self.crypto.sign(merkle_root)

            logger.info(
                f"  Segmento {idx} listo:\n"
                f"    sha256      : {sha256[:16]}...\n"
                f"    merkle_root : {merkle_root[:16]}...\n"
                f"    firma       : {signature[:20]}..."
            )

            if SAVE_SEGMENTS_DIR:
                os.makedirs(SAVE_SEGMENTS_DIR, exist_ok=True)
                saved_path = os.path.join(SAVE_SEGMENTS_DIR, fname)
                shutil.copy2(seg_path, saved_path)
                self._saved_files.append(saved_path)
                logger.info(
                    f"  💾 Guardado → {saved_path}\n"
                    f"     video_id  : {video_id}"
                )

            payload = {
                "video_id":        video_id,
                "segment_index":   idx,
                "start_time_secs": start_secs,
                "end_time_secs":   start_secs + SEGMENT_DURATION,
                "sha256_hash":     sha256,
                "ecdsa_signature": signature,
                "public_key_id":   self.crypto.public_key_id,
                "file_size_bytes": file_size,
                "merkle_root":     merkle_root,
                "second_hashes":   second_hashes,
            }

            if not self.api.send_segment(payload):
                logger.error(f"Segmento {idx} encolado para reintento")
                self._failed.put(payload)

        self.api.finish_video(video_id)

    @staticmethod
    def _tamper_file(path: str) -> None:
        size = os.path.getsize(path)
        if size < 300:
            return
        mid = size // 2
        with open(path, "r+b") as f:
            f.seek(mid)
            original = f.read(128)
            f.seek(mid)
            f.write(bytes(b ^ 0xFF for b in original))

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(timeout=HEARTBEAT_INTERVAL):
            self.api.heartbeat()

    def _retry_loop(self) -> None:
        while not self._stop.wait(timeout=60):
            if self._failed.empty():
                continue
            logger.info(f"Reintentando {self._failed.qsize()} segmentos pendientes")
            pending = []
            while not self._failed.empty():
                try:
                    p = self._failed.get_nowait()
                    if self.api.send_segment(p):
                        logger.success(f"Reintento OK — segmento #{p['segment_index']}")
                    else:
                        pending.append(p)
                except queue.Empty:
                    break
            for p in pending:
                self._failed.put(p)


# ── Entry point ────────────────────────────────────────────

if __name__ == "__main__":
    CameraSimulator().run()
