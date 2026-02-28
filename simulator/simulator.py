#!/usr/bin/env python3
"""
EVIDETH Camera Simulator
========================
Simula una cámara de seguridad:
  1. Genera vídeo sintético con OpenCV (frames con timestamp y camera ID)
  2. Divide la grabación en segmentos de SEGMENT_DURATION segundos
  3. Calcula el hash SHA-256 de cada segmento
  4. Firma el hash con ECDSA P-256 (clave local o Azure Key Vault)
  5. Envía el segmento + hash + firma al servidor EVIDETH
  6. Mantiene un heartbeat cada HEARTBEAT_INTERVAL segundos
  7. Reintenta los envíos fallidos mediante una cola persistente

Variables de entorno (ver .env.example):
    API_URL            URL base del backend  (e.g. https://evideth.azurewebsites.net/api/v1)
    CAMERA_API_KEY     X-API-Key de esta cámara
    CAMERA_ID          Identificador  (e.g. CAM-SIM-01)
    SEGMENT_DURATION   Segundos por segmento  (default: 60)
    FPS                Frames por segundo     (default: 25)
    WIDTH / HEIGHT     Resolución del frame   (default: 1280x720)
    SIGNING_MODE       'local' | 'azure'      (default: local)
    PRIVATE_KEY_FILE   Ruta clave PEM         (SIGNING_MODE=local)
    AZURE_VAULT_URL    URL del Key Vault      (SIGNING_MODE=azure)
    AZURE_KEY_NAME     Nombre de la clave     (SIGNING_MODE=azure)
    TAMPER_MODE        'true' corrompe 1 de cada 3 segmentos para la demo
    HEARTBEAT_INTERVAL Segundos entre heartbeats (default: 30)
    MAX_RETRIES        Reintentos por petición (default: 3)
    RETRY_DELAY        Segundos base de espera entre reintentos (default: 5)
"""

import os
import time
import queue
import hashlib
import base64
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

import cv2
import numpy as np
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from loguru import logger
from dotenv import load_dotenv

load_dotenv()


# ── Configuración ────────────────────────────────────────────────

API_URL            = os.environ["API_URL"].rstrip("/")
CAMERA_API_KEY     = os.environ["CAMERA_API_KEY"]
CAMERA_ID          = os.environ["CAMERA_ID"]
SEGMENT_DURATION   = int(os.getenv("SEGMENT_DURATION",   "60"))
FPS                = int(os.getenv("FPS",                "25"))
WIDTH              = int(os.getenv("WIDTH",              "1280"))
HEIGHT             = int(os.getenv("HEIGHT",             "720"))
SIGNING_MODE       = os.getenv("SIGNING_MODE",           "local")
PRIVATE_KEY_FILE   = os.getenv("PRIVATE_KEY_FILE",       "/keys/camera_private.pem")
TAMPER_MODE        = os.getenv("TAMPER_MODE",            "false").lower() == "true"
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "30"))
MAX_RETRIES        = int(os.getenv("MAX_RETRIES",        "3"))
RETRY_DELAY        = int(os.getenv("RETRY_DELAY",        "5"))

HEADERS = {"X-API-Key": CAMERA_API_KEY}


# ── Utilidades criptográficas ─────────────────────────────────────

def sha256_file(path: str) -> str:
    """
    Calcula el hash SHA-256 de un fichero.
    Lee en bloques de 64 KB para no cargar el fichero entero en memoria.
    Devuelve el hash como cadena hexadecimal en minúsculas (64 chars).
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class CryptoService:
    """
    Servicio de firma ECDSA P-256.

    Soporta dos modos:
    - local  : clave PEM en disco (se genera automáticamente si no existe)
    - azure  : Azure Key Vault con DefaultAzureCredential

    Convenio de firma:
        Se firma el string hexadecimal del hash SHA-256 codificado en UTF-8.
        El servidor verifica: verify(sig, sha256_hex.encode('utf-8'), ECDSA-SHA256)
    """

    def __init__(self):
        if SIGNING_MODE == "azure":
            self._init_azure()
        else:
            self._init_local()

    # ── Inicialización ────────────────────────────────────────

    def _init_local(self):
        key_path = Path(PRIVATE_KEY_FILE)
        if key_path.exists():
            with open(key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            logger.info(f"Clave privada cargada desde {key_path}")
        else:
            # Primera ejecución: generar y persistir clave nueva
            self._private_key = ec.generate_private_key(
                ec.SECP256R1(), default_backend()
            )
            key_path.parent.mkdir(parents=True, exist_ok=True)
            pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_path.write_bytes(pem)
            logger.info(f"Nueva clave ECDSA P-256 generada → {key_path}")

        # Huella pública (primeros 16 hex del SHA-256 del PEM público)
        pub_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_id = hashlib.sha256(pub_pem).hexdigest()[:16]
        logger.info(f"public_key_id (fingerprint): {self.public_key_id}")

        # Exportar clave pública para que el servidor pueda verificar
        pub_export = key_path.parent / "camera_public.pem"
        pub_export.write_bytes(pub_pem)
        logger.info(f"Clave pública exportada → {pub_export}")

    def _init_azure(self):
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

        vault_url  = os.environ["AZURE_VAULT_URL"]
        key_name   = os.environ["AZURE_KEY_NAME"]
        credential = DefaultAzureCredential()
        key_client = KeyClient(vault_url=vault_url, credential=credential)
        key        = key_client.get_key(key_name)
        self._crypto_client = CryptographyClient(key, credential=credential)
        self._sign_algo     = SignatureAlgorithm.es256
        self.public_key_id  = key_name
        logger.info(f"Azure Key Vault conectado — clave: {key_name}")

    # ── Firma ─────────────────────────────────────────────

    def sign(self, sha256_hex: str) -> str:
        """
        Firma el string hexadecimal del hash SHA-256.
        Devuelve la firma en Base64url (DER encoding).

        Verificación en el servidor:
            public_key.verify(
                base64.urlsafe_b64decode(signature + '=='),
                sha256_hex.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
        """
        data = sha256_hex.encode("utf-8")   # 64 bytes ASCII

        if SIGNING_MODE == "azure":
            # Azure KV calcula el digest internamente con ES256
            import hashlib as _hl
            digest = _hl.sha256(data).digest()
            result = self._crypto_client.sign(self._sign_algo, digest)
            return base64.urlsafe_b64encode(result.signature).decode()
        else:
            sig = self._private_key.sign(data, ec.ECDSA(hashes.SHA256()))
            return base64.urlsafe_b64encode(sig).decode()


# ── Cliente API ──────────────────────────────────────────────

class APIClient:
    """
    Comunicación con el backend EVIDETH.
    Todos los métodos implementan reintentos con backoff exponencial.
    """

    def start_video(self, filename: str) -> str:
        """Registra el inicio de una grabación. Devuelve el UUID del vídeo."""
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = requests.post(
                    f"{API_URL}/cameras/videos",
                    json={
                        "filename":   filename,
                        "fps":        FPS,
                        "resolution": f"{WIDTH}x{HEIGHT}",
                        "codec":      "mp4v",
                    },
                    headers=HEADERS,
                    timeout=10,
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
        """
        Envía un segmento al servidor.
        Devuelve True si el servidor lo aceptó (200) o ya existía (409).
        """
        idx = payload["segment_index"]
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = requests.post(
                    f"{API_URL}/cameras/segments",
                    json=payload,
                    headers=HEADERS,
                    timeout=15,
                )
                if r.status_code == 409:
                    logger.warning(f"Segmento #{idx} ya registrado (409) — ignorado")
                    return True
                r.raise_for_status()
                logger.success(
                    f"Segmento #{idx} enviado — "
                    f"hash: {payload['sha256_hash'][:16]}..."
                )
                return True
            except Exception as exc:
                logger.warning(f"send_segment #{idx} intento {attempt}/{MAX_RETRIES}: {exc}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * attempt)
        return False

    def finish_video(self, video_id: str) -> None:
        """Marca el vídeo como completado."""
        try:
            r = requests.patch(
                f"{API_URL}/cameras/videos/{video_id}/finish",
                headers=HEADERS,
                timeout=10,
            )
            r.raise_for_status()
            logger.info(f"Vídeo {video_id} finalizado")
        except Exception as exc:
            logger.error(f"finish_video error: {exc}")

    def heartbeat(self) -> None:
        """Envía un ping al servidor para mantener el estado online."""
        try:
            r = requests.post(
                f"{API_URL}/cameras/heartbeat",
                headers=HEADERS,
                timeout=5,
            )
            r.raise_for_status()
            logger.debug("Heartbeat OK")
        except Exception as exc:
            logger.warning(f"Heartbeat fallido: {exc}")


# ── Generador de vídeo ──────────────────────────────────────────

class VideoGenerator:
    """
    Genera vídeo sintético con OpenCV.

    Cada frame contiene:
    - Fondo negro con rejilla sutil
    - Mira central animada
    - Timestamp UTC en tiempo real
    - Identificador de cámara y índice de segmento
    - Contador de frame
    - Indicador visual [TAMPERED] si TAMPER_MODE activo
    """

    def record_segment(
        self,
        out_path:      str,
        segment_index: int,
        start_epoch:   int,
    ) -> None:
        """
        Graba un segmento de SEGMENT_DURATION segundos en out_path (MP4).
        Bloquea hasta completar la grabación.
        """
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        writer = cv2.VideoWriter(out_path, fourcc, float(FPS), (WIDTH, HEIGHT))

        if not writer.isOpened():
            raise RuntimeError(f"VideoWriter no pudo abrir: {out_path}")

        total_frames = FPS * SEGMENT_DURATION
        t0 = time.time()

        for frame_n in range(total_frames):
            abs_sec = start_epoch + frame_n // FPS
            frame   = self._build_frame(frame_n, segment_index, abs_sec)
            writer.write(frame)

            # Sincronizar con tiempo real (best-effort)
            elapsed  = time.time() - t0
            expected = frame_n / FPS
            if expected > elapsed:
                time.sleep(expected - elapsed)

        writer.release()
        size_mb = os.path.getsize(out_path) / (1024 * 1024)
        logger.debug(f"Segmento {segment_index} escrito → {out_path} ({size_mb:.1f} MB)")

    def _build_frame(
        self,
        frame_n:       int,
        segment_index: int,
        abs_sec:       int,
    ) -> np.ndarray:
        frame = np.zeros((HEIGHT, WIDTH, 3), dtype=np.uint8)

        # Rejilla de fondo
        for y in range(0, HEIGHT, 60):
            cv2.line(frame, (0, y), (WIDTH, y), (8, 20, 8), 1)
        for x in range(0, WIDTH, 60):
            cv2.line(frame, (x, 0), (x, HEIGHT), (8, 20, 8), 1)

        # Mira central
        cx, cy = WIDTH // 2, HEIGHT // 2
        pulse  = int(abs((frame_n % (FPS * 2)) - FPS) * 1.5)   # 0..FPS*1.5
        color_mira = (0, min(80 + pulse, 255), 0)
        cv2.circle(frame, (cx, cy), 80, color_mira, 1)
        cv2.circle(frame, (cx, cy), 4, color_mira, -1)
        cv2.line(frame, (cx - 40, cy), (cx + 40, cy), color_mira, 1)
        cv2.line(frame, (cx, cy - 40), (cx, cy + 40), color_mira, 1)

        # Esquinas decorativas
        corner_len = 20
        corner_col = (0, 120, 0)
        for (ox, oy, sx, sy) in [
            (0,         0,          1,  1),
            (WIDTH - 1, 0,         -1,  1),
            (0,         HEIGHT - 1, 1, -1),
            (WIDTH - 1, HEIGHT - 1,-1, -1),
        ]:
            cv2.line(frame, (ox, oy), (ox + sx * corner_len, oy), corner_col, 1)
            cv2.line(frame, (ox, oy), (ox, oy + sy * corner_len), corner_col, 1)

        font     = cv2.FONT_HERSHEY_SIMPLEX
        now_str  = datetime.utcfromtimestamp(abs_sec).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Línea superior: nombre cámara
        cv2.putText(frame, f"EVIDETH — {CAMERA_ID}",
                    (20, 38), font, 0.85, (0, 200, 255), 1, cv2.LINE_AA)

        # Línea segunda: segmento + frame
        cv2.putText(frame,
                    f"SEG {segment_index:04d}  FRM {frame_n:06d}  "
                    f"[{WIDTH}x{HEIGHT} @ {FPS}fps]",
                    (20, 70), font, 0.55, (0, 140, 180), 1, cv2.LINE_AA)

        # Timestamp inferior izquierda
        cv2.putText(frame, now_str,
                    (20, HEIGHT - 18), font, 0.55, (0, 180, 80), 1, cv2.LINE_AA)

        # Criptografía inferior derecha
        cv2.putText(frame, "SHA-256 · ECDSA P-256 · EVIDETH",
                    (WIDTH - 360, HEIGHT - 18), font, 0.45, (40, 60, 40), 1, cv2.LINE_AA)

        # TAMPER MODE: aviso rojo visible en segmentos manipulados
        if TAMPER_MODE and segment_index % 3 == 0:
            cv2.rectangle(frame, (cx - 220, cy - 40), (cx + 220, cy + 50), (0, 0, 180), 2)
            cv2.putText(frame, "!! TAMPERED !!",
                        (cx - 175, cy + 15), font, 1.4, (0, 0, 255), 3, cv2.LINE_AA)

        return frame


# ── Daemon principal ───────────────────────────────────────────

class CameraSimulator:
    """
    Daemon principal del simulador.

    Hilos:
    - Principal : graba segmento → hash → firma → envía → repite
    - Heartbeat : POST /cameras/heartbeat cada HEARTBEAT_INTERVAL s
    - Retry     : reintenta segmentos fallidos cada 60 s
    """

    def __init__(self):
        self.api    = APIClient()
        self.crypto = CryptoService()
        self.gen    = VideoGenerator()
        self._failed: queue.Queue = queue.Queue()   # segmentos pendientes de reenviar
        self._stop  = threading.Event()

    def run(self) -> None:
        logger.info("="*60)
        logger.info(f"EVIDETH Camera Simulator arrancando")
        logger.info(f"  Cámara        : {CAMERA_ID}")
        logger.info(f"  Backend        : {API_URL}")
        logger.info(f"  Segmento       : {SEGMENT_DURATION}s @ {FPS}fps {WIDTH}x{HEIGHT}")
        logger.info(f"  Firma          : {SIGNING_MODE.upper()}")
        logger.info(f"  Tamper mode    : {'ACTIVADO ⚠' if TAMPER_MODE else 'desactivado'}")
        logger.info("="*60)

        # Hilos auxiliares
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        threading.Thread(target=self._retry_loop,     daemon=True, name="retry").start()

        segment_index = 0
        boot_epoch    = int(time.time())

        try:
            while not self._stop.is_set():
                self._process_segment(segment_index, boot_epoch)
                segment_index += 1
        except KeyboardInterrupt:
            logger.info("Simulador detenido por el usuario (Ctrl+C)")
        finally:
            self._stop.set()

    # ── Lógica de un segmento ────────────────────────────────────

    def _process_segment(self, idx: int, boot_epoch: int) -> None:
        ts    = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fname = f"{CAMERA_ID}_{ts}_seg{idx:04d}.mp4"

        # 1. Registrar inicio de vídeo
        video_id   = self.api.start_video(fname)
        start_secs = idx * SEGMENT_DURATION

        with tempfile.TemporaryDirectory(prefix="evideth_sim_") as tmp:
            seg_path = os.path.join(tmp, fname)

            # 2. Grabar segmento (bloquea SEGMENT_DURATION segundos)
            logger.info(f"--- Grabando segmento {idx} ---")
            self.gen.record_segment(seg_path, idx, boot_epoch + start_secs)

            # 3. TAMPER MODE: corromper bytes del fichero en segmentos 0, 3, 6...
            if TAMPER_MODE and idx % 3 == 0:
                self._tamper_file(seg_path)
                logger.warning(f"[TAMPER] Segmento {idx} corrompido (demo)")

            # 4. Hash SHA-256
            sha256    = sha256_file(seg_path)
            file_size = os.path.getsize(seg_path)

            # 5. Firma ECDSA P-256
            signature = self.crypto.sign(sha256)

            logger.info(
                f"Segmento {idx} listo — "
                f"hash: {sha256[:16]}... — "
                f"firma: {signature[:20]}... — "
                f"tamaño: {file_size // 1024} KB"
            )

            # 6. Payload para el servidor
            payload = {
                "video_id":        video_id,
                "segment_index":   idx,
                "start_time_secs": start_secs,
                "end_time_secs":   start_secs + SEGMENT_DURATION,
                "sha256_hash":     sha256,
                "ecdsa_signature": signature,
                "public_key_id":   self.crypto.public_key_id,
                "file_size_bytes": file_size,
            }

            # 7. Enviar al servidor (con reintentos internos)
            if not self.api.send_segment(payload):
                logger.error(f"Segmento {idx} encolado para reintento")
                self._failed.put(payload)

        # 8. Finalizar vídeo
        self.api.finish_video(video_id)

    # ── Tamper ────────────────────────────────────────────────

    @staticmethod
    def _tamper_file(path: str) -> None:
        """
        Invierte 128 bytes en el centro del fichero.
        Suficiente para alterar el hash SHA-256 y que el servidor
        marque el segmento como INVALID (demo de detección).
        """
        size = os.path.getsize(path)
        if size < 300:
            return
        mid = size // 2
        with open(path, "r+b") as f:
            f.seek(mid)
            original = f.read(128)
            f.seek(mid)
            f.write(bytes(b ^ 0xFF for b in original))

    # ── Hilos auxiliares ─────────────────────────────────────────

    def _heartbeat_loop(self) -> None:
        """Envía heartbeat cada HEARTBEAT_INTERVAL segundos."""
        while not self._stop.wait(timeout=HEARTBEAT_INTERVAL):
            self.api.heartbeat()

    def _retry_loop(self) -> None:
        """
        Reintenta los segmentos que fallaron al enviarse.
        Ejecuta cada 60 segundos. Los que siguen fallando
        vuelven a la cola para el siguiente ciclo.
        """
        while not self._stop.wait(timeout=60):
            if self._failed.empty():
                continue

            logger.info(f"Reintentando segmentos pendientes ({self._failed.qsize()} en cola)")
            pending = []
            while not self._failed.empty():
                try:
                    payload = self._failed.get_nowait()
                    if self.api.send_segment(payload):
                        logger.success(f"Reintento OK — segmento #{payload['segment_index']}")
                    else:
                        pending.append(payload)
                except queue.Empty:
                    break

            for p in pending:
                self._failed.put(p)


# ── Entry point ──────────────────────────────────────────────

if __name__ == "__main__":
    CameraSimulator().run()
