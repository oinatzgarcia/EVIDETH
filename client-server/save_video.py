"""EVIDETH Client Video Server
Recibe segmentos WebM desde el Live Viewer, los transcodifica a MP4 con ffmpeg
y los guarda en /videos. Puerto 5000 dentro del contenedor Docker del cliente.

Flujo:
  1. Recibe WebM (blob de MediaRecorder)
  2. Guarda .webm temporal
  3. ffmpeg: webm → mp4 (H.264 / AAC, faststart)
  4. Borra el .webm temporal
  5. Calcula SHA-256 del fichero archivado final (MP4 o WebM fallback)
  6. Calcula second_hashes (SHA-256 de frames RGB por segundo) + merkle_root
  7. Devuelve sha256, merkle_root, second_hashes, duration_secs

Nota sobre integridad forense:
  El hash que se devuelve al viewer es SIEMPRE el SHA-256 del fichero
  que queda guardado en disco (MP4 tras transcodificación, o WebM si
  ffmpeg falla). El viewer DEBE usar este hash —no el del blob WebM
  original— al registrar el segmento en el backend, de forma que el
  hash en BD coincida con el fichero que el analista subirá para verificar.

  Lo mismo aplica a merkle_root y second_hashes: se calculan sobre el
  fichero archivado final para que coincidan exactamente con los que
  recalculará verifier.py al procesar el mismo contenido de video.
"""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import hashlib
import os
import shutil
import subprocess
import json
from typing import List, Optional

app = FastAPI(title="EVIDETH Video Saver", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

VIDEOS_ROOT = os.environ.get("VIDEOS_ROOT", "/videos")
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def _transcode_to_mp4(webm_path: str, mp4_path: str) -> bool:
    """
    Transcodifica webm_path → mp4_path usando ffmpeg.
    -c:v libx264  -crf 23  -preset fast  -movflags +faststart
    Devuelve True si OK, False si ffmpeg no está disponible o falla.
    """
    cmd = [
        "ffmpeg", "-y",
        "-i", webm_path,
        "-c:v", "libx264",
        "-crf", "23",
        "-preset", "fast",
        "-c:a", "aac",
        "-movflags", "+faststart",
        mp4_path,
    ]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _sha256_file(path: str) -> str:
    """Calcula el SHA-256 del fichero en path de forma eficiente (chunks de 64 KB)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_duration_secs(path: str) -> int:
    """Duración del fichero en segundos enteros via ffprobe. Devuelve 0 si falla."""
    cmd = [
        "ffprobe", "-v", "quiet",
        "-print_format", "json",
        "-show_format",
        path,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            return max(int(float(data["format"]["duration"])), 1)
    except Exception:
        pass
    return 0


def _extract_second_hashes(path: str, duration_secs: int) -> List[str]:
    """
    Hash SHA-256 de los frames RGB decodificados de cada segundo.

    Mismo algoritmo que app/services/video_processor.py:
      ffmpeg -ss <sec> -t 1 -f rawvideo -pix_fmt rgb24 pipe:1

    Hashing pixels puros (no bytes de contenedor) garantiza que el
    resultado sea idéntico independientemente del formato del fichero
    (MP4 vs WebM) o de la versión de ffmpeg.
    """
    hashes: List[str] = []
    effective = max(duration_secs, 1)
    for sec in range(effective):
        cmd = [
            "ffmpeg", "-i", path,
            "-ss", str(sec),
            "-t", "1",
            "-f", "rawvideo",
            "-pix_fmt", "rgb24",
            "pipe:1",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=30)
            if r.returncode == 0 and r.stdout:
                hashes.append(hashlib.sha256(r.stdout).hexdigest())
            else:
                hashes.append(_EMPTY_HASH)
        except Exception:
            hashes.append(_EMPTY_HASH)
    return hashes


def _build_merkle_root(hashes: List[str]) -> Optional[str]:
    """
    Árbol Merkle binario sobre la lista de hashes hex.
    Mismo algoritmo que app/utils/merkle.py.
    Devuelve None si la lista está vacía.
    """
    if not hashes:
        return None
    layer = hashes[:]
    while len(layer) > 1:
        if len(layer) % 2 != 0:
            layer.append(layer[-1])  # duplicar el último nodo si número impar
        next_layer = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i + 1]
            next_layer.append(hashlib.sha256(combined.encode()).hexdigest())
        layer = next_layer
    return layer[0]


@app.post("/save-segment")
async def save_segment(
    camera_id: str = Form(...),
    video_id:  str = Form(...),
    seg_index: int = Form(...),
    file: UploadFile = File(...),
):
    """Recibe un blob WebM, lo convierte a MP4 y lo guarda en
    /videos/<camera_id>/<video_id>/seg_NNN.mp4

    Retorna:
      sha256       — SHA-256 del fichero archivado final (MP4 o WebM fallback)
      merkle_root  — Raíz del árbol Merkle de hashes por segundo (o null)
      second_hashes — Lista de SHA-256 por segundo (lista vacía si falla)
      duration_secs — Duración en segundos enteros

    El viewer DEBE reenviar merkle_root y second_hashes al backend para
    que la verificación L2 (Merkle) funcione. Sin estos datos el verificador
    solo puede usar L1 (hash de fichero), que falla siempre porque ffmpeg
    regenera el contenedor MP4 con metadata diferente al re-segmentar.
    """
    for val in (camera_id, video_id):
        if "/" in val or ".." in val:
            raise HTTPException(status_code=400, detail="Invalid camera_id or video_id")

    dest_dir = os.path.join(VIDEOS_ROOT, camera_id, video_id)
    os.makedirs(dest_dir, exist_ok=True)

    seg_name = f"seg_{str(seg_index).zfill(3)}"
    webm_path = os.path.join(dest_dir, f"{seg_name}.webm")
    mp4_path  = os.path.join(dest_dir, f"{seg_name}.mp4")

    with open(webm_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    ok = _transcode_to_mp4(webm_path, mp4_path)

    if ok and os.path.exists(mp4_path) and os.path.getsize(mp4_path) > 0:
        os.remove(webm_path)
        final_path = mp4_path
        final_name = f"{seg_name}.mp4"
    else:
        final_path = webm_path
        final_name = f"{seg_name}.webm"

    # ── Criptografía sobre el fichero archivado final ──────────────────────
    # Todos los hashes se calculan sobre final_path (el fichero en disco).
    # El analista subirá exactamente este fichero para verificar → coincidencia garantizada.

    sha256 = _sha256_file(final_path)

    duration_secs = _get_duration_secs(final_path)
    second_hashes: List[str] = []
    merkle_root: Optional[str] = None

    if duration_secs > 0:
        try:
            second_hashes = _extract_second_hashes(final_path, duration_secs)
            merkle_root = _build_merkle_root(second_hashes)
        except Exception:
            # No bloquear el guardado si falla la criptografía L2
            second_hashes = []
            merkle_root = None

    size_kb = round(os.path.getsize(final_path) / 1024, 1)
    return {
        "saved": True,
        "path": f"{camera_id}/{video_id}/{final_name}",
        "size_kb": size_kb,
        "format": "mp4" if final_name.endswith(".mp4") else "webm",
        "sha256": sha256,
        "merkle_root": merkle_root,
        "second_hashes": second_hashes,
        "duration_secs": duration_secs,
    }


@app.get("/health")
def health():
    try:
        r = subprocess.run(["ffmpeg", "-version"], capture_output=True, timeout=5)
        ffmpeg_ok = r.returncode == 0
    except Exception:
        ffmpeg_ok = False
    return {"status": "ok", "videos_root": VIDEOS_ROOT, "ffmpeg": ffmpeg_ok}
