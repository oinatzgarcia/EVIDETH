"""EVIDETH Client Video Server
Recibe segmentos WebM desde el Live Viewer, los transcodifica a MP4 con ffmpeg
y los guarda en /videos. Puerto 5000 dentro del contenedor Docker del cliente.

Flujo:
  1. Recibe WebM (blob de MediaRecorder)
  2. Guarda .webm temporal
  3. ffmpeg: webm → mp4 (H.264 / AAC, faststart)
  4. Borra el .webm temporal
  5. Devuelve ruta y tamaño del .mp4

Nota sobre integridad forense:
  El SHA-256 lo calcula el navegador sobre el blob WebM ANTES de enviarlo.
  El .mp4 resultante es la copia de archivo; el hash que va al backend
  corresponde al WebM original (bytes que el navegador firmó).
"""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os, shutil, subprocess, tempfile

app = FastAPI(title="EVIDETH Video Saver", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

VIDEOS_ROOT = os.environ.get("VIDEOS_ROOT", "/videos")


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
            timeout=120,  # 2 min máximo por segmento
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@app.post("/save-segment")
async def save_segment(
    camera_id: str = Form(...),
    video_id:  str = Form(...),
    seg_index: int = Form(...),
    file: UploadFile = File(...),
):
    """Recibe un blob WebM, lo convierte a MP4 y lo guarda en
    /videos/<camera_id>/<video_id>/seg_NNN.mp4
    """
    # Validar path traversal
    for val in (camera_id, video_id):
        if "/" in val or ".." in val:
            raise HTTPException(status_code=400, detail="Invalid camera_id or video_id")

    dest_dir = os.path.join(VIDEOS_ROOT, camera_id, video_id)
    os.makedirs(dest_dir, exist_ok=True)

    seg_name = f"seg_{str(seg_index).zfill(3)}"
    webm_path = os.path.join(dest_dir, f"{seg_name}.webm")
    mp4_path  = os.path.join(dest_dir, f"{seg_name}.mp4")

    # 1. Guardar WebM recibido
    with open(webm_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # 2. Transcodificar a MP4
    ok = _transcode_to_mp4(webm_path, mp4_path)

    if ok and os.path.exists(mp4_path) and os.path.getsize(mp4_path) > 0:
        # Borrar el WebM temporal; solo conservamos el MP4
        os.remove(webm_path)
        final_path = mp4_path
        final_name = f"{seg_name}.mp4"
    else:
        # ffmpeg no disponible o falló → conservar WebM como fallback
        final_path = webm_path
        final_name = f"{seg_name}.webm"

    size_kb = round(os.path.getsize(final_path) / 1024, 1)
    return {
        "saved": True,
        "path": f"{camera_id}/{video_id}/{final_name}",
        "size_kb": size_kb,
        "format": "mp4" if final_name.endswith(".mp4") else "webm",
    }


@app.get("/health")
def health():
    # Comprobar si ffmpeg está disponible
    try:
        r = subprocess.run(["ffmpeg", "-version"], capture_output=True, timeout=5)
        ffmpeg_ok = r.returncode == 0
    except Exception:
        ffmpeg_ok = False
    return {"status": "ok", "videos_root": VIDEOS_ROOT, "ffmpeg": ffmpeg_ok}
