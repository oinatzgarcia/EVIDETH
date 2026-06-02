"""EVIDETH Client Video Server
Recibe segmentos de vídeo WebM desde el Live Viewer y los guarda en /videos.
Corre en puerto 5000 dentro del contenedor Docker del cliente.
"""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os, shutil

app = FastAPI(title="EVIDETH Video Saver", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

VIDEOS_ROOT = os.environ.get("VIDEOS_ROOT", "/videos")


@app.post("/save-segment")
async def save_segment(
    camera_id: str = Form(...),
    video_id:  str = Form(...),
    seg_index: int = Form(...),
    file: UploadFile = File(...),
):
    """Guarda un segmento WebM en /videos/<camera_id>/<video_id>/seg_NNN.webm"""
    # Validar que no hay path traversal
    if "/" in camera_id or ".." in camera_id or "/" in video_id or ".." in video_id:
        raise HTTPException(status_code=400, detail="Invalid camera_id or video_id")

    dest_dir = os.path.join(VIDEOS_ROOT, camera_id, video_id)
    os.makedirs(dest_dir, exist_ok=True)

    filename = f"seg_{str(seg_index).zfill(3)}.webm"
    dest_path = os.path.join(dest_dir, filename)

    with open(dest_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    size_kb = round(os.path.getsize(dest_path) / 1024, 1)
    return {
        "saved": True,
        "path": f"{camera_id}/{video_id}/{filename}",
        "size_kb": size_kb,
    }


@app.get("/health")
def health():
    return {"status": "ok", "videos_root": VIDEOS_ROOT}
