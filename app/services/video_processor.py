import base64
import subprocess
import hashlib
import math
import os
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Optional

from app.utils.merkle import build_merkle_root


SEGMENT_DURATION = 30  # segundos
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def get_video_duration(video_path: str) -> float:
    """Obtiene la duración del video en segundos usando ffprobe."""
    cmd = [
        "ffprobe", "-v", "quiet",
        "-print_format", "json",
        "-show_format",
        video_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"ffprobe error: {result.stderr}")
    data = json.loads(result.stdout)
    return float(data["format"]["duration"])


def calculate_sha256(file_path: str) -> str:
    """Calcula el hash SHA-256 de un archivo binario."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def extract_second_hashes(segment_path: str, duration_secs: int) -> List[str]:
    """
    Hash SHA-256 de los frames RGB decodificados de cada segundo.

    Usa ffmpeg -f rawvideo -pix_fmt rgb24 para obtener los pixels puros,
    eliminando diferencias de contenedor entre plataformas/versiones ffmpeg.
    """
    hashes: List[str] = []

    for sec in range(duration_secs):
        cmd = [
            "ffmpeg",
            "-i",       segment_path,
            "-ss",      str(sec),
            "-t",       "1",
            "-f",       "rawvideo",
            "-pix_fmt", "rgb24",
            "pipe:1",
        ]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0 or not r.stdout:
            hashes.append(_EMPTY_HASH)
        else:
            hashes.append(hashlib.sha256(r.stdout).hexdigest())

    return hashes


def extract_frame_thumbnail(video_path: str, second: int, quality: int = 5) -> Optional[str]:
    """
    Extrae un frame JPEG del centro del segundo indicado.
    Devuelve la imagen codificada en base64, o None si falla.

    Args:
        video_path: Ruta al fichero de vídeo.
        second:     Segundo del que extraer el frame (0-indexed).
        quality:    Calidad JPEG ffmpeg (1=mejor, 31=peor). 5 da ~20-40 KB
                    por frame a resolución 1280x720.

    Returns:
        String base64 del JPEG, o None si ffmpeg no puede extraer el frame.
    """
    cmd = [
        "ffmpeg", "-y",
        "-i",       video_path,
        "-ss",      f"{second}.5",   # centro del segundo
        "-vframes", "1",
        "-f",       "image2",
        "-vcodec",  "mjpeg",
        "-q:v",     str(quality),
        "pipe:1",
    ]
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode != 0 or not r.stdout:
        return None
    return base64.b64encode(r.stdout).decode()


def segment_video(video_path: str, output_dir: str) -> List[Dict]:
    """
    Divide el video en segmentos lógicos de SEGMENT_DURATION segundos.

    Para videos de un único segmento (duración <= SEGMENT_DURATION),
    se hashea el fichero original directamente sin re-extraerlo con ffmpeg.
    """
    duration = get_video_duration(video_path)
    total_logical_segments = math.ceil(duration / SEGMENT_DURATION)
    segments = []
    segment_index = 0
    start = 0.0

    while start < duration:
        end          = min(start + SEGMENT_DURATION, duration)
        seg_duration = end - start
        is_complete  = seg_duration >= SEGMENT_DURATION

        if total_logical_segments == 1:
            work_path   = video_path
            sha256_hash = calculate_sha256(work_path)
            file_size   = os.path.getsize(work_path)
        else:
            work_path = os.path.join(output_dir, f"segment_{segment_index:04d}.mp4")
            cmd = [
                "ffmpeg", "-y",
                "-i",    video_path,
                "-ss",   str(start),
                "-t",    str(seg_duration),
                "-c",    "copy",
                "-avoid_negative_ts", "1",
                work_path
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(
                    f"ffmpeg error en segmento {segment_index}: {result.stderr}"
                )
            sha256_hash = calculate_sha256(work_path)
            file_size   = os.path.getsize(work_path)

        second_hashes = extract_second_hashes(work_path, int(seg_duration))
        merkle_root   = build_merkle_root(second_hashes)

        segments.append({
            "segment_index":   segment_index,
            "start_time_secs": int(start),
            "end_time_secs":   int(end),
            "duration_secs":   int(seg_duration),
            "complete":        is_complete,
            "sha256_hash":     sha256_hash,
            "second_hashes":   second_hashes,
            "merkle_root":     merkle_root,
            "file_size_bytes": file_size,
            "file_path":       work_path,
        })

        segment_index += 1
        start = end

    return segments


def cleanup_segments(output_dir: str):
    """Elimina los archivos temporales de segmentos."""
    for f in Path(output_dir).glob("segment_*.mp4"):
        f.unlink()
