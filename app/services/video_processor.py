import subprocess
import hashlib
import math
import os
import json
import tempfile
from pathlib import Path
from typing import List, Dict

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

    En lugar de hashear ficheros MP4 de 1s (cuyos bytes de contenedor
    varian entre versiones/plataformas de ffmpeg), se extraen los pixels
    crudos RGB24 via stdout. El contenido decodificado es identico
    en cualquier plataforma para el mismo fichero de entrada.

    Este metodo es el mismo que usa el simulador, garantizando que
    los hashes son comparables independientemente del SO o version ffmpeg.
    """
    hashes: List[str] = []

    for sec in range(duration_secs):
        cmd = [
            "ffmpeg",
            "-i",      segment_path,
            "-ss",     str(sec),
            "-t",      "1",
            "-f",      "rawvideo",   # pixeles crudos, sin contenedor
            "-pix_fmt", "rgb24",    # formato de pixel canonico
            "pipe:1",               # volcar por stdout
        ]
        r = subprocess.run(cmd, capture_output=True)
        if r.returncode != 0 or not r.stdout:
            hashes.append(_EMPTY_HASH)
        else:
            hashes.append(hashlib.sha256(r.stdout).hexdigest())

    return hashes


def segment_video(video_path: str, output_dir: str) -> List[Dict]:
    """
    Divide el video en segmentos logicos de SEGMENT_DURATION segundos.

    Para videos de un unico segmento (duracion <= SEGMENT_DURATION),
    se hashea el fichero original directamente sin re-extraerlo con ffmpeg,
    garantizando que el sha256 (Nivel 1) sea identico al almacenado
    por el simulador.
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
            # Video de un unico segmento: usar el fichero original sin re-extraer.
            # El simulador hashea este mismo fichero directamente, por lo que
            # el sha256 es comparable.
            work_path   = video_path
            sha256_hash = calculate_sha256(work_path)
            file_size   = os.path.getsize(work_path)
        else:
            # Multi-segmento: extraer la porcion con ffmpeg.
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

        # Nivel 2: raw-frame hashes + Merkle root
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
