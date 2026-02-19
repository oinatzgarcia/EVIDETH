import subprocess
import hashlib
import os
import json
import tempfile
from pathlib import Path
from typing import List, Dict


SEGMENT_DURATION = 30  # segundos


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


def segment_video(video_path: str, output_dir: str) -> List[Dict]:
    """
    Divide el video en segmentos de 30s usando ffmpeg.
    Devuelve lista de segmentos con sus metadatos y hashes SHA-256.
    """
    duration = get_video_duration(video_path)
    segments = []
    segment_index = 0
    start = 0.0

    while start < duration:
        end = min(start + SEGMENT_DURATION, duration)
        seg_duration = end - start
        is_complete = seg_duration >= SEGMENT_DURATION

        output_path = os.path.join(output_dir, f"segment_{segment_index:04d}.mp4")

        # Extrae el segmento con ffmpeg (copia sin recodificar → más rápido)
        cmd = [
            "ffmpeg", "-y",
            "-i", video_path,
            "-ss", str(start),
            "-t", str(seg_duration),
            "-c", "copy",           # Sin recodificar → hash consistente
            "-avoid_negative_ts", "1",
            output_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ffmpeg error en segmento {segment_index}: {result.stderr}")

        # Calcula SHA-256 del segmento
        sha256_hash = calculate_sha256(output_path)
        file_size = os.path.getsize(output_path)

        segments.append({
            "segment_index":   segment_index,
            "start_time_secs": int(start),
            "end_time_secs":   int(end),
            "duration_secs":   int(seg_duration),
            "complete":        is_complete,
            "sha256_hash":     sha256_hash,
            "file_size_bytes": file_size,
            "file_path":       output_path,
        })

        segment_index += 1
        start = end

    return segments


def cleanup_segments(output_dir: str):
    """Elimina los archivos temporales de segmentos."""
    for f in Path(output_dir).glob("segment_*.mp4"):
        f.unlink()
