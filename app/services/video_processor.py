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
    Extrae el hash SHA-256 de cada chunk de 1 segundo dentro de un segmento.

    Usa exactamente los mismos parámetros ffmpeg que el simulador para
    garantizar hashes idénticos sobre el mismo fichero.
    """
    hashes: List[str] = []

    with tempfile.TemporaryDirectory(prefix="evideth_sec_") as tmp:
        for sec in range(duration_secs):
            out = os.path.join(tmp, f"sec_{sec:04d}.mp4")
            cmd = [
                "ffmpeg", "-y",
                "-i", segment_path,
                "-ss", str(sec),
                "-t", "1",
                "-c", "copy",
                "-avoid_negative_ts", "1",
                out
            ]
            r = subprocess.run(cmd, capture_output=True)
            if r.returncode != 0 or not os.path.exists(out) or os.path.getsize(out) == 0:
                hashes.append(_EMPTY_HASH)
            else:
                hashes.append(calculate_sha256(out))

    return hashes


def segment_video(video_path: str, output_dir: str) -> List[Dict]:
    """
    Divide el video en segmentos lógicos de SEGMENT_DURATION segundos.

    IMPORTANTE — consistencia de hashes:
      El simulador guarda el fichero MP4 generado por OpenCV y calcula
      sha256 + second_hashes directamente sobre ese fichero.
      Si el verificador re-extrae el mismo contenido con ffmpeg (-c copy),
      los headers del contenedor MP4 cambian → bytes distintos → hashes distintos.

      Por tanto:
        - Si el vídeo subido cabe en un único segmento (duración ≤ SEGMENT_DURATION),
          se hashea y se extraen los segundos DIRECTAMENTE del fichero original.
        - Solo se re-extrae con ffmpeg cuando hay múltiples segmentos (el vídeo
          fue concatenado y hay que trocearlo).
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
            # ── Video de un único segmento: trabajar con el fichero original ──────
            # El simulador hashea este mismo fichero sin pasar por ffmpeg,
            # por lo que los hashes son directamente comparables.
            work_path = video_path
            sha256_hash = calculate_sha256(work_path)
            file_size   = os.path.getsize(work_path)
        else:
            # ── Video multi-segmento: extraer la porción con ffmpeg ──────────────
            # Aquí sí es necesario trocear; ambos lados (grabación y verificación)
            # pasarían por ffmpeg por lo que el comportamiento es simétrico.
            work_path = os.path.join(output_dir, f"segment_{segment_index:04d}.mp4")
            cmd = [
                "ffmpeg", "-y",
                "-i", video_path,
                "-ss", str(start),
                "-t", str(seg_duration),
                "-c", "copy",
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

        # Nivel 2: hashes por segundo + Merkle root (sobre work_path en ambos casos)
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
