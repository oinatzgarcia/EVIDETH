import subprocess
import hashlib
import os
import json
from pathlib import Path
from typing import List, Dict, Tuple

from app.core.merkle import hash_bytes, get_merkle_root


SEGMENT_DURATION    = 30  # segundos por segmento principal
SUBSEGMENT_DURATION = 1   # segundos por sub-segmento (granularidad Merkle)


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


def compute_merkle_for_segment(
    video_path: str,
    segment_start: float,
    segment_duration: float,
    output_dir: str
) -> Tuple[List[Dict], str]:
    """
    Divide un segmento en sub-segmentos de 1s y construye el Merkle Tree.

    Args:
        video_path:       Ruta al video original.
        segment_start:    Segundo de inicio del segmento en el video.
        segment_duration: Duración del segmento en segundos (normalmente 30).
        output_dir:       Directorio temporal para los sub-segmentos.

    Returns:
        Tuple (leaf_hashes, merkle_root) donde:
        - leaf_hashes: lista de {leaf_index, hash} para cada sub-segmento de 1s
        - merkle_root: root del árbol de Merkle (se firmará con ECDSA)
    """
    n_subsegments = int(segment_duration)
    leaf_hashes = []

    for i in range(n_subsegments):
        sub_start = segment_start + i
        sub_path  = os.path.join(output_dir, f"sub_{i:04d}.mp4")

        cmd = [
            "ffmpeg", "-y",
            "-ss", str(sub_start),
            "-i",  video_path,
            "-t",  str(SUBSEGMENT_DURATION),
            "-c",  "copy",
            "-avoid_negative_ts", "1",
            sub_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"ffmpeg error en sub-segmento {i} (start={sub_start}s): {result.stderr}"
            )

        with open(sub_path, "rb") as f:
            leaf_hash = hash_bytes(f.read())

        leaf_hashes.append({"leaf_index": i, "hash": leaf_hash})
        os.remove(sub_path)

    merkle_root = get_merkle_root([lh["hash"] for lh in leaf_hashes])
    return leaf_hashes, merkle_root


def segment_video(video_path: str, output_dir: str) -> List[Dict]:
    """
    Divide el video en segmentos de 30s usando ffmpeg.
    Por cada segmento calcula:
      - SHA-256 del segmento completo (para compatibilidad)
      - Merkle root de sus sub-segmentos de 1s (para verificación granular)

    Returns:
        Lista de dicts con metadatos, sha256_hash, merkle_root y leaf_hashes.
    """
    duration = get_video_duration(video_path)
    segments = []
    segment_index = 0
    start = 0.0

    while start < duration:
        end          = min(start + SEGMENT_DURATION, duration)
        seg_duration = end - start
        is_complete  = seg_duration >= SEGMENT_DURATION

        output_path = os.path.join(output_dir, f"segment_{segment_index:04d}.mp4")

        # Extrae el segmento con ffmpeg (sin recodificar → hash consistente)
        cmd = [
            "ffmpeg", "-y",
            "-i",  video_path,
            "-ss", str(start),
            "-t",  str(seg_duration),
            "-c",  "copy",
            "-avoid_negative_ts", "1",
            output_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"ffmpeg error en segmento {segment_index}: {result.stderr}"
            )

        # Hash SHA-256 del segmento completo (compatibilidad con esquema existente)
        sha256_hash = calculate_sha256(output_path)
        file_size   = os.path.getsize(output_path)

        # Merkle Tree de sub-segmentos de 1s
        leaf_hashes, merkle_root = compute_merkle_for_segment(
            video_path, start, seg_duration, output_dir
        )

        segments.append({
            "segment_index":   segment_index,
            "start_time_secs": int(start),
            "end_time_secs":   int(end),
            "duration_secs":   int(seg_duration),
            "complete":        is_complete,
            "sha256_hash":     sha256_hash,   # Hash del segmento completo
            "merkle_root":     merkle_root,   # Root del Merkle Tree de 1s
            "leaf_hashes":     leaf_hashes,   # Lista de hashes de sub-segmentos
            "file_size_bytes": file_size,
            "file_path":       output_path,
        })

        segment_index += 1
        start = end

    return segments


def cleanup_segments(output_dir: str):
    """Elimina los archivos temporales de segmentos y sub-segmentos."""
    for f in Path(output_dir).glob("segment_*.mp4"):
        f.unlink()
    for f in Path(output_dir).glob("sub_*.mp4"):
        f.unlink()
