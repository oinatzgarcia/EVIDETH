import subprocess
import hashlib
import os
import json
import tempfile
from pathlib import Path
from typing import List, Dict

from app.utils.merkle import build_merkle_root


SEGMENT_DURATION = 30  # segundos
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()  # Centinela para segundos no extraíbles


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

    Granularidad fina equivalente a las hojas del árbol Merkle: permite
    identificar exactamente qué segundo fue manipulado, sin necesidad de
    retransmitir el segmento completo (análogo a SPV de Bitcoin).

    Args:
        segment_path:  Ruta al fichero de segmento (.mp4).
        duration_secs: Duración del segmento en segundos (normalmente 30).

    Returns:
        Lista de ``duration_secs`` hashes SHA-256 en hex.
        Si un segundo no se puede extraer, se usa SHA-256(b"") como centinela.
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
    Divide el video en segmentos de 30 s usando ffmpeg.

    Para cada segmento calcula dos niveles criptográficos:
      - **Nivel 1** ``sha256_hash``:  SHA-256 del fichero de segmento completo.
      - **Nivel 2** ``second_hashes`` + ``merkle_root``:
            SHA-256 de cada chunk de 1 s → raíz del árbol Merkle.

    Devuelve lista de segmentos con sus metadatos y datos criptográficos.
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

        # Extrae el segmento con ffmpeg (copia sin recodificar → hash consistente)
        cmd = [
            "ffmpeg", "-y",
            "-i", video_path,
            "-ss", str(start),
            "-t", str(seg_duration),
            "-c", "copy",
            "-avoid_negative_ts", "1",
            output_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"ffmpeg error en segmento {segment_index}: {result.stderr}")

        # Nivel 1: hash del segmento completo
        sha256_hash = calculate_sha256(output_path)
        file_size   = os.path.getsize(output_path)

        # Nivel 2: hashes por segundo + Merkle root
        second_hashes = extract_second_hashes(output_path, int(seg_duration))
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
            "file_path":       output_path,
        })

        segment_index += 1
        start = end

    return segments


def cleanup_segments(output_dir: str):
    """Elimina los archivos temporales de segmentos."""
    for f in Path(output_dir).glob("segment_*.mp4"):
        f.unlink()
