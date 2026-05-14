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

# Timeouts por operación ffmpeg
_TIMEOUT_DURATION  = 30   # ffprobe duración
_TIMEOUT_SEGMENT   = 120  # cortar segmento
_TIMEOUT_SECOND    = 10   # hash de un segundo individual (fallback)
_TIMEOUT_THUMBNAIL = 8    # extraer frame JPEG


def get_video_duration(video_path: str) -> float:
    """
    Obtiene la duración del vídeo en segundos usando ffprobe.
    Robusto para .webm de MediaRecorder que no tienen 'duration' en la cabecera.
    """
    cmd = [
        "ffprobe", "-v", "quiet",
        "-print_format", "json",
        "-show_format",
        "-show_streams",
        video_path
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT_DURATION)
    except subprocess.TimeoutExpired:
        return float(SEGMENT_DURATION)

    if result.returncode != 0:
        raise RuntimeError(f"ffprobe error: {result.stderr}")

    data = json.loads(result.stdout)

    # 1. format.duration
    fmt_duration = data.get("format", {}).get("duration")
    if fmt_duration is not None:
        try:
            val = float(fmt_duration)
            if val > 0:
                return val
        except (ValueError, TypeError):
            pass

    # 2. streams[x].duration
    for stream in data.get("streams", []):
        stream_duration = stream.get("duration")
        if stream_duration is not None:
            try:
                val = float(stream_duration)
                if val > 0:
                    return val
            except (ValueError, TypeError):
                pass

    # 3. nb_frames / fps
    for stream in data.get("streams", []):
        nb_frames    = stream.get("nb_frames")
        r_frame_rate = stream.get("r_frame_rate", "")
        if nb_frames and r_frame_rate and "/" in str(r_frame_rate):
            try:
                num, den = r_frame_rate.split("/")
                fps = float(num) / float(den)
                if fps > 0:
                    duration = int(nb_frames) / fps
                    if duration > 0:
                        return duration
            except (ValueError, ZeroDivisionError):
                pass

    # 4. Fallback seguro
    return float(SEGMENT_DURATION)


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

    Estategia: decodifica TODO el segmento de una vez con ffmpeg -f segment
    en lugar de N llamadas secuenciales — mucho más rápido y sin riesgo
    de bloqueo. Cada chunk de rawvideo de 1 segundo (~WxHx3 bytes) se
    hashea por separado.

    Si el modo batch falla (webm mal formado) hace fallback por segundo
    con timeout individual de {_TIMEOUT_SECOND}s.
    """
    if duration_secs <= 0:
        return []

    # ── Modo batch: un solo ffmpeg que vuelca todos los frames ──────────
    # Detectar resolución para calcular tamaño de frame
    try:
        probe_cmd = [
            "ffprobe", "-v", "quiet",
            "-select_streams", "v:0",
            "-show_entries", "stream=width,height",
            "-print_format", "json",
            segment_path
        ]
        probe = subprocess.run(probe_cmd, capture_output=True, text=True, timeout=10)
        probe_data = json.loads(probe.stdout)
        streams = probe_data.get("streams", [])
        if streams:
            width  = int(streams[0].get("width",  0))
            height = int(streams[0].get("height", 0))
        else:
            width = height = 0
    except Exception:
        width = height = 0

    if width > 0 and height > 0:
        frame_bytes = width * height * 3  # rgb24
        batch_timeout = duration_secs * 3 + 30  # margen generoso
        cmd = [
            "ffmpeg", "-y",
            "-i", segment_path,
            "-f", "rawvideo",
            "-pix_fmt", "rgb24",
            "-r", "1",          # un frame por segundo
            "pipe:1",
        ]
        try:
            r = subprocess.run(
                cmd, capture_output=True,
                timeout=batch_timeout,
            )
            raw = r.stdout
            # Trocear en frames de exactamente frame_bytes
            if raw and len(raw) >= frame_bytes:
                hashes = []
                for i in range(duration_secs):
                    chunk = raw[i * frame_bytes: (i + 1) * frame_bytes]
                    if len(chunk) == frame_bytes:
                        hashes.append(hashlib.sha256(chunk).hexdigest())
                    else:
                        hashes.append(_EMPTY_HASH)
                # Rellenar si ffmpeg entregó menos frames de los esperados
                while len(hashes) < duration_secs:
                    hashes.append(_EMPTY_HASH)
                return hashes
        except subprocess.TimeoutExpired:
            pass  # cae al fallback por segundo
        except Exception:
            pass

    # ── Fallback: N llamadas con timeout individual ──────────────────────
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
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=_TIMEOUT_SECOND)
            if r.returncode != 0 or not r.stdout:
                hashes.append(_EMPTY_HASH)
            else:
                hashes.append(hashlib.sha256(r.stdout).hexdigest())
        except subprocess.TimeoutExpired:
            hashes.append(_EMPTY_HASH)
        except Exception:
            hashes.append(_EMPTY_HASH)

    return hashes


def extract_frame_thumbnail(video_path: str, second: int, quality: int = 5) -> Optional[str]:
    """
    Extrae un frame JPEG del centro del segundo indicado.
    Devuelve la imagen codificada en base64, o None si falla.
    """
    cmd = [
        "ffmpeg", "-y",
        "-i",       video_path,
        "-ss",      f"{second}.5",
        "-vframes", "1",
        "-f",       "image2",
        "-vcodec",  "mjpeg",
        "-q:v",     str(quality),
        "pipe:1",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=_TIMEOUT_THUMBNAIL)
        if r.returncode != 0 or not r.stdout:
            return None
        return base64.b64encode(r.stdout).decode()
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


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
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=_TIMEOUT_SEGMENT,
                )
            except subprocess.TimeoutExpired:
                raise RuntimeError(
                    f"ffmpeg timeout al cortar segmento {segment_index}"
                )
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
