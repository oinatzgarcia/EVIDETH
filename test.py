"""
test_verification.py
Script de prueba automática del flujo completo de EVIDETH.
Ejecutar desde la raíz del proyecto: python test_verification.py
"""

import subprocess
import hashlib
import requests
import os
import json

# ── Configuración ─────────────────────────────────────────────
BASE_URL    = "http://127.0.0.1:8000/api/v1"
ADMIN_EMAIL = "admin@evideth.com"
ADMIN_PASS  = "Admin1234"
CAMERA_ID   = "CAM-AUTO-TEST"
VIDEO_FILE  = "test_video.mp4"
SEGMENT_DURATION = 30


# ── Helpers ───────────────────────────────────────────────────

def calculate_sha256(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def print_step(n: int, text: str):
    print(f"\n{'='*50}")
    print(f"  PASO {n}: {text}")
    print(f"{'='*50}")


def print_ok(text: str):
    print(f"  ✅ {text}")


def print_fail(text: str):
    print(f"  ❌ {text}")


def print_info(text: str):
    print(f"  ℹ️  {text}")


# ── Paso 1: Genera video sintético de 65s ─────────────────────

def generate_test_video():
    print_step(1, "Generando video de prueba con ffmpeg (65s)")
    cmd = [
        "ffmpeg", "-y",
        "-f", "lavfi",
        "-i", "color=c=blue:size=1280x720:rate=25",
        "-t", "65",
        VIDEO_FILE
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print_fail(f"Error ffmpeg: {result.stderr}")
        exit(1)
    print_ok(f"Video generado: {VIDEO_FILE} ({os.path.getsize(VIDEO_FILE) // 1024} KB)")


# ── Paso 2: Segmenta y calcula hashes ─────────────────────────

def segment_and_hash() -> list:
    print_step(2, "Segmentando video y calculando hashes SHA-256")

    # Obtiene duración
    cmd = ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", VIDEO_FILE]
    result = subprocess.run(cmd, capture_output=True, text=True)
    duration = float(json.loads(result.stdout)["format"]["duration"])
    print_info(f"Duración del video: {duration:.2f} segundos")

    segments = []
    start = 0.0
    index = 0

    while start < duration:
        end = min(start + SEGMENT_DURATION, duration)
        seg_file = f"seg_{index:04d}.mp4"

        cmd = [
            "ffmpeg", "-y",
            "-i", VIDEO_FILE,
            "-ss", str(start),
            "-t", str(end - start),
            "-c", "copy",
            "-avoid_negative_ts", "1",
            seg_file
        ]
        subprocess.run(cmd, capture_output=True)

        sha256 = calculate_sha256(seg_file)
        segments.append({
            "segment_index":   index,
            "start_time_secs": int(start),
            "end_time_secs":   int(end),
            "sha256_hash":     sha256,
            "file_size_bytes": os.path.getsize(seg_file),
            "complete":        (end - start) >= SEGMENT_DURATION
        })

        print_ok(f"Segmento {index}: [{int(start)}s - {int(end)}s] hash={sha256[:16]}...")
        os.remove(seg_file)   # Limpia segmento temporal
        start = end
        index += 1

    return segments


# ── Paso 3: Login ─────────────────────────────────────────────

def login() -> str:
    print_step(3, "Login como Admin")
    r = requests.post(f"{BASE_URL}/auth/login", json={
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASS
    })
    if r.status_code != 200:
        print_fail(f"Login fallido: {r.text}")
        exit(1)
    token = r.json()["access_token"]
    print_ok(f"JWT obtenido: {token[:30]}...")
    return token


# ── Paso 4: Registra cámara ───────────────────────────────────

def register_camera(token: str) -> str:
    print_step(4, f"Registrando cámara {CAMERA_ID}")
    headers = {"Authorization": f"Bearer {token}"}

    # Comprueba si ya existe
    r = requests.get(f"{BASE_URL}/cameras/", headers=headers)
    cameras = r.json() if r.status_code == 200 else []
    if any(c["camera_id"] == CAMERA_ID for c in cameras):
        print_info("Cámara ya existe, usando la existente.")
        print_info("⚠️  No se puede recuperar la API Key — borra la cámara en BD y repite.")
        exit(1)

    r = requests.post(f"{BASE_URL}/cameras/", headers=headers, json={
        "camera_id":   CAMERA_ID,
        "name":        "Cámara Test Automático",
        "location":    "Test Suite"
    })
    if r.status_code != 201:
        print_fail(f"Error registrando cámara: {r.text}")
        exit(1)

    api_key = r.json()["api_key"]
    print_ok(f"Cámara registrada. API Key: {api_key[:20]}...")
    return api_key


# ── Paso 5: Inicia video ──────────────────────────────────────

def start_video(api_key: str) -> str:
    print_step(5, "Iniciando grabación de video en BD")
    headers = {"X-API-Key": api_key}
    r = requests.post(f"{BASE_URL}/cameras/videos", headers=headers, json={
        "filename":   VIDEO_FILE,
        "fps":        25.0,
        "resolution": "1280x720",
        "codec":      "H264"
    })
    if r.status_code != 201:
        print_fail(f"Error iniciando video: {r.text}")
        exit(1)
    video_id = r.json()["id"]
    print_ok(f"Video creado en BD. ID: {video_id}")
    return video_id


# ── Paso 6: Envía segmentos ───────────────────────────────────

def upload_segments(api_key: str, video_id: str, segments: list):
    print_step(6, f"Enviando {len(segments)} segmentos al backend")
    headers = {"X-API-Key": api_key}

    for seg in segments:
        r = requests.post(f"{BASE_URL}/cameras/segments", headers=headers, json={
            "video_id":        video_id,
            "segment_index":   seg["segment_index"],
            "start_time_secs": seg["start_time_secs"],
            "end_time_secs":   seg["end_time_secs"],
            "sha256_hash":     seg["sha256_hash"],
            "file_size_bytes": seg["file_size_bytes"]
        })
        if r.status_code != 201:
            print_fail(f"Error en segmento {seg['segment_index']}: {r.text}")
            exit(1)
        print_ok(f"Segmento {seg['segment_index']} enviado y almacenado")


# ── Paso 7: Finaliza video ────────────────────────────────────

def finish_video(api_key: str, video_id: str):
    print_step(7, "Finalizando grabación")
    headers = {"X-API-Key": api_key}
    r = requests.patch(f"{BASE_URL}/cameras/videos/{video_id}/finish", headers=headers)
    if r.status_code != 200:
        print_fail(f"Error finalizando video: {r.text}")
        exit(1)
    print_ok(f"Video marcado como COMPLETED")


# ── Paso 8: Verifica integridad ───────────────────────────────

def verify_video(token: str, video_id: str):
    print_step(8, "Verificando integridad del video")
    headers = {"Authorization": f"Bearer {token}"}

    with open(VIDEO_FILE, "rb") as f:
        r = requests.post(
            f"{BASE_URL}/verification/upload",
            headers=headers,
            files={"video": (VIDEO_FILE, f, "video/mp4")},
            data={
                "camera_id":   CAMERA_ID,
                "video_db_id": video_id
            }
        )

    if r.status_code != 200:
        print_fail(f"Error en verificación: {r.text}")
        exit(1)

    report = r.json()
    print_ok(f"Verificación completada")
    print_info(f"Veredicto: {report['verdict']}")
    print_info(f"Integridad OK: {report['integrity_ok']}")
    print_info(f"Resumen: {report['summary']}")

    print(f"\n{'='*50}")
    print("  DETALLE POR SEGMENTO:")
    print(f"{'='*50}")
    for seg in report["segments"]:
        icon = "✅" if seg["result"] == "pass" else "❌"
        print(f"  {icon} Seg {seg['segment_index']:02d} | {seg['result'].upper()} | hash_match={seg['hash_match']}")

    print(f"\n{'='*50}")
    if report["integrity_ok"]:
        print("  🎉 RESULTADO FINAL: VIDEO ÍNTEGRO")
    else:
        print("  🚨 RESULTADO FINAL: MANIPULACIÓN DETECTADA")
    print(f"{'='*50}\n")


# ── Limpieza ──────────────────────────────────────────────────

def cleanup():
    if os.path.exists(VIDEO_FILE):
        os.remove(VIDEO_FILE)
        print_info(f"Archivo {VIDEO_FILE} eliminado")


# ── Main ──────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🔍 EVIDETH — Test de verificación automático\n")

    generate_test_video()
    segments = segment_and_hash()
    token    = login()
    api_key  = register_camera(token)
    video_id = start_video(api_key)
    upload_segments(api_key, video_id, segments)
    finish_video(api_key, video_id)
    verify_video(token, video_id)
    cleanup()
