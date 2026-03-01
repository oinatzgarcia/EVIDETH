#!/usr/bin/env python3
"""
tamper_video.py  --  Herramienta de tampering forense para demos EVIDETH
========================================================================
Modifica N bytes dentro del bloque mdat (datos de frame comprimidos)
de un video MP4, en el rango temporal correspondiente al segundo
elegido. El contenedor MP4 queda valido (ffmpeg puede leerlo) pero
los frames decodificados cambian -> EVIDETH detecta la manipulacion.

Uso:
    python tools/tamper_video.py <input.mp4> [opciones]

Ejemplos:
    # Tamperiza el segundo 3 del video (por defecto 8 bytes en el centro)
    python tools/tamper_video.py saved_segments/CAM-SIM-01_xxx_seg0000.mp4 --second 3

    # Tamperiza el segundo 0 modificando 32 bytes
    python tools/tamper_video.py saved_segments/CAM-SIM-01_xxx_seg0000.mp4 --second 0 --nbytes 32

    # Especifica fichero de salida
    python tools/tamper_video.py entrada.mp4 --second 5 --output tampered.mp4
"""

import argparse
import hashlib
import os
import struct
import shutil
import sys


# ---------------------------------------------------------------------------
# Localizacion del bloque mdat dentro del MP4
# ---------------------------------------------------------------------------

def find_mdat_offset(data: bytes) -> tuple[int, int]:
    """
    Busca el primer box 'mdat' en el fichero MP4.
    Devuelve (offset_inicio_payload, tamanio_payload).
    El payload empieza justo despues del header del box (8 bytes: size + 'mdat').
    """
    pos = 0
    while pos < len(data) - 8:
        box_size = struct.unpack(">I", data[pos:pos+4])[0]
        box_type = data[pos+4:pos+8]

        if box_type == b"mdat":
            payload_start = pos + 8
            payload_size  = box_size - 8
            return payload_start, payload_size

        if box_size == 0:   # box hasta el EOF
            break
        if box_size < 8:    # box corrupto
            pos += 1
            continue
        pos += box_size

    raise ValueError(
        "No se encontro el bloque 'mdat' en el fichero. "
        "Asegurate de que es un MP4 valido generado por el simulador EVIDETH."
    )


# ---------------------------------------------------------------------------
# Calculo del offset dentro de mdat para un segundo concreto
# ---------------------------------------------------------------------------

def offset_for_second(mdat_payload_size: int, duration_secs: int, target_second: int) -> int:
    """
    Estima el offset dentro del payload mdat que corresponde al segundo
    'target_second'. Divide el payload uniformemente entre los segundos
    y apunta al centro del rango correspondiente.
    """
    bytes_per_second = mdat_payload_size // duration_secs
    sec_start        = bytes_per_second * target_second
    # Apuntar al centro del segundo para evitar keyframe headers
    return sec_start + bytes_per_second // 2


# ---------------------------------------------------------------------------
# Tampering
# ---------------------------------------------------------------------------

def tamper(input_path: str,
           output_path: str,
           target_second: int,
           n_bytes: int,
           duration_secs: int) -> dict:
    """
    Lee el fichero, localiza el segundo indicado dentro de mdat y
    invierte n_bytes de bits (XOR 0xFF) en esa posicion.

    Devuelve un dict con los detalles del tampering para el informe.
    """
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    sha256_before = hashlib.sha256(bytes(data)).hexdigest()

    # --- Localizar mdat ---
    mdat_start, mdat_size = find_mdat_offset(bytes(data))

    if mdat_size < duration_secs * 10:
        raise ValueError(
            f"mdat demasiado pequenio ({mdat_size} bytes) para {duration_secs} segundos. "
            "Comprueba --duration."
        )

    # --- Calcular offset de tampering ---
    inner_offset = offset_for_second(mdat_size, duration_secs, target_second)
    abs_offset   = mdat_start + inner_offset

    if abs_offset + n_bytes > len(data):
        raise ValueError(
            f"Offset {abs_offset} + {n_bytes} bytes supera el tamano del fichero ({len(data)} bytes)."
        )

    # --- Guardar bytes originales y aplicar XOR 0xFF ---
    original_bytes = bytes(data[abs_offset : abs_offset + n_bytes])
    for i in range(n_bytes):
        data[abs_offset + i] ^= 0xFF

    sha256_after = hashlib.sha256(bytes(data)).hexdigest()

    with open(output_path, "wb") as f:
        f.write(data)

    return {
        "input":           input_path,
        "output":          output_path,
        "target_second":   target_second,
        "n_bytes":         n_bytes,
        "mdat_start":      mdat_start,
        "mdat_size":       mdat_size,
        "abs_offset":      abs_offset,
        "original_bytes":  original_bytes.hex(),
        "tampered_bytes":  bytes(data[abs_offset:abs_offset+n_bytes]).hex(),
        "sha256_before":   sha256_before,
        "sha256_after":    sha256_after,
        "sha256_changed":  sha256_before != sha256_after,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Tamperiza un segundo especifico de un video MP4 para demo EVIDETH."
    )
    parser.add_argument("input",           help="Fichero MP4 de entrada")
    parser.add_argument("--second",   "-s", type=int, default=2,
                        help="Segundo a tamperizar (0-indexed, default: 2)")
    parser.add_argument("--nbytes",   "-n", type=int, default=8,
                        help="Numero de bytes a invertir (XOR 0xFF, default: 8)")
    parser.add_argument("--duration", "-d", type=int, default=0,
                        help="Duracion del video en segundos (0 = autodetectar, default: 0)")
    parser.add_argument("--output",   "-o", default="",
                        help="Fichero de salida (default: <input>_tampered_secN.mp4)")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[ERROR] No se encuentra el fichero: {args.input}")
        sys.exit(1)

    # Autodetectar duracion con ffprobe si no se especifica
    if args.duration == 0:
        import subprocess, json
        r = subprocess.run(
            ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", args.input],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print("[ERROR] ffprobe no disponible. Especifica --duration manualmente.")
            sys.exit(1)
        duration_secs = int(float(json.loads(r.stdout)["format"]["duration"]))
    else:
        duration_secs = args.duration

    if args.second >= duration_secs or args.second < 0:
        print(f"[ERROR] --second {args.second} fuera de rango (video tiene {duration_secs}s, indices 0-{duration_secs-1}).")
        sys.exit(1)

    # Fichero de salida
    if args.output:
        output_path = args.output
    else:
        base, ext   = os.path.splitext(args.input)
        output_path = f"{base}_tampered_sec{args.second}{ext}"

    print(f"[INFO]  Input          : {args.input}")
    print(f"[INFO]  Output         : {output_path}")
    print(f"[INFO]  Duracion       : {duration_secs}s")
    print(f"[INFO]  Segundo target : {args.second}")
    print(f"[INFO]  Bytes a flip   : {args.nbytes}")
    print()

    result = tamper(
        input_path     = args.input,
        output_path    = output_path,
        target_second  = args.second,
        n_bytes        = args.nbytes,
        duration_secs  = duration_secs,
    )

    print(f"[OK]    mdat encontrado  : offset {result['mdat_start']} bytes, tamano {result['mdat_size']} bytes")
    print(f"[OK]    Offset absoluto  : {result['abs_offset']} (segundo {args.second} ~ centro del rango)")
    print(f"[OK]    Bytes originales : {result['original_bytes']}")
    print(f"[OK]    Bytes tampeados  : {result['tampered_bytes']}")
    print()
    print(f"[OK]    SHA-256 antes    : {result['sha256_before']}")
    print(f"[OK]    SHA-256 despues  : {result['sha256_after']}")
    print(f"[{'OK' if result['sha256_changed'] else 'WARN'}]   SHA-256 cambiado : {result['sha256_changed']}")
    print()
    print(f"[INFO]  Verificar en EVIDETH:")
    print(f"        POST /api/v1/verification/upload/{{video_id}}")
    print(f"        Adjuntar: {output_path}")
    print(f"        Esperado: MANIPULADO -- Segundo(s) afectado(s): [{args.second}]")


if __name__ == "__main__":
    main()
