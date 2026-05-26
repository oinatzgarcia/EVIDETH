"""
tests/unit/test_hash_utils.py

Tests unitarios del cálculo SHA-256 usado en EVIDETH.
Verifica que el hashing de segmentos sea correcto y determinista.

Ejecución:
    pytest tests/unit/test_hash_utils.py -v
"""

import hashlib
import os

import pytest


# ── Helpers (reimplementamos la lógica sin importar app/) ────────────────────
# Estos tests validan el comportamiento esperado del hashing,
# independientemente de la implementación concreta.

def sha256_hex(data: bytes) -> str:
    """SHA-256 de datos binarios → hex string (64 chars)."""
    return hashlib.sha256(data).hexdigest()


def sha256_of_hashes(hashes: list[str]) -> str:
    """
    Combina una lista de hashes hex concatándolos y aplicando SHA-256.
    Es la lógica simplificada del Merkle root de EVIDETH.
    """
    combined = "".join(hashes)
    return hashlib.sha256(combined.encode()).hexdigest()


# ── Tests ────────────────────────────────────────────────────────────────────

class TestSha256Hash:

    def test_output_is_64_chars_hex(self):
        """SHA-256 siempre produce 64 caracteres hexadecimales."""
        result = sha256_hex(b"evideth-test-segment")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self):
        """El mismo input siempre produce el mismo hash."""
        data = b"segment-data-30s"
        assert sha256_hex(data) == sha256_hex(data)

    def test_different_inputs_differ(self):
        """Datos distintos producen hashes distintos (resistencia a colisiones)."""
        h1 = sha256_hex(b"frame-original")
        h2 = sha256_hex(b"frame-tampered")
        assert h1 != h2

    def test_avalanche_effect(self):
        """
        Cambiar un solo bit en la entrada cambia drásticamente el hash.
        Verifica el efecto avaláncha de SHA-256.
        """
        original = b"evideth-frame-data"
        tampered = b"fvideth-frame-data"  # Solo cambia la primera letra
        h1 = sha256_hex(original)
        h2 = sha256_hex(tampered)
        # Los hashes deben diferir en al menos la mitad de los bits
        bits_diff = bin(int(h1, 16) ^ int(h2, 16)).count('1')
        assert bits_diff > 100, f"Efecto avaláncha insuficiente: solo {bits_diff} bits cambiaron"

    def test_empty_bytes_has_known_hash(self):
        """El hash de bytes vacíos es el SHA-256 conocido (valor de referencia NIST)."""
        empty_hash = sha256_hex(b"")
        assert empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_large_data(self):
        """Puede hashear datos de 4MB sin errores (equivale a ~30s de video comprimido)."""
        large_data = os.urandom(4 * 1024 * 1024)
        result = sha256_hex(large_data)
        assert len(result) == 64


class TestMerkleRootSimple:

    def test_single_hash_merkle(self):
        """Un solo hash → el Merkle root es su propio SHA-256."""
        h = sha256_hex(b"frame-0")
        root = sha256_of_hashes([h])
        assert len(root) == 64

    def test_merkle_order_matters(self):
        """El orden de los hashes afecta al Merkle root (no es conmutativo)."""
        h1 = sha256_hex(b"frame-0")
        h2 = sha256_hex(b"frame-1")
        root_ab = sha256_of_hashes([h1, h2])
        root_ba = sha256_of_hashes([h2, h1])
        assert root_ab != root_ba

    def test_tampered_frame_changes_root(self):
        """
        Si un frame es manipulado, su hash cambia y el Merkle root también.
        Esto simula la detección de manipulación en EVIDETH.
        """
        original_frames = [sha256_hex(f"frame-{i}".encode()) for i in range(10)]
        tampered_frames  = list(original_frames)
        tampered_frames[5] = sha256_hex(b"tampered-frame-5")  # Manipular frame 5

        root_original = sha256_of_hashes(original_frames)
        root_tampered = sha256_of_hashes(tampered_frames)

        assert root_original != root_tampered

    def test_identical_segments_differ_by_index(self):
        """
        Dos segmentos con el mismo contenido de video deben producir hashes
        diferentes si se incluye el índice de segmento en el cálculo.
        """
        content = b"same-video-content"
        h_seg1 = sha256_hex(b"1" + content)
        h_seg2 = sha256_hex(b"2" + content)
        assert h_seg1 != h_seg2
