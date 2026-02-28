"""
tests/unit/test_verifier_ecdsa.py

Tests unitarios de la función verify_ecdsa_signature() del verifier.

Cada test es autosuficiente: genera su propio par de claves ECDSA P-256.
No requiere BD, ffmpeg ni red.

Ejecución:
    pytest tests/unit/test_verifier_ecdsa.py -v
"""

import base64
import hashlib
import os
import sys

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.verifier import verify_ecdsa_signature


# ── Helpers ─────────────────────────────────────────────────

def _generate_keypair():
    """Genera un par ECDSA P-256 fresco y devuelve (private_key, public_key_pem)."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_key, public_key_pem


def _sign_merkle_root(private_key, merkle_root_hex: str) -> str:
    """
    Firma el Merkle root con la misma convención que el simulador:
        datos = bytes.fromhex(merkle_root)  [32 bytes raw]
        sig   = base64url(ECDSA-SHA256(datos))
    """
    data = bytes.fromhex(merkle_root_hex)
    sig  = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.urlsafe_b64encode(sig).decode()


def _fake_merkle_root() -> str:
    """Genera un Merkle root sintético de 64 chars hex."""
    return hashlib.sha256(os.urandom(32)).hexdigest()


# ── Tests ─────────────────────────────────────────────────

class TestVerifyEcdsaSignature:

    def test_valid_signature(self):
        """Firma + verificación con la misma clave → True."""
        private_key, pub_pem = _generate_keypair()
        merkle_root = _fake_merkle_root()
        signature   = _sign_merkle_root(private_key, merkle_root)

        assert verify_ecdsa_signature(merkle_root, signature, pub_pem) is True

    def test_invalid_signature_tampered_merkle(self):
        """
        Misma firma pero Merkle root diferente (como si el video fuera manipulado).
        La verificación debe fallar.
        """
        private_key, pub_pem = _generate_keypair()
        original_root  = _fake_merkle_root()
        tampered_root  = _fake_merkle_root()   # distinto hash
        signature      = _sign_merkle_root(private_key, original_root)

        # La firma cubre original_root, no tampered_root
        assert verify_ecdsa_signature(tampered_root, signature, pub_pem) is False

    def test_wrong_key(self):
        """
        Firma con clave A, verifica con clave B → False.
        Simula suplantación de cámara.
        """
        key_a, _       = _generate_keypair()
        _,     pub_b   = _generate_keypair()   # clave pública de otra cámara
        merkle_root    = _fake_merkle_root()
        signature      = _sign_merkle_root(key_a, merkle_root)

        # La firma de la cámara A no es válida con la clave de la cámara B
        assert verify_ecdsa_signature(merkle_root, signature, pub_b) is False

    def test_urlsafe_padding_variants(self):
        """
        La firma DER de ECDSA P-256 tiene longitud variable (70–72 bytes).
        base64url produce cadenas de longitud mod 4 ∈ {0,1,2,3}.
        La función debe manejar todos los casos sin excepción.
        """
        private_key, pub_pem = _generate_keypair()
        # Generar hasta 20 firmas para cubrir todas las variantes de padding
        merkle_roots_seen = set()
        for _ in range(20):
            root      = _fake_merkle_root()
            signature = _sign_merkle_root(private_key, root)
            merkle_roots_seen.add(len(signature) % 4)
            assert verify_ecdsa_signature(root, signature, pub_pem) is True, \
                f"Fallo con firma de longitud {len(signature)} (mod4 = {len(signature) % 4})"

    def test_tampered_signature_bytes(self):
        """
        Firma válida pero con el último byte modificado (corrupción parcial).
        """
        private_key, pub_pem = _generate_keypair()
        merkle_root = _fake_merkle_root()
        signature   = _sign_merkle_root(private_key, merkle_root)

        # Decodificar, cambiar último byte, recodificar
        raw       = base64.urlsafe_b64decode(signature + "==")
        tampered  = raw[:-1] + bytes([raw[-1] ^ 0xFF])
        bad_sig   = base64.urlsafe_b64encode(tampered).decode()

        assert verify_ecdsa_signature(merkle_root, bad_sig, pub_pem) is False

    def test_invalid_pem_returns_false(self):
        """
        PEM corrupto no debe lanzar excepción — debe devolver False.
        """
        private_key, _ = _generate_keypair()
        merkle_root    = _fake_merkle_root()
        signature      = _sign_merkle_root(private_key, merkle_root)

        assert verify_ecdsa_signature(merkle_root, signature, "not-a-pem") is False

    def test_empty_signature_returns_false(self):
        """Firma vacía → False sin excepción."""
        _, pub_pem  = _generate_keypair()
        merkle_root = _fake_merkle_root()
        assert verify_ecdsa_signature(merkle_root, "", pub_pem) is False

    def test_empty_merkle_root_returns_false(self):
        """Merkle root vacío → False sin excepción."""
        private_key, pub_pem = _generate_keypair()
        signature = _sign_merkle_root(private_key, _fake_merkle_root())
        assert verify_ecdsa_signature("", signature, pub_pem) is False

    def test_deterministic_for_same_inputs(self):
        """
        Misma firma y misma clave → siempre True (la función es determinista).
        """
        private_key, pub_pem = _generate_keypair()
        merkle_root = _fake_merkle_root()
        signature   = _sign_merkle_root(private_key, merkle_root)

        for _ in range(5):
            assert verify_ecdsa_signature(merkle_root, signature, pub_pem) is True
