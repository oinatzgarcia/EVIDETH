"""
app/utils/crypto.py
===================
Utilidades criptográficas puras de EVIDETH.

Este módulo NO importa nada de app.db ni app.config.
Puede ser usado en tests unitarios sin base de datos.

Funciones:
    verify_ecdsa_signature(merkle_root, signature_b64, public_key_pem) -> bool
"""

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def verify_ecdsa_signature(
    merkle_root: str,
    signature_b64: str,
    public_key_pem: str,
) -> bool:
    """
    Verifica una firma ECDSA P-256 sobre un Merkle root.

    Args:
        merkle_root:    Hex string de 64 caracteres (SHA-256 del árbol Merkle).
        signature_b64:  Firma DER codificada en base64url (sin padding).
        public_key_pem: Clave pública en formato PEM (SubjectPublicKeyInfo).

    Returns:
        True  si la firma es criptográficamente válida.
        False en cualquier otro caso (firma incorrecta, PEM inválido,
              Merkle root vacío, excepción inesperada).

    Seguridad:
        - Nunca lanza excepción: cualquier error devuelve False.
        - Los datos firmados son los 32 bytes raw del Merkle root
          (bytes.fromhex), igual que en el simulador de cámara.
        - Ref: NIST FIPS 186-5 (ECDSA), NIST SP 800-57.
    """
    if not merkle_root or not signature_b64 or not public_key_pem:
        return False
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        # Restaurar padding base64url
        padding = 4 - len(signature_b64) % 4
        padded = signature_b64 + "=" * (padding if padding != 4 else 0)
        signature = base64.urlsafe_b64decode(padded)
        data = bytes.fromhex(merkle_root)
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
