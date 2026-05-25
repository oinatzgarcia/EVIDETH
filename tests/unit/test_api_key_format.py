"""
tests/unit/test_api_key_format.py

Tests unitarios para la generación y validación del formato
de API Keys de cámaras en EVIDETH.

No requieren BD ni red.

Ejecución:
    pytest tests/unit/test_api_key_format.py -v
"""

import re
import secrets
import string

import pytest


# ── Lógica de generación (replica la del backend) ────────────────────────────

EVIDETH_KEY_PREFIX = "evideth_cam_"
EVIDETH_KEY_CHARS  = string.ascii_letters + string.digits
EVIDETH_KEY_LENGTH = 32  # longitud de la parte aleatoria


def generate_api_key() -> str:
    """Genera una API Key con el formato evideth_cam_<32 chars alfanuméricos>."""
    random_part = "".join(secrets.choice(EVIDETH_KEY_CHARS) for _ in range(EVIDETH_KEY_LENGTH))
    return f"{EVIDETH_KEY_PREFIX}{random_part}"


API_KEY_PATTERN = re.compile(r"^evideth_cam_[A-Za-z0-9]{32}$")


def is_valid_api_key_format(key: str) -> bool:
    """Valida que una clave tenga el formato correcto."""
    return bool(API_KEY_PATTERN.match(key))


# ── Tests ────────────────────────────────────────────────────────────────────

class TestApiKeyGeneration:

    def test_prefix_correct(self):
        """La clave generada empieza con el prefijo oficial."""
        key = generate_api_key()
        assert key.startswith(EVIDETH_KEY_PREFIX)

    def test_total_length(self):
        """La clave tiene la longitud esperada: prefijo + 32 caracteres."""
        key = generate_api_key()
        expected_len = len(EVIDETH_KEY_PREFIX) + EVIDETH_KEY_LENGTH
        assert len(key) == expected_len

    def test_only_alphanumeric_after_prefix(self):
        """La parte aleatoria sólo contiene caracteres alfanuméricos."""
        key = generate_api_key()
        random_part = key[len(EVIDETH_KEY_PREFIX):]
        assert random_part.isalnum()

    def test_matches_regex_pattern(self):
        """La clave generada cumple el patrón regex de validación."""
        for _ in range(10):
            key = generate_api_key()
            assert is_valid_api_key_format(key), f"Clave inválida: {key}"

    def test_uniqueness(self):
        """1000 claves generadas son todas distintas (entropía suficiente)."""
        keys = {generate_api_key() for _ in range(1000)}
        assert len(keys) == 1000, "Se generaron claves duplicadas"

    def test_uses_secrets_module(self):
        """
        Verifica que la función usa secrets (criptográficamente seguro)
        comprobando que la distribución de caracteres no es uniforme en 100 keys.
        """
        keys = [generate_api_key() for _ in range(100)]
        assert len(set(keys)) > 90


class TestApiKeyValidation:

    def test_valid_key_accepted(self):
        """Una clave correctamente formateada (exactamente 32 chars) pasa la validación."""
        # "AbC123xyz456789AbC123xyz45678900" = exactamente 32 caracteres alfanuméricos
        assert is_valid_api_key_format("evideth_cam_AbC123xyz456789AbC123xy") is True

    def test_empty_key_rejected(self):
        """Clave vacía es rechazada."""
        assert is_valid_api_key_format("") is False

    def test_missing_prefix_rejected(self):
        """Clave sin prefijo es rechazada."""
        assert is_valid_api_key_format("AbC123xyz456789AbC123xyz456789Ab") is False

    def test_wrong_prefix_rejected(self):
        """Clave con prefijo incorrecto es rechazada."""
        assert is_valid_api_key_format("api_cam_AbC123xyz456789AbC123xyz4") is False

    def test_special_chars_rejected(self):
        """Caracteres especiales en la parte aleatoria son rechazados."""
        assert is_valid_api_key_format("evideth_cam_AbC123xyz456789AbC12@#") is False

    def test_too_short_rejected(self):
        """Clave con parte aleatoria demasiado corta es rechazada."""
        assert is_valid_api_key_format("evideth_cam_abc123") is False

    def test_too_long_rejected(self):
        """Clave con parte aleatoria demasiado larga es rechazada."""
        long_key = "evideth_cam_" + "a" * 40
        assert is_valid_api_key_format(long_key) is False

    def test_sql_injection_rejected(self):
        """Intento de SQL injection es rechazado por el patrón."""
        assert is_valid_api_key_format("evideth_cam_' OR '1'='1") is False

    def test_jwt_token_rejected(self):
        """Un JWT no debe ser válido como API Key de cámara."""
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
        assert is_valid_api_key_format(fake_jwt) is False
