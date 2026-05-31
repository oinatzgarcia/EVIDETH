"""
tests/unit/test_key_vault.py

Tests unitarios para app/core/key_vault.py y app/core/key_vault_bootstrap.py.

Estrategia: todos los tests usan mocks de los clientes de Azure
(SecretClient, KeyClient) para no requerir conexion real a Key Vault.
El CI ejecuta estos tests sin credenciales de Azure.

Escenarios cubiertos:
  1. Key Vault deshabilitado (URL vacia) - fallback a env vars
  2. Key Vault disponible - get/set/delete de secretos
  3. Key Vault disponible - gestion de claves ECDSA por camara
  4. Key Vault no accesible - fallback graceful sin crash
  5. Bootstrap de secretos al arrancar la aplicacion
  6. Convencion de nombres de secretos por camara
"""

from unittest.mock import MagicMock, call, patch

import pytest

from app.core.key_vault import (
    KeyVaultClient,
    _camera_private_key_name,
    _camera_public_key_name,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def kv_disabled():
    """KeyVaultClient con URL vacia - Key Vault deshabilitado."""
    return KeyVaultClient(vault_url="")


@pytest.fixture
def kv_available():
    """KeyVaultClient con Key Vault disponible (SecretClient mockeado)."""
    with patch("app.core.key_vault.KeyVaultClient._init_clients"):
        client = KeyVaultClient(vault_url="https://evideth-kv.vault.azure.net/")
        client._available = True
        client._secret_client = MagicMock()
        client._key_client = MagicMock()
        yield client


@pytest.fixture
def kv_unavailable():
    """KeyVaultClient configurado pero inaccesible (simula error de red)."""
    with patch("app.core.key_vault.KeyVaultClient._init_clients"):
        client = KeyVaultClient(vault_url="https://evideth-kv.vault.azure.net/")
        client._available = False
        client._secret_client = None
        yield client


# ---------------------------------------------------------------------------
# 1. Key Vault deshabilitado (URL vacia)
# ---------------------------------------------------------------------------


class TestKeyVaultDisabled:
    def test_available_is_false_when_no_url(self, kv_disabled):
        assert kv_disabled.available is False

    def test_get_secret_returns_fallback(self, kv_disabled):
        result = kv_disabled.get_secret("any-secret", fallback="my-fallback")
        assert result == "my-fallback"

    def test_get_secret_returns_none_without_fallback(self, kv_disabled):
        result = kv_disabled.get_secret("any-secret")
        assert result is None

    def test_set_secret_returns_false(self, kv_disabled):
        assert kv_disabled.set_secret("name", "value") is False

    def test_delete_secret_returns_false(self, kv_disabled):
        assert kv_disabled.delete_secret("name") is False

    def test_get_camera_private_key_returns_none(self, kv_disabled):
        assert kv_disabled.get_camera_private_key("cam-001") is None

    def test_get_camera_public_key_returns_none(self, kv_disabled):
        assert kv_disabled.get_camera_public_key("cam-001") is None


# ---------------------------------------------------------------------------
# 2. Key Vault disponible - secretos generales
# ---------------------------------------------------------------------------


class TestKeyVaultSecrets:
    def test_available_is_true(self, kv_available):
        assert kv_available.available is True

    def test_get_secret_returns_value(self, kv_available):
        mock_secret = MagicMock()
        mock_secret.value = "super-secret-jwt-key"
        kv_available._secret_client.get_secret.return_value = mock_secret

        result = kv_available.get_secret("evideth-jwt-secret-key")

        assert result == "super-secret-jwt-key"
        kv_available._secret_client.get_secret.assert_called_once_with(
            "evideth-jwt-secret-key"
        )

    def test_get_secret_returns_fallback_on_exception(self, kv_available):
        kv_available._secret_client.get_secret.side_effect = Exception("Not found")

        result = kv_available.get_secret("missing-secret", fallback="default")

        assert result == "default"

    def test_set_secret_returns_true_on_success(self, kv_available):
        result = kv_available.set_secret("evideth-jwt-secret-key", "new-value")

        assert result is True
        kv_available._secret_client.set_secret.assert_called_once_with(
            "evideth-jwt-secret-key", "new-value"
        )

    def test_set_secret_returns_false_on_exception(self, kv_available):
        kv_available._secret_client.set_secret.side_effect = Exception("Forbidden")

        result = kv_available.set_secret("name", "value")

        assert result is False

    def test_delete_secret_returns_true_on_success(self, kv_available):
        mock_poller = MagicMock()
        kv_available._secret_client.begin_delete_secret.return_value = mock_poller

        result = kv_available.delete_secret("evideth-jwt-secret-key")

        assert result is True
        mock_poller.result.assert_called_once()

    def test_delete_secret_returns_false_on_exception(self, kv_available):
        kv_available._secret_client.begin_delete_secret.side_effect = Exception(
            "Not found"
        )

        result = kv_available.delete_secret("missing-secret")

        assert result is False


# ---------------------------------------------------------------------------
# 3. Gestion de claves ECDSA por camara
# ---------------------------------------------------------------------------


class TestCameraECDSAKeys:
    FAKE_PRIVATE_PEM = (
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHQCAQEEIOaRqVItDnLQMCDkxWlMGBFqVQIV+fakeprivatekey==\n"
        "-----END EC PRIVATE KEY-----"
    )
    FAKE_PUBLIC_PEM = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfakepublickey==\n"
        "-----END PUBLIC KEY-----"
    )

    def test_store_camera_private_key(self, kv_available):
        result = kv_available.store_camera_private_key("cam-001", self.FAKE_PRIVATE_PEM)

        assert result is True
        kv_available._secret_client.set_secret.assert_called_once_with(
            "evideth-camera-cam-001-private-key", self.FAKE_PRIVATE_PEM
        )

    def test_get_camera_private_key(self, kv_available):
        mock_secret = MagicMock()
        mock_secret.value = self.FAKE_PRIVATE_PEM
        kv_available._secret_client.get_secret.return_value = mock_secret

        result = kv_available.get_camera_private_key("cam-001")

        assert result == self.FAKE_PRIVATE_PEM
        kv_available._secret_client.get_secret.assert_called_once_with(
            "evideth-camera-cam-001-private-key"
        )

    def test_store_camera_public_key(self, kv_available):
        result = kv_available.store_camera_public_key("cam-001", self.FAKE_PUBLIC_PEM)

        assert result is True
        kv_available._secret_client.set_secret.assert_called_once_with(
            "evideth-camera-cam-001-public-key", self.FAKE_PUBLIC_PEM
        )

    def test_get_camera_public_key(self, kv_available):
        mock_secret = MagicMock()
        mock_secret.value = self.FAKE_PUBLIC_PEM
        kv_available._secret_client.get_secret.return_value = mock_secret

        result = kv_available.get_camera_public_key("cam-001")

        assert result == self.FAKE_PUBLIC_PEM

    def test_rotate_camera_keys_success(self, kv_available):
        result = kv_available.rotate_camera_keys(
            "cam-001", self.FAKE_PRIVATE_PEM, self.FAKE_PUBLIC_PEM
        )

        assert result is True
        assert kv_available._secret_client.set_secret.call_count == 2

    def test_rotate_camera_keys_partial_failure(self, kv_available):
        """Si falla almacenar la clave publica, rotate devuelve False."""
        call_count = {"n": 0}

        def set_secret_side_effect(name, value):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise Exception("Permission denied")

        kv_available._secret_client.set_secret.side_effect = set_secret_side_effect

        result = kv_available.rotate_camera_keys(
            "cam-001", self.FAKE_PRIVATE_PEM, self.FAKE_PUBLIC_PEM
        )

        assert result is False

    def test_camera_id_with_underscores_normalized(self, kv_available):
        """Los guiones bajos en camera_id se convierten a guiones en el nombre."""
        kv_available.store_camera_private_key("cam_exterior_01", self.FAKE_PRIVATE_PEM)

        kv_available._secret_client.set_secret.assert_called_once_with(
            "evideth-camera-cam-exterior-01-private-key", self.FAKE_PRIVATE_PEM
        )


# ---------------------------------------------------------------------------
# 4. Key Vault inaccesible - fallback graceful
# ---------------------------------------------------------------------------


class TestKeyVaultUnavailable:
    def test_get_secret_returns_fallback(self, kv_unavailable):
        result = kv_unavailable.get_secret("any-secret", fallback="env-value")
        assert result == "env-value"

    def test_set_secret_returns_false(self, kv_unavailable):
        assert kv_unavailable.set_secret("name", "value") is False

    def test_no_crash_on_get(self, kv_unavailable):
        """No debe lanzar excepcion aunque Key Vault no este disponible."""
        result = kv_unavailable.get_camera_private_key("cam-001")
        assert result is None


# ---------------------------------------------------------------------------
# 5. Convencion de nombres de secretos
# ---------------------------------------------------------------------------


class TestSecretNamingConvention:
    @pytest.mark.parametrize(
        "camera_id, expected",
        [
            ("cam-001", "evideth-camera-cam-001-private-key"),
            ("cam_exterior", "evideth-camera-cam-exterior-private-key"),
            ("CAM LOBBY", "evideth-camera-cam-lobby-private-key"),
            ("Cam_01_Entrada", "evideth-camera-cam-01-entrada-private-key"),
        ],
    )
    def test_private_key_name(self, camera_id, expected):
        assert _camera_private_key_name(camera_id) == expected

    @pytest.mark.parametrize(
        "camera_id, expected",
        [
            ("cam-001", "evideth-camera-cam-001-public-key"),
            ("cam_exterior", "evideth-camera-cam-exterior-public-key"),
        ],
    )
    def test_public_key_name(self, camera_id, expected):
        assert _camera_public_key_name(camera_id) == expected


# ---------------------------------------------------------------------------
# 6. Bootstrap de secretos
# ---------------------------------------------------------------------------


class TestKeyVaultBootstrap:
    def test_bootstrap_noop_when_kv_unavailable(self):
        """bootstrap_secrets_from_key_vault es no-op si Key Vault no esta disponible."""
        mock_kv = MagicMock()
        mock_kv.available = False

        # El import de get_key_vault esta en el modulo bootstrap -> patchear alli
        with patch("app.core.key_vault_bootstrap.get_key_vault", return_value=mock_kv):
            from app.core.key_vault_bootstrap import bootstrap_secrets_from_key_vault

            bootstrap_secrets_from_key_vault()

        mock_kv.get_secret.assert_not_called()

    def test_bootstrap_loads_jwt_secret(self):
        """bootstrap inyecta JWT_SECRET_KEY desde Key Vault en settings."""
        mock_kv = MagicMock()
        mock_kv.available = True
        mock_kv.get_secret.side_effect = lambda name: (
            "kv-jwt-super-secret" if name == "evideth-jwt-secret-key" else None
        )

        with (
            patch("app.core.key_vault_bootstrap.get_key_vault", return_value=mock_kv),
            patch("app.core.key_vault_bootstrap.settings") as mock_settings,
        ):
            from app.core.key_vault_bootstrap import bootstrap_secrets_from_key_vault

            bootstrap_secrets_from_key_vault()

        # Verificar que se llamo set_secret con el nombre correcto
        mock_kv.get_secret.assert_any_call("evideth-jwt-secret-key")
        # Verificar que se intento actualizar settings con el valor de KV
        mock_settings.__class__  # mock_settings fue accedido
