"""
app/core/key_vault.py

Integración con Azure Key Vault para EVIDETH.

Estrategia de autenticación (DefaultAzureCredential):
  1. Producción (Azure Container App):
     Managed Identity: sin CLIENT_ID ni CLIENT_SECRET en variables de entorno.
     El Container App tiene una identidad asignada con acceso a Key Vault.
  2. CI / GitHub Actions:
     Service Principal: AZURE_CLIENT_ID + AZURE_CLIENT_SECRET + AZURE_TENANT_ID
     se inyectan como secretos de Actions (nunca en texto plano en el repo).
  3. Local (development):
     Si AZURE_KEY_VAULT_URL está vacío, Key Vault se omite completamente
     y los secretos se leen desde .env (comportamiento actual sin cambios).

Convención de nombres de secretos en Key Vault:
  - Secretos de aplicación:  evideth-jwt-secret-key
                              evideth-db-password
  - Claves ECDSA por cámara: evideth-camera-{camera_id}-private-key
                              evideth-camera-{camera_id}-public-key

Ref: OWASP ASVS S6.4.1 (gestión de claves), NIST SP 800-57 Part 1.
"""

import logging
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)


class KeyVaultClient:
    """
    Cliente singleton para Azure Key Vault.

    Uso::

        from app.core.key_vault import kv

        secret = kv.get_secret("evideth-jwt-secret-key", fallback="dev-value")
        private_key_pem = kv.get_camera_private_key("cam-001")
    """

    def __init__(self, vault_url: str):
        self._vault_url = vault_url
        self._secret_client = None
        self._key_client = None
        self._available = False
        self._init_clients()

    def _init_clients(self) -> None:
        """Inicializa los clientes de Key Vault con DefaultAzureCredential."""
        if not self._vault_url:
            logger.info(
                "AZURE_KEY_VAULT_URL no configurado - Key Vault deshabilitado. "
                "Los secretos se leerán desde variables de entorno (.env)."
            )
            return

        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.secrets import SecretClient

            credential = DefaultAzureCredential()
            self._secret_client = SecretClient(
                vault_url=self._vault_url,
                credential=credential,
            )
            self._key_client = KeyClient(
                vault_url=self._vault_url,
                credential=credential,
            )
            self._available = True
            logger.info(
                "Azure Key Vault inicializado correctamente: %s", self._vault_url
            )
        except ImportError:
            logger.warning(
                "azure-identity / azure-keyvault-secrets no instalados. "
                "Instala: pip install azure-identity azure-keyvault-secrets"
            )
        except Exception as exc:
            logger.error(
                "No se pudo inicializar Azure Key Vault (%s): %s. "
                "Usando fallback a variables de entorno.",
                self._vault_url,
                exc,
            )

    @property
    def available(self) -> bool:
        """True si Key Vault está configurado y accesible."""
        return self._available

    # Secretos

    def get_secret(self, name: str, fallback: Optional[str] = None) -> Optional[str]:
        """
        Obtiene un secreto de Key Vault.
        Si Key Vault no está disponible, devuelve ``fallback``.

        Args:
            name: Nombre del secreto en Key Vault (ej: "evideth-jwt-secret-key").
            fallback: Valor a devolver si Key Vault no está disponible.

        Returns:
            El valor del secreto, o ``fallback`` si Key Vault no está activo.
        """
        if not self._available or self._secret_client is None:
            return fallback

        try:
            secret = self._secret_client.get_secret(name)
            return secret.value
        except Exception as exc:
            logger.error("Error obteniendo secreto '%s' de Key Vault: %s", name, exc)
            return fallback

    def set_secret(self, name: str, value: str) -> bool:
        """
        Almacena o actualiza un secreto en Key Vault.

        Args:
            name: Nombre del secreto.
            value: Valor del secreto (nunca se loguea).

        Returns:
            True si se almacenó correctamente, False si hubo error.
        """
        if not self._available or self._secret_client is None:
            logger.warning(
                "Key Vault no disponible - no se pudo almacenar secreto '%s'.", name
            )
            return False

        try:
            self._secret_client.set_secret(name, value)
            logger.info("Secreto '%s' almacenado en Key Vault.", name)
            return True
        except Exception as exc:
            logger.error(
                "Error almacenando secreto '%s' en Key Vault: %s", name, exc
            )
            return False

    def delete_secret(self, name: str) -> bool:
        """
        Elimina (soft-delete) un secreto de Key Vault.
        Azure retiene el secreto durante el período de retención configurado.
        """
        if not self._available or self._secret_client is None:
            return False

        try:
            self._secret_client.begin_delete_secret(name).result()
            logger.info("Secreto '%s' eliminado de Key Vault.", name)
            return True
        except Exception as exc:
            logger.error(
                "Error eliminando secreto '%s' de Key Vault: %s", name, exc
            )
            return False

    # Claves ECDSA por camara

    def get_camera_private_key(self, camera_id: str) -> Optional[str]:
        """
        Obtiene la clave privada ECDSA P-256 de una cámara desde Key Vault.

        Convención de nombre: ``evideth-camera-{camera_id}-private-key``.
        El valor almacenado es la clave en formato PEM.

        Args:
            camera_id: Identificador de la cámara (ej: "cam-001").

        Returns:
            Clave privada en formato PEM, o None si no existe.
        """
        return self.get_secret(_camera_private_key_name(camera_id))

    def store_camera_private_key(self, camera_id: str, private_key_pem: str) -> bool:
        """
        Almacena la clave privada ECDSA P-256 de una cámara en Key Vault.
        La clave privada NUNCA debe almacenarse en la base de datos.

        Args:
            camera_id: Identificador de la cámara.
            private_key_pem: Clave privada en formato PEM.

        Returns:
            True si se almacenó correctamente.
        """
        return self.set_secret(_camera_private_key_name(camera_id), private_key_pem)

    def get_camera_public_key(self, camera_id: str) -> Optional[str]:
        """
        Obtiene la clave pública ECDSA P-256 de una cámara desde Key Vault.
        Alternativa a leer ``Camera.public_key_pem`` de la BD.
        """
        return self.get_secret(_camera_public_key_name(camera_id))

    def store_camera_public_key(self, camera_id: str, public_key_pem: str) -> bool:
        """
        Almacena la clave pública ECDSA P-256 de una cámara en Key Vault.
        La clave pública también se guarda en BD (``cameras.public_key_pem``)
        para consultas rápidas sin llamar a Key Vault en cada verificación.
        """
        return self.set_secret(_camera_public_key_name(camera_id), public_key_pem)

    def rotate_camera_keys(
        self, camera_id: str, new_private_pem: str, new_public_pem: str
    ) -> bool:
        """
        Rota las claves ECDSA de una cámara.
        Key Vault mantiene el historial de versiones anteriores automáticamente.

        Returns:
            True si ambas claves se rotaron correctamente.
        """
        ok_priv = self.store_camera_private_key(camera_id, new_private_pem)
        ok_pub = self.store_camera_public_key(camera_id, new_public_pem)
        if ok_priv and ok_pub:
            logger.info("Claves ECDSA rotadas para cámara '%s'.", camera_id)
        else:
            logger.error(
                "Rotación de claves incompleta para cámara '%s': "
                "private=%s public=%s.",
                camera_id,
                ok_priv,
                ok_pub,
            )
        return ok_priv and ok_pub


# Helpers de nomenclatura


def _camera_private_key_name(camera_id: str) -> str:
    """Sanitiza el camera_id para usarlo como nombre de secreto en Key Vault."""
    safe_id = camera_id.lower().replace("_", "-").replace(" ", "-")
    return f"evideth-camera-{safe_id}-private-key"


def _camera_public_key_name(camera_id: str) -> str:
    """Sanitiza el camera_id para usarlo como nombre de secreto en Key Vault."""
    safe_id = camera_id.lower().replace("_", "-").replace(" ", "-")
    return f"evideth-camera-{safe_id}-public-key"


# Singleton


@lru_cache(maxsize=1)
def _get_kv_instance() -> KeyVaultClient:
    """Crea la instancia singleton de KeyVaultClient."""
    from app.config import settings

    return KeyVaultClient(vault_url=settings.AZURE_KEY_VAULT_URL)


def get_key_vault() -> KeyVaultClient:
    """
    Devuelve la instancia singleton de KeyVaultClient.

    Uso como dependencia FastAPI o importación directa::

        from app.core.key_vault import get_key_vault
        kv = get_key_vault()
        private_key = kv.get_camera_private_key("cam-001")
    """
    return _get_kv_instance()


# Acceso directo: `from app.core.key_vault import kv`
kv = get_key_vault()
