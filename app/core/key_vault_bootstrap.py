"""
app/core/key_vault_bootstrap.py
─────────────────────────────────────────────────────────────────────────────
Bootstrap de secretos desde Azure Key Vault al arrancar la aplicación.

Si Key Vault está disponible, sobreescribe los valores de Settings con los
secretos almacenados en Key Vault, eliminando la necesidad de tener
JWT_SECRET_KEY o DATABASE_URL en variables de entorno del contenedor.

Flujo en producción:
  1. Container App arranca con Managed Identity (sin credenciales explícitas).
  2. Este módulo obtiene JWT_SECRET_KEY y DB_PASSWORD de Key Vault.
  3. La aplicación opera con secretos gestionados centralmente.
  4. Rotación de secretos: se actualiza en Key Vault → reinicio del container.

Flujo en desarrollo/test:
  - AZURE_KEY_VAULT_URL vacío → bootstrap es no-op → .env funciona como siempre.
─────────────────────────────────────────────────────────────────────────────
"""

import logging

logger = logging.getLogger(__name__)

# Mapa: nombre del secreto en Key Vault → atributo en Settings
KEY_VAULT_SECRET_MAP = {
    "evideth-jwt-secret-key": "JWT_SECRET_KEY",
    "evideth-secret-key": "SECRET_KEY",
}


def bootstrap_secrets_from_key_vault() -> None:
    """
    Obtiene secretos críticos de Key Vault y los inyecta en Settings.

    Llamar una única vez al arrancar la aplicación, antes de que cualquier
    módulo use `settings.JWT_SECRET_KEY` o `settings.DATABASE_URL`.

    Si Key Vault no está disponible (dev local), esta función es un no-op.
    """
    from app.config import settings
    from app.core.key_vault import get_key_vault

    kv = get_key_vault()

    if not kv.available:
        logger.debug(
            "Key Vault no disponible — usando secretos desde variables de entorno."
        )
        return

    logger.info("Cargando secretos desde Azure Key Vault...")
    loaded = 0

    for secret_name, settings_attr in KEY_VAULT_SECRET_MAP.items():
        value = kv.get_secret(secret_name)
        if value:
            object.__setattr__(settings, settings_attr, value)
            loaded += 1
            logger.info(
                "Secreto '%s' cargado desde Key Vault → settings.%s",
                secret_name,
                settings_attr,
            )
        else:
            logger.warning(
                "Secreto '%s' no encontrado en Key Vault — "
                "usando valor de variable de entorno.",
                secret_name,
            )

    logger.info("%d secreto(s) cargados desde Key Vault.", loaded)
