"""
app/core/seed.py

Creacion del usuario administrador por defecto.

Se ejecuta automaticamente en cada arranque del servidor (lifespan).
Es idempotente: si admin@evideth.com ya existe, no hace nada.

Credenciales iniciales:
  Email:      admin@evideth.com
  Contrasena: Evideth@2026!

El campo must_change_password=True obliga al admin a cambiar la
contrasena en su primer login. Hasta que no la cambie, el endpoint
POST /api/v1/auth/change-password devuelve 403 en cualquier otra ruta.
"""

import logging

from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.models import User, UserRole

logger = logging.getLogger(__name__)

DEFAULT_ADMIN_EMAIL = "admin@evideth.com"
DEFAULT_ADMIN_PASSWORD = "Evideth@2026!"
DEFAULT_ADMIN_NAME = "Administrador EVIDETH"


def seed_default_admin(db: Session) -> None:
    """
    Crea el usuario admin por defecto si no existe.

    Idempotente: llamar multiples veces es seguro.
    """
    existing = db.query(User).filter(User.email == DEFAULT_ADMIN_EMAIL).first()
    if existing:
        logger.debug("Admin por defecto ya existe, seed omitido.")
        return

    admin = User(
        email=DEFAULT_ADMIN_EMAIL,
        full_name=DEFAULT_ADMIN_NAME,
        password=hash_password(DEFAULT_ADMIN_PASSWORD),
        role=UserRole.ADMIN,
        is_active=True,
        must_change_password=True,  # obliga a cambiar en primer login
    )
    db.add(admin)
    db.commit()
    logger.info(
        "Usuario admin por defecto creado: %s (debe cambiar contrasena en primer login)",
        DEFAULT_ADMIN_EMAIL,
    )
