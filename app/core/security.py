from datetime import UTC, datetime, timedelta
from typing import Optional

import bcrypt as _bcrypt
from jose import JWTError, jwt

from app.config import settings
import secrets
import hashlib

# ── bcrypt ────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ── JWT ───────────────────────────────────────────────────────────


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decodifica y valida un JWT. Devuelve el payload o None si el token
    es inválido o ha expirado.
    """
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        return None


# Alias para compatibilidad con dependencies.py
verify_token = decode_token


# ── API Keys para cámaras ─────────────────────────────────────────


def generate_api_key() -> str:
    """Genera una API Key segura con el formato evideth_cam_<32 chars>."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    random_part = "".join(secrets.choice(chars) for _ in range(32))
    return f"evideth_cam_{random_part}"


def hash_api_key(api_key: str) -> str:
    """Hashea la API Key para almacenarla en BD (nunca en claro)."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(plain: str, hashed: str) -> bool:
    return hash_api_key(plain) == hashed
