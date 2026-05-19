from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, APIKeyHeader
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, UserRole, Camera
from app.core.security import decode_token, verify_api_key

bearer_scheme = HTTPBearer()
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ── Obtener usuario actual desde JWT ──────
def get_current_user(
    token=Depends(bearer_scheme), db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_token(token.credentials)
    if not payload or payload.get("type") != "access":
        raise credentials_exception

    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if not user or not user.is_active:
        raise credentials_exception
    return user


# ── RBAC: decoradores por rol ─────────────
def require_role(*roles: UserRole):
    def checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acceso denegado. Rol requerido: {[r.value for r in roles]}",
            )
        return current_user

    return checker


# Atajos de roles
require_admin = require_role(UserRole.ADMIN)
require_analyst = require_role(UserRole.ADMIN, UserRole.ANALYST)
require_viewer = require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)


# ── Autenticación de cámaras por API Key ──
def get_current_camera(
    api_key: str = Security(api_key_header), db: Session = Depends(get_db)
) -> Camera:
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key requerida"
        )
    cameras = db.query(Camera).filter(Camera.is_active).all()
    for camera in cameras:
        if verify_api_key(api_key, camera.api_key):
            return camera

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key inválida"
    )
