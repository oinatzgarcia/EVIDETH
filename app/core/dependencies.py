from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User, UserRole, Camera
from app.core.security import verify_token, hash_api_key

bearerScheme = HTTPBearer(auto_error=False)
apiKeyHeader = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearerScheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Extrae y valida el JWT del header Authorization: Bearer <token>.
    Comprueba is_active en cada petición para revocación inmediata
    (no hay que esperar a que el token expire). OWASP ASVS §3.3.
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Token de autenticación requerido")

    payload = verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=401, detail="Token sin identificador de usuario"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Cuenta desactivada. Contacta con el administrador.",
        )
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Solo usuarios con rol ADMIN pueden acceder."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Acceso restringido a administradores",
        )
    return current_user


def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    """Usuarios con rol ANALYST o ADMIN pueden acceder."""
    if current_user.role not in (UserRole.ADMIN, UserRole.ANALYST):
        raise HTTPException(
            status_code=403,
            detail="Acceso restringido a analistas y administradores",
        )
    return current_user


def get_current_camera(
    api_key: str = Security(apiKeyHeader),
    db: Session = Depends(get_db),
) -> Camera:
    """
    Valida la API Key enviada en el header X-API-Key.

    Seguridad:
    - La API Key se almacena hasheada (SHA-256) en BD — nunca en claro.
    - Las cámaras desactivadas son rechazadas aunque la API Key sea
      criptográficamente válida (principio de menor privilegio).
    - NIST SP 800-57: las claves de entidades desactivadas deben
      considerarse revocadas operacionalmente.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API Key requerida (header X-API-Key)",
        )

    hashed = hash_api_key(api_key)
    camera = db.query(Camera).filter(Camera.api_key == hashed).first()

    if not camera:
        raise HTTPException(status_code=401, detail="API Key inválida")

    # Cámara desactivada: la clave sigue siendo criptográficamente válida
    # pero el sistema rechaza operaciones de cámaras inactivas.
    # Esto garantiza que la desactivación es inmediata (no hay tokens
    # que esperar a expirar, a diferencia de JWT).
    if not camera.is_active:
        raise HTTPException(
            status_code=401,
            detail="Cámara desactivada. API Key revocada operacionalmente.",
        )

    return camera
