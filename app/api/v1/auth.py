"""
app/api/v1/auth.py
==================
Endpoints de autenticacion JWT para usuarios de EVIDETH.

Rutas:
  POST /api/v1/auth/login            -- obtener JWT
  GET  /api/v1/auth/me               -- perfil del usuario autenticado
  POST /api/v1/auth/refresh          -- renovar JWT sin volver a hacer login
  POST /api/v1/auth/change-password  -- cambiar contrasena (obligatorio en primer login)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.core.logger import log
from app.core.security import create_access_token, hash_password, verify_password
from app.db.models import User
from app.db.session import get_db

router = APIRouter(prefix="/auth", tags=["Auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    must_change_password: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 10:
            raise ValueError("La nueva contrasena debe tener al menos 10 caracteres")
        if v == "Evideth@2026!":
            raise ValueError("No puedes reutilizar la contrasena por defecto")
        return v


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login -- obtener JWT",
    description=(
        "Autentica al usuario con email y contrasena. "
        "Si must_change_password=true en la respuesta, el cliente DEBE "
        "redirigir a la pantalla de cambio de contrasena antes de continuar."
    ),
)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "-"
    user = db.query(User).filter(User.email == payload.email).first()

    if not user or not verify_password(payload.password, user.password):
        log.warning(
            "login_failed", extra={"ip": ip, "detail": f"email={payload.email}"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email o contrasena incorrectos",
        )

    if not user.is_active:
        log.warning(
            "login_blocked_inactive",
            extra={
                "ip": ip,
                "user_id": str(user.id),
                "detail": f"email={payload.email}",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Cuenta desactivada"
        )

    token = create_access_token(
        {
            "sub": str(user.id),
            "role": user.role.value,
            "mcp": user.must_change_password,  # must_change_password en el JWT
        }
    )
    log.info(
        "login_ok",
        extra={
            "ip": ip,
            "user_id": str(user.id),
            "detail": f"role={user.role.value} mcp={user.must_change_password}",
        },
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "must_change_password": user.must_change_password,
    }


@router.get(
    "/me",
    summary="Perfil del usuario autenticado",
    description="Devuelve el perfil del usuario identificado por el JWT.",
)
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role.value,
        "is_active": current_user.is_active,
        "must_change_password": current_user.must_change_password,
        "created_at": current_user.created_at,
    }


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Renovar JWT",
    description="Emite un nuevo JWT para el usuario autenticado sin solicitar contrasena.",
)
def refresh(current_user: User = Depends(get_current_user)):
    token = create_access_token(
        {
            "sub": str(current_user.id),
            "role": current_user.role.value,
            "mcp": current_user.must_change_password,
        }
    )
    log.info("token_refreshed", extra={"user_id": str(current_user.id)})
    return {
        "access_token": token,
        "token_type": "bearer",
        "must_change_password": current_user.must_change_password,
    }


@router.post(
    "/change-password",
    summary="Cambiar contrasena",
    description=(
        "Permite al usuario cambiar su contrasena. "
        "Obligatorio si must_change_password=true. "
        "Tras el cambio emite un nuevo JWT con must_change_password=false."
    ),
    response_model=TokenResponse,
)
def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(payload.current_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contrasena actual no es correcta",
        )

    current_user.password = hash_password(payload.new_password)
    current_user.must_change_password = False
    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    token = create_access_token(
        {
            "sub": str(current_user.id),
            "role": current_user.role.value,
            "mcp": False,
        }
    )
    log.info(
        "password_changed",
        extra={"user_id": str(current_user.id), "detail": "must_change_password cleared"},
    )
    return {"access_token": token, "token_type": "bearer", "must_change_password": False}
