"""
app/api/v1/auth.py
==================
Endpoints de autenticación JWT para usuarios de EVIDETH.

Rutas:
  POST /api/v1/auth/login   — obtener JWT
  GET  /api/v1/auth/me      — perfil del usuario autenticado
  POST /api/v1/auth/refresh — renovar JWT sin volver a hacer login
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.db.session import get_db
from app.db.models import User
from app.core.security import verify_password, create_access_token
from app.core.dependencies import get_current_user
from app.core.logger import log

router = APIRouter(prefix="/auth", tags=["Auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login — obtener JWT",
    description="Autentica al usuario con email y contraseña. Devuelve un JWT Bearer.",
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
            detail="Email o contraseña incorrectos",
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

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    log.info(
        "login_ok",
        extra={"ip": ip, "user_id": str(user.id), "detail": f"role={user.role.value}"},
    )
    return {"access_token": token, "token_type": "bearer"}


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
        "created_at": current_user.created_at,
    }


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Renovar JWT",
    description="Emite un nuevo JWT para el usuario autenticado sin solicitar contraseña.",
)
def refresh(current_user: User = Depends(get_current_user)):
    token = create_access_token(
        {"sub": str(current_user.id), "role": current_user.role.value}
    )
    log.info("token_refreshed", extra={"user_id": str(current_user.id)})
    return {"access_token": token, "token_type": "bearer"}
