from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.db.models import User
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserResponse,
)
from app.core.dependencies import get_current_user, require_admin

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Helper ───────────────────────────────────────────────


def _build_token_response(user: User) -> TokenResponse:
    """Construye la respuesta de token incluyendo el objeto user.

    Incluir el user en la respuesta evita que el frontend tenga que
    hacer un segundo fetch a GET /auth/me solo para conocer el rol.
    Auth.setTokens(payload) en auth.js persiste payload.user en storage.
    """
    return TokenResponse(
        access_token=create_access_token({"sub": str(user.id), "role": user.role}),
        refresh_token=create_refresh_token({"sub": str(user.id)}),
        user=UserResponse.model_validate(user),
    )


# ── Endpoints ────────────────────────────────────────────


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=201,
    summary="Registrar usuario",
    description="""
Crea una nueva cuenta de usuario. **Solo Admin**.

El campo `role` permite asignar cualquier rol al nuevo usuario.
El primer Admin del sistema debe crearse mediante el script de seed
o una migración de base de datos (`scripts/seed_admin.py`).

**RBAC:**
- `POST /auth/register` → Admin (JWT Bearer requerido)
- `POST /auth/login`    → público
- `GET  /auth/me`       → cualquier usuario autenticado
    """,
)
def register(
    data: RegisterRequest,
    db: Session = Depends(get_db),
    _current_admin: User = Depends(require_admin),  # ◄─ RBAC: solo Admin crea usuarios
):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email ya registrado")

    user = User(
        email=data.email,
        full_name=data.full_name,
        password=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Iniciar sesión",
    description="Autenticación pública. Devuelve access token + refresh token + objeto user.",
)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email o contraseña incorrectos",
        )
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Usuario inactivo")

    return _build_token_response(user)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Renovar tokens",
    description="Rota el access token usando un refresh token válido.",
)
def refresh_token(data: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Refresh token inválido")

    user = db.query(User).filter(User.id == payload.get("sub")).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")

    return _build_token_response(user)


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Usuario actual",
    description="Devuelve los datos del usuario autenticado (cualquier rol).",
)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
