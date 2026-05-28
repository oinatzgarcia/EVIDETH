from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel, EmailStr

from app.db.session import get_db
from app.db.models import User, UserRole
from app.core.security import hash_password
from app.core.dependencies import require_admin, get_current_user
from app.schemas.auth import UserResponse


router = APIRouter(
    prefix="/users",
    tags=["Users"],
    responses={
        401: {"description": "JWT inválido"},
        403: {"description": "Sin permisos suficientes"},
    },
)


# ── Schemas ──────────────────────────────────────────────────


class UserCreate(BaseModel):
    """
    Payload para que el Admin cree un nuevo usuario en el sistema.
    La contraseña se almacena siempre como hash bcrypt.
    """

    email: EmailStr
    full_name: str
    password: str
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    """
    Campos opcionales para actualizar un usuario.
    Solo se actualizan los campos que se incluyan en la petición.
    """

    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserListResponse(BaseModel):
    """Respuesta paginada para listado de usuarios."""

    total: int
    page: int
    per_page: int
    pages: int
    items: list[UserResponse]


# ── 1. Crear usuario (Admin) ─────────────────────────────────


@router.post(
    "/",
    response_model=UserResponse,
    status_code=201,
    summary="Crear usuario",
    description="""
Crea un nuevo usuario en el sistema. Solo **Admin**.

El campo `role` admite: `admin`, `analyst`, `viewer`.
La contraseña se almacena como hash bcrypt — nunca en claro.
    """,
)
def create_user(
    data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email ya registrado")

    user = User(
        email=data.email,
        full_name=data.full_name,
        password=hash_password(data.password),
        role=data.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ── 2. Listar usuarios (Admin) ───────────────────────────────


@router.get(
    "/",
    response_model=UserListResponse,
    summary="Listar usuarios",
)
def list_users(
    role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
    page: int = 1,
    per_page: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    query = db.query(User)
    if role is not None:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    total = query.count()
    users = (
        query.order_by(User.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return UserListResponse(
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page,
        items=users,
    )


# ── 3. Obtener usuario por ID ────────────────────────────────


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Obtener usuario por ID",
)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != UserRole.ADMIN and str(current_user.id) != user_id:
        raise HTTPException(
            status_code=403, detail="No tienes permisos para ver este usuario"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user


# ── 4. Actualizar usuario ────────────────────────────────────


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Actualizar usuario",
)
def update_user(
    user_id: str,
    data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    is_admin = current_user.role == UserRole.ADMIN
    is_self = str(current_user.id) == user_id

    if not is_admin and not is_self:
        raise HTTPException(
            status_code=403, detail="No tienes permisos para modificar este usuario"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    if data.full_name is not None:
        user.full_name = data.full_name

    if data.email is not None:
        conflict = (
            db.query(User).filter(User.email == data.email, User.id != user_id).first()
        )
        if conflict:
            raise HTTPException(status_code=400, detail="Email ya en uso")
        user.email = data.email

    if data.password is not None:
        user.password = hash_password(data.password)

    if (data.role is not None or data.is_active is not None) and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Solo Admin puede cambiar el rol o el estado activo",
        )

    if is_admin:
        if data.role is not None:
            user.role = data.role
        if data.is_active is not None:
            user.is_active = data.is_active

    db.commit()
    db.refresh(user)
    return user


# ── 5. Desactivar usuario — PATCH /deactivate (Admin) ────────
#
# Alias REST semántico coexistente con DELETE /{user_id}.
# El test de RBAC (Escenario 3) usa este endpoint para verificar
# que la revocación es inmediata incluso con JWT vigente.


@router.patch(
    "/{user_id}/deactivate",
    status_code=200,
    summary="Desactivar usuario (PATCH)",
    description="""
Desactiva un usuario (soft delete). La sesión activa queda revocada
inmediatamente: el middleware `get_current_user` comprueba `is_active`
en cada petición, no solo en el login. Solo **Admin**.
    """,
)
def deactivate_user_patch(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if str(current_user.id) == user_id:
        raise HTTPException(
            status_code=400, detail="No puedes desactivar tu propia cuenta"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="El usuario ya está inactivo")

    user.is_active = False
    db.commit()
    return {
        "detail": f"Usuario {user.email} desactivado correctamente",
        "user_id": user_id,
        "is_active": False,
    }


# ── 6. Desactivar usuario — DELETE (Admin) ───────────────────


@router.delete(
    "/{user_id}",
    status_code=200,
    summary="Desactivar usuario (DELETE)",
)
def deactivate_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if str(current_user.id) == user_id:
        raise HTTPException(
            status_code=400, detail="No puedes desactivar tu propia cuenta"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="El usuario ya está inactivo")

    user.is_active = False
    db.commit()
    return {"detail": f"Usuario {user.email} desactivado correctamente"}
