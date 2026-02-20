from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
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
    }
)


# ── Schemas ─────────────────────────────────────────

class UserUpdate(BaseModel):
    """
    Campos opcionales para actualizar un usuario.
    Solo se actualizan los campos que se incluyan en la petición.
    """
    full_name: Optional[str]  = None
    email:     Optional[EmailStr] = None
    password:  Optional[str]  = None
    role:      Optional[UserRole] = None    # Solo Admin
    is_active: Optional[bool] = None        # Solo Admin


class UserListResponse(BaseModel):
    """Respuesta paginada para listado de usuarios."""
    total:    int
    page:     int
    per_page: int
    pages:    int
    items:    list[UserResponse]


# ── 1. Listar usuarios ─────────────────────────────

@router.get(
    "/",
    response_model=UserListResponse,
    summary="Listar usuarios",
    description="""
Devuelve todos los usuarios del sistema con paginación y filtros opcionales.
Solo **Admin**.

Filtros disponibles:
- `role`: filtrar por rol (`admin`, `analyst`, `viewer`)
- `is_active`: filtrar por estado activo/inactivo
- `page` / `per_page`: paginación
    """
)
def list_users(
    role:      Optional[UserRole] = None,
    is_active: Optional[bool]     = None,
    page:      int                = 1,
    per_page:  int                = 20,
    db:        Session            = Depends(get_db),
    current_user: User            = Depends(require_admin)
):
    query = db.query(User)

    if role is not None:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    total = query.count()
    users = query.order_by(User.created_at.desc()) \
        .offset((page - 1) * per_page).limit(per_page).all()

    return UserListResponse(
        total=total,
        page=page,
        per_page=per_page,
        pages=(total + per_page - 1) // per_page,
        items=users
    )


# ── 2. Obtener usuario por ID ───────────────────────

@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Obtener usuario por ID",
    description="""
Devuelve los datos de un usuario específico.
- **Admin**: puede ver cualquier usuario
- **Cualquier usuario**: solo puede verse a sí mismo
    """
)
def get_user(
    user_id:  str,
    db:       Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != UserRole.ADMIN and str(current_user.id) != user_id:
        raise HTTPException(
            status_code=403,
            detail="No tienes permisos para ver este usuario"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user


# ── 3. Actualizar usuario ─────────────────────────

@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    summary="Actualizar usuario",
    description="""
Actualiza campos de un usuario (PATCH — solo se envían los campos a cambiar).

- **Admin**: puede cambiar cualquier campo de cualquier usuario, incluidos `role` e `is_active`
- **Cualquier usuario**: puede cambiar `full_name`, `email` y `password` de su propia cuenta
    """
)
def update_user(
    user_id:  str,
    data:     UserUpdate,
    db:       Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    is_admin = current_user.role == UserRole.ADMIN
    is_self  = str(current_user.id) == user_id

    if not is_admin and not is_self:
        raise HTTPException(
            status_code=403,
            detail="No tienes permisos para modificar este usuario"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Campos editables por cualquier usuario (sobre sí mismo)
    if data.full_name is not None:
        user.full_name = data.full_name

    if data.email is not None:
        conflict = db.query(User).filter(
            User.email == data.email,
            User.id    != user_id
        ).first()
        if conflict:
            raise HTTPException(status_code=400, detail="Email ya en uso")
        user.email = data.email

    if data.password is not None:
        user.password = hash_password(data.password)

    # Campos exclusivos de Admin
    if (data.role is not None or data.is_active is not None) and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="Solo Admin puede cambiar el rol o el estado activo"
        )

    if is_admin:
        if data.role is not None:
            user.role = data.role
        if data.is_active is not None:
            user.is_active = data.is_active

    db.commit()
    db.refresh(user)
    return user


# ── 4. Desactivar usuario (soft delete) ─────────────

@router.delete(
    "/{user_id}",
    status_code=200,
    summary="Desactivar usuario",
    description="""
Desactiva un usuario (soft delete — no se elimina de BD, solo se marca como inactivo).

- No se puede desactivar la propia cuenta del Admin que hace la petición
- Solo **Admin**
    """
)
def deactivate_user(
    user_id:  str,
    db:       Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    if str(current_user.id) == user_id:
        raise HTTPException(
            status_code=400,
            detail="No puedes desactivar tu propia cuenta"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="El usuario ya está inactivo")

    user.is_active = False
    db.commit()
    return {"detail": f"Usuario {user.email} desactivado correctamente"}
