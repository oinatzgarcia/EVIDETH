from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from app.db.models import UserRole
from uuid import UUID

# ── Request schemas ───────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: UserRole = UserRole.VIEWER

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

# ── Response schemas ──────────────────────
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: UserRole
    is_active: bool

    @field_validator('id', mode='before')   # ← convierte UUID → str automáticamente
    @classmethod
    def uuid_to_str(cls, v):
        return str(v)

    model_config = {"from_attributes": True}  # ← Pydantic v2 (reemplaza class Config)
