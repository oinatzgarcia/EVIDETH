#!/usr/bin/env python3
"""
EVIDETH — seed_admin.py
Crea el primer usuario administrador del sistema.

Uso:
    python scripts/seed_admin.py
    python scripts/seed_admin.py --email otro@email.com --password OtraPass1!

El script es idempotente: si el email ya existe, no hace nada.
"""
import sys
import os
import argparse

# Asegurar que el root del proyecto está en el path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.session import SessionLocal, engine
from app.db import models
from app.db.models import User, UserRole
from app.core.security import hash_password
import uuid


def create_admin(email: str, password: str, full_name: str) -> None:
    # Crear tablas si no existen
    models.Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"⚠  Usuario ya existe: {email} (role={existing.role})")
            print("   Si quieres cambiar la contraseña, usa el panel de admin.")
            return

        admin = User(
            id=str(uuid.uuid4()),
            email=email,
            full_name=full_name,
            password=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        print(f"✅ Admin creado correctamente")
        print(f"   Email    : {admin.email}")
        print(f"   Nombre   : {admin.full_name}")
        print(f"   Rol      : {admin.role}")
        print(f"   ID       : {admin.id}")
        print(f"   URL login: https://evideth-dev-backend.icywave-c2a647eb.spaincentral.azurecontainerapps.io/frontend/pages/login/login.html")
    except Exception as e:
        db.rollback()
        print(f"❌ Error al crear el admin: {e}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crear primer admin de EVIDETH")
    parser.add_argument("--email",     default="admin@evideth.com")
    parser.add_argument("--password",  default="Admin1234!")
    parser.add_argument("--full-name", default="Administrador EVIDETH")
    args = parser.parse_args()

    print(f"Creando admin: {args.email}")
    create_admin(
        email=args.email,
        password=args.password,
        full_name=args.full_name,
    )
