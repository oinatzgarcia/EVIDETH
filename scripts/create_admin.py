#!/usr/bin/env python3
"""
Crea el primer usuario admin de EVIDETH.
Ejecutar desde la raíz del proyecto: python scripts/create_admin.py
"""
import sys
import os
from pathlib import Path

# Añadir raíz al path para importar app
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db.session import SessionLocal
from app.db.models import User
from app.core.security import get_password_hash

def create_admin():
    db = SessionLocal()
    try:
        # Verificar si ya existe un admin
        existing = db.query(User).filter(User.email == "admin@evideth.io").first()
        if existing:
            print("❌ El usuario admin@evideth.io ya existe")
            return

        # Crear usuario admin
        admin = User(
            email="admin@evideth.io",
            username="admin",
            full_name="EVIDETH Administrator",
            hashed_password=get_password_hash("admin123"),  # ← CAMBIAR EN PRODUCCIÓN
            is_active=True,
            is_superuser=True,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)
        
        print("✅ Usuario admin creado:")
        print(f"   Email    : {admin.email}")
        print(f"   Password : admin123")
        print(f"   ID       : {admin.id}")
        print("\n⚠️  CAMBIAR la contraseña tras el primer login en producción")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin()
