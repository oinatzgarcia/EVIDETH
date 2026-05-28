"""
tests/integration/test_api.py
==============================
Tests de integración de la API REST de EVIDETH.

Cubren los flujos principales del sistema:
  - Auth: login, token inválido, /me, RBAC
  - Health: endpoint de disponibilidad
  - Cameras: registro, listado, heartbeat, segmentos
  - RBAC: protección de rutas por rol

Usan TestClient de FastAPI (HTTPX) con base de datos SQLite
en memoria — sin dependencia de PostgreSQL ni Azure.

Ejecución:
    pytest tests/integration/test_api.py -v
"""

import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import hash_password
from app.db.models import User, UserRole
from app.db.session import Base, get_db
from app.main import app

# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def client():
    """
    TestClient con BD SQLite en memoria compartida para todo el módulo.
    StaticPool hace que todas las conexiones usen el mismo objeto en memoria.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        c._test_session_local = SessionLocal
        yield c

    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="module")
def db_session(client):
    """Sesión directa a la BD de test (misma que el client usa)."""
    SessionLocal = client._test_session_local
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture(scope="module")
def admin_user(db_session):
    """Crea un usuario Admin en la BD de test."""
    user = User(
        email="admin@evideth.com",
        full_name="Admin Test",
        password=hash_password("Admin1234!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="module")
def analyst_user(db_session):
    """Crea un usuario Analyst en la BD de test."""
    user = User(
        email="analyst@evideth.com",
        full_name="Analyst Test",
        password=hash_password("Analyst1234!"),
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="module")
def admin_token(client, admin_user):
    """Devuelve el JWT de acceso del admin."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@evideth.com", "password": "Admin1234!"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def analyst_token(client, analyst_user):
    """Devuelve el JWT de acceso del analyst."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst@evideth.com", "password": "Analyst1234!"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def registered_camera(client, admin_token):
    """Registra una cámara como Admin y devuelve {camera_id, api_key}."""
    resp = client.post(
        "/api/v1/cameras/",
        json={"camera_id": "CAM-INT-001", "name": "Camara Integración", "location": "Pasillo A"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    return {"camera_id": data["camera_id"], "api_key": data["api_key"]}


@pytest.fixture(scope="module")
def active_video_id(client, registered_camera):
    """Inicia una grabación de video y devuelve el video_id."""
    resp = client.post(
        "/api/v1/cameras/videos",
        json={"filename": "test_integration_video.mp4", "fps": 25.0, "resolution": "1920x1080"},
        headers={"X-API-Key": registered_camera["api_key"]},
    )
    assert resp.status_code == 201
    return resp.json()["id"]


# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: Health check
# ══════════════════════════════════════════════════════════════════════════════


class TestHealth:
    def test_health_returns_200(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "version" in body


# ══════════════════════════════════════════════════════════════════════════════
# TEST 2-4: Autenticación
# ══════════════════════════════════════════════════════════════════════════════


class TestAuth:
    def test_login_admin_returns_jwt(self, client, admin_user):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@evideth.com", "password": "Admin1234!"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"
        assert body["user"]["role"] == "admin"
        assert body["user"]["email"] == "admin@evideth.com"

    def test_login_wrong_password_returns_401(self, client, admin_user):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@evideth.com", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    def test_me_with_valid_token(self, client, admin_token):
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == "admin@evideth.com"
        assert body["role"] == "admin"

    def test_me_without_token_returns_401(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_me_with_invalid_token_returns_401(self, client):
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer este.no.esuntoken"},
        )
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# TEST 5-7: RBAC — Control de acceso basado en roles
# ══════════════════════════════════════════════════════════════════════════════


class TestRBAC:
    def test_analyst_cannot_register_camera(self, client, analyst_token):
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": "CAM-NOAUTH", "name": "No autorizado"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 403

    def test_analyst_can_list_cameras(self, client, analyst_token):
        resp = client.get(
            "/api/v1/cameras/",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "total" in body

    def test_unauthenticated_cannot_list_cameras(self, client):
        resp = client.get("/api/v1/cameras/")
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# TEST 8-9: Gestión de cámaras
# ══════════════════════════════════════════════════════════════════════════════


class TestCameras:
    def test_admin_registers_camera(self, client, admin_token):
        resp = client.post(
            "/api/v1/cameras/",
            json={
                "camera_id": "CAM-REGISTER-TEST",
                "name": "Test Registration",
                "location": "Entrada principal",
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["camera_id"] == "CAM-REGISTER-TEST"
        assert "api_key" in body
        assert body["api_key"] is not None
        assert body["is_active"] is True

    def test_duplicate_camera_id_returns_400(self, client, admin_token):
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": "CAM-REGISTER-TEST", "name": "Duplicado"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 400

    def test_get_camera_by_id(self, client, admin_token, registered_camera):
        camera_id = registered_camera["camera_id"]
        resp = client.get(
            f"/api/v1/cameras/{camera_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["camera_id"] == camera_id
        assert body["location"] == "Pasillo A"

    def test_camera_heartbeat_with_api_key(self, client, registered_camera):
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["camera_id"] == registered_camera["camera_id"]

    def test_heartbeat_with_invalid_api_key_returns_401(self, client):
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": "evideth_invalidkey000000000000000000000000000000"},
        )
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# TEST 10-12: Segmentos — flujo de captura forense
# ══════════════════════════════════════════════════════════════════════════════


class TestSegments:
    def test_start_video_with_api_key(self, client, registered_camera):
        resp = client.post(
            "/api/v1/cameras/videos",
            json={"filename": "test_segment_video.mp4", "fps": 30.0},
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "recording"
        assert body["filename"] == "test_segment_video.mp4"

    def test_upload_segment_minimal(self, client, registered_camera, active_video_id):
        fake_hash = hashlib.sha256(b"test_segment_data_0").hexdigest()
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": active_video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": fake_hash,
            },
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["sha256_hash"] == fake_hash
        assert body["status"] == "pending"
        assert body["segment_index"] == 0

    def test_upload_duplicate_segment_returns_409(self, client, registered_camera, active_video_id):
        fake_hash = hashlib.sha256(b"test_segment_data_0").hexdigest()
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": active_video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": fake_hash,
            },
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 409

    def test_invalid_sha256_format_returns_422(self, client, registered_camera, active_video_id):
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": active_video_id,
                "segment_index": 99,
                "start_time_secs": 990,
                "end_time_secs": 1020,
                "sha256_hash": "este-no-es-un-hash-valido",
            },
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 422
