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

from app.core.security import generate_api_key, hash_api_key, hash_password
from app.db.models import User, UserRole
from app.db.session import Base, get_db
from app.main import app

# ── Base de datos SQLite en memoria para tests ─────────────────────────────

SQLITE_URL = "sqlite:///./test_integration.db"

engine_test = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_test)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    """Crea tablas antes del módulo y las elimina al terminar."""
    Base.metadata.create_all(bind=engine_test)
    yield
    Base.metadata.drop_all(bind=engine_test)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def db_session():
    db = TestingSessionLocal()
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
        """
        GET /api/v1/health debe devolver 200 y status=healthy.
        Verifica que el servidor arranca y el probe de Azure funcionaría.
        """
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
        """
        POST /auth/login con credenciales válidas de admin devuelve
        access_token, refresh_token y objeto user con role=admin.
        """
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@evideth.com", "password": "Admin1234!"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["user"]["role"] == "admin"
        assert body["user"]["email"] == "admin@evideth.com"

    def test_login_wrong_password_returns_401(self, client, admin_user):
        """
        POST /auth/login con contraseña incorrecta debe devolver 401.
        Garantiza que la API no expone información sobre la existencia
        del usuario (mensaje genérico).
        """
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@evideth.com", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401

    def test_me_with_valid_token(self, client, admin_token):
        """
        GET /auth/me con JWT válido devuelve el perfil del usuario autenticado.
        Verifica que el token es correctamente decodificado y el usuario
        existe en la BD.
        """
        resp = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == "admin@evideth.com"
        assert body["role"] == "admin"

    def test_me_without_token_returns_401(self, client):
        """
        GET /auth/me sin Authorization header debe devolver 401.
        Protección básica de endpoint autenticado.
        """
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    def test_me_with_invalid_token_returns_401(self, client):
        """
        GET /auth/me con token malformado (no JWT válido) debe devolver 401.
        Verifica que el middleware de auth rechaza tokens inválidos.
        """
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
        """
        POST /cameras/ con token de Analyst debe devolver 403.
        El registro de cámaras está restringido a Admin (RBAC).
        """
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": "CAM-NOAUTH", "name": "No autorizado"},
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 403

    def test_analyst_can_list_cameras(self, client, analyst_token):
        """
        GET /cameras/ con token de Analyst debe devolver 200.
        Los analistas tienen acceso de lectura a cámaras.
        """
        resp = client.get(
            "/api/v1/cameras/",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "total" in body

    def test_unauthenticated_cannot_list_cameras(self, client):
        """
        GET /cameras/ sin autenticación debe devolver 401.
        Ninguna ruta de datos es pública excepto /auth/login.
        """
        resp = client.get("/api/v1/cameras/")
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# TEST 8-9: Gestión de cámaras
# ══════════════════════════════════════════════════════════════════════════════


class TestCameras:
    def test_admin_registers_camera(self, client, admin_token):
        """
        POST /cameras/ con Admin registra una cámara correctamente.
        La API Key se devuelve en texto plano UNA ÚNICA VEZ y no debe
        almacenarse en la BD (se guarda su hash bcrypt).
        """
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
        assert body["api_key"] is not None  # Solo se devuelve en la creación
        assert body["is_active"] is True

    def test_duplicate_camera_id_returns_400(self, client, admin_token):
        """
        POST /cameras/ con camera_id ya existente debe devolver 400.
        Garantiza la unicidad del identificador de cámara.
        """
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": "CAM-REGISTER-TEST", "name": "Duplicado"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 400

    def test_get_camera_by_id(self, client, admin_token, registered_camera):
        """
        GET /cameras/{camera_id} devuelve el detalle de la cámara.
        Verifica que los campos de metadata se persisten correctamente.
        """
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
        """
        POST /cameras/heartbeat con API Key válida actualiza last_seen.
        El heartbeat es el mecanismo de presencia de la cámara en el sistema.
        """
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["camera_id"] == registered_camera["camera_id"]

    def test_heartbeat_with_invalid_api_key_returns_401(self, client):
        """
        POST /cameras/heartbeat con API Key inválida debe devolver 401.
        Las API Keys se almacenan hasheadas; las inválidas no coinciden.
        """
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
        """
        POST /cameras/videos inicia una grabación de video.
        La cámara usa su API Key para autenticarse (no JWT).
        """
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
        """
        POST /cameras/segments con hash SHA-256 válido registra el segmento.
        Sin firma ECDSA el segmento queda en estado PENDING (no VALID),
        lo que es correcto para cámaras sin clave registrada.
        """
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
        assert body["status"] == "pending"  # Sin firma ECDSA → PENDING
        assert body["segment_index"] == 0

    def test_upload_duplicate_segment_returns_409(self, client, registered_camera, active_video_id):
        """
        POST /cameras/segments con segment_index duplicado debe devolver 409.
        Garantiza la inmutabilidad de los segmentos ya registrados —
        principio forense fundamental: ningún segmento se puede sobreescribir.
        """
        fake_hash = hashlib.sha256(b"test_segment_data_0").hexdigest()
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": active_video_id,
                "segment_index": 0,  # mismo índice → conflicto
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": fake_hash,
            },
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 409

    def test_invalid_sha256_format_returns_422(self, client, registered_camera, active_video_id):
        """
        POST /cameras/segments con sha256_hash malformado debe devolver 422.
        Pydantic valida que el hash sea exactamente 64 caracteres hexadecimales.
        Cualquier hash truncado o con caracteres inválidos es rechazado.
        """
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": active_video_id,
                "segment_index": 99,
                "start_time_secs": 990,
                "end_time_secs": 1020,
                "sha256_hash": "este-no-es-un-hash-valido",  # formato inválido
            },
            headers={"X-API-Key": registered_camera["api_key"]},
        )
        assert resp.status_code == 422
