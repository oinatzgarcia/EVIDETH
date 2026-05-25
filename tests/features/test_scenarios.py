"""
tests/features/test_scenarios.py
================================
Tests de características (Feature Tests / Acceptance Tests) de EVIDETH.

Verifican flujos de usuario completos de punta a punta a través de la
API HTTP, tal como los ejecutaría un analista forense o un sistema
automático de monitoreo.

A diferencia de los tests de integración (test_api.py), estos tests:
  - Representan casos de uso reales del sistema ("el analista quiere...")
  - Encadenan varias llamadas HTTP en secuencia
  - Verifican el estado final completo del sistema, no solo el código HTTP

Escenarios cubiertos:
  1. Alta y ciclo de vida de una cámara (registro → heartbeat → desactivación)
  2. Flujo forense completo (cámara → video → segmentos → consulta de integridad)
  3. Rotación de acceso (admin crea analyst, analyst opera, admin revoca)
  4. Rechazo de datos inválidos (la API nunca acepta hashes malformados)
  5. Multi-cámara (dos cámaras operan en paralelo sin interferencias)

Ejecución:
    SECRET_KEY=test DATABASE_URL=sqlite:///./test_features.db JWT_SECRET_KEY=test \\
    python -m pytest tests/features/test_scenarios.py -v

    # Un escenario concreto:
    python -m pytest tests/features/test_scenarios.py::TestScenario3Rbac -v
"""

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.security import hash_password
from app.db.models import User, UserRole
from app.db.session import Base, get_db
from app.main import app

# ── Infraestructura compartida ───────────────────────────────────────────

SQLITE_URL = "sqlite:///./test_features.db"

engine_test = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_test)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="module", autouse=True)
def setup_db():
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
def admin_token(client, db_session):
    """Crea un admin y devuelve su JWT."""
    user = User(
        email="admin@features.evideth.com",
        full_name="Admin Features",
        password=hash_password("Admin1234!"),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@features.evideth.com", "password": "Admin1234!"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


def _valid_sha256() -> str:
    """Genera un hash SHA-256 válido de 64 caracteres hex."""
    return hashlib.sha256(uuid.uuid4().bytes).hexdigest()


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
# ESCENARIO 1 — Alta y ciclo de vida de una cámara
#
# Actores: Administrador
# Flujo: registrar cámara → verificar que aparece en el listado → heartbeat
#        → desactivar → verificar que el heartbeat ya no funciona
#
# Propósito: validar que el ciclo de vida completo de una cámara en EVIDETH
# funciona correctamente, incluyendo la desactivación como mecanismo de
# revocación de acceso (principio de menor privilegio, NIST SP 800-53 AC-2).
# ══════════════════════════════════════════════════════════════════════════════


class TestScenario1CameraLifecycle:
    """
    Escenario 1: Alta y ciclo de vida completo de una cámara.

    Un administrador registra una cámara, comprueba que aparece en el
    sistema, realiza un heartbeat y finalmente la desactiva. Una vez
    desactivada, la cámara no puede enviar más datos.
    """

    camera_id = "CAM-FEAT-LIFECYCLE-001"

    def test_step1_register_camera(self, client, admin_token):
        """
        Paso 1: El admin registra la cámara y recibe la API Key en claro.
        La API Key solo se devuelve en este momento (no recuperable después).
        """
        resp = client.post(
            "/api/v1/cameras/",
            json={
                "camera_id": self.camera_id,
                "name": "Cámara Pasillo B",
                "location": "Planta 2 — Pasillo B",
            },
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["camera_id"] == self.camera_id
        assert body["is_active"] is True
        assert "api_key" in body and body["api_key"] is not None
        # Guardamos la API Key para los siguientes pasos
        TestScenario1CameraLifecycle._api_key = body["api_key"]

    def test_step2_camera_appears_in_list(self, client, admin_token):
        """
        Paso 2: La cámara recién registrada aparece en el listado.
        Verifica la persistencia y la correcta paginación de la respuesta.
        """
        resp = client.get("/api/v1/cameras/", headers=_auth(admin_token))
        assert resp.status_code == 200
        body = resp.json()
        camera_ids = [c["camera_id"] for c in body["items"]]
        assert self.camera_id in camera_ids

    def test_step3_heartbeat_succeeds(self, client):
        """
        Paso 3: La cámara activa puede enviar heartbeats con su API Key.
        El heartbeat actualiza last_seen y confirma que la cámara está online.
        """
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": TestScenario1CameraLifecycle._api_key},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
        assert resp.json()["camera_id"] == self.camera_id

    def test_step4_deactivate_camera(self, client, admin_token):
        """
        Paso 4: El admin desactiva la cámara (baja lógica, no borrado físico).
        Los datos históricos se preservan para auditoría forense.
        """
        resp = client.patch(
            f"/api/v1/cameras/{self.camera_id}/deactivate",
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    def test_step5_heartbeat_rejected_after_deactivation(self, client):
        """
        Paso 5: La cámara desactivada no puede enviar heartbeats.
        Su API Key sigue siendo válida criptográficamente, pero el sistema
        rechaza las peticiones de cámaras inactivas (401).
        """
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": TestScenario1CameraLifecycle._api_key},
        )
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# ESCENARIO 2 — Flujo forense completo de captura de segmentos
#
# Actores: Cámara (API Key) + Analista (JWT)
# Flujo: cámara inicia video → envía 3 segmentos con hashes SHA-256
#        → analista consulta el estado de integridad del video
#
# Propósito: validar el flujo principal de captura forense de EVIDETH.
# Los hashes SHA-256 son la raíz de la cadena de custodia digital
# (NIST SP 800-101 Rev.1, sección 5.2 — Hash verification).
# ══════════════════════════════════════════════════════════════════════════════


class TestScenario2ForensicCaptureFlow:
    """
    Escenario 2: Flujo forense completo de captura de segmentos.

    Una cámara activa registra un video y envía 3 segmentos consecutivos
    de 30 segundos con sus hashes SHA-256. Un analista consulta después
    los segmentos del video para verificar la cobertura temporal.
    """

    camera_id = "CAM-FEAT-FORENSIC-001"
    segments_hashes = [_valid_sha256() for _ in range(3)]

    def test_step1_register_camera_for_capture(self, client, admin_token):
        """Registro inicial de la cámara forense."""
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": self.camera_id, "name": "Cámara Forense 01", "location": "Sala de servidores"},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201
        TestScenario2ForensicCaptureFlow._api_key = resp.json()["api_key"]

    def test_step2_camera_starts_video(self, client):
        """La cámara inicia una grabación. El sistema crea el registro de video."""
        resp = client.post(
            "/api/v1/cameras/videos",
            json={"filename": "sala_servidores_20260525.mp4", "fps": 25.0, "resolution": "1920x1080"},
            headers={"X-API-Key": TestScenario2ForensicCaptureFlow._api_key},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "recording"
        TestScenario2ForensicCaptureFlow._video_id = body["id"]

    def test_step3_camera_uploads_three_segments(self, client):
        """
        La cámara envía 3 segmentos consecutivos de 30 segundos.
        Cada segmento incluye su hash SHA-256 calculado sobre el archivo de video.
        Los 3 deben ser aceptados (HTTP 201) y quedar en estado PENDING.
        """
        video_id = TestScenario2ForensicCaptureFlow._video_id
        api_key = TestScenario2ForensicCaptureFlow._api_key

        for i, sha in enumerate(self.segments_hashes):
            resp = client.post(
                "/api/v1/cameras/segments",
                json={
                    "video_id": video_id,
                    "segment_index": i,
                    "start_time_secs": i * 30,
                    "end_time_secs": (i + 1) * 30,
                    "sha256_hash": sha,
                },
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 201, f"Segmento {i} falló: {resp.json()}"
            body = resp.json()
            assert body["segment_index"] == i
            assert body["sha256_hash"] == sha
            assert body["status"] == "pending"

    def test_step4_analyst_queries_video_segments(self, client, admin_token):
        """
        El analista consulta los segmentos del video y verifica:
        - Los 3 segmentos están presentes
        - La cobertura temporal es continua (0-30, 30-60, 60-90)
        - Los hashes coinciden con los enviados por la cámara
        """
        video_id = TestScenario2ForensicCaptureFlow._video_id
        resp = client.get(
            f"/api/v1/cameras/videos/{video_id}/segments",
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200
        segments = resp.json()["items"] if "items" in resp.json() else resp.json()
        assert len(segments) == 3

        # Verificar cobertura temporal continua
        sorted_segs = sorted(segments, key=lambda s: s["segment_index"])
        for i, seg in enumerate(sorted_segs):
            assert seg["start_time_secs"] == i * 30
            assert seg["end_time_secs"] == (i + 1) * 30
            assert seg["sha256_hash"] == self.segments_hashes[i]


# ══════════════════════════════════════════════════════════════════════════════
# ESCENARIO 3 — Rotación de acceso (RBAC operacional)
#
# Actores: Administrador + Analista
# Flujo: admin crea analista → analista consulta datos → admin desactiva analista
#        → analista ya no puede operar
#
# Propósito: validar el modelo de control de acceso de EVIDETH.
# Aplica el principio de acceso mínimo y revocación inmediata
# (OWASP ASVS v4.0 §4.2 — Operation Level Access Control).
# ══════════════════════════════════════════════════════════════════════════════


class TestScenario3Rbac:
    """
    Escenario 3: Rotación de acceso y revocación de un analista.

    El admin crea un nuevo analista, éste opera correctamente y después
    el admin le revoca el acceso. El analista no puede seguir operando
    aunque su JWT no haya expirado (revocación en el estado del usuario).
    """

    analyst_email = "perito@features.evideth.com"
    analyst_password = "Perito1234!"

    def test_step1_admin_creates_analyst(self, client, admin_token):
        """
        El admin crea una cuenta de analista forense a través de la API.
        """
        resp = client.post(
            "/api/v1/users/",
            json={
                "email": self.analyst_email,
                "full_name": "Períto Forense",
                "password": self.analyst_password,
                "role": "analyst",
            },
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == self.analyst_email
        assert body["role"] == "analyst"
        assert body["is_active"] is True
        TestScenario3Rbac._analyst_id = body["id"]

    def test_step2_analyst_logs_in(self, client):
        """
        El analista se autentica y obtiene un JWT válido.
        """
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": self.analyst_email, "password": self.analyst_password},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["user"]["role"] == "analyst"
        TestScenario3Rbac._analyst_token = body["access_token"]

    def test_step3_analyst_can_read_cameras(self, client):
        """
        El analista activo puede consultar la lista de cámaras (operación de lectura).
        """
        resp = client.get(
            "/api/v1/cameras/",
            headers=_auth(TestScenario3Rbac._analyst_token),
        )
        assert resp.status_code == 200

    def test_step4_analyst_cannot_delete_user(self, client):
        """
        El analista no puede gestionar usuarios (operación solo de ADMIN).
        Verifica el principio de menor privilegio.
        """
        resp = client.delete(
            f"/api/v1/users/{TestScenario3Rbac._analyst_id}",
            headers=_auth(TestScenario3Rbac._analyst_token),
        )
        assert resp.status_code == 403

    def test_step5_admin_deactivates_analyst(self, client, admin_token):
        """
        El admin desactiva la cuenta del analista.
        La desactivación es inmediata: aunque el JWT no haya expirado,
        el usuario no puede acceder al sistema.
        """
        resp = client.patch(
            f"/api/v1/users/{TestScenario3Rbac._analyst_id}/deactivate",
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    def test_step6_deactivated_analyst_cannot_operate(self, client):
        """
        El analista desactivado no puede operar aunque tenga un JWT válido.
        El sistema comprueba is_active en cada petición, no solo en el login.
        Esto garantiza revocación inmediata sin necesidad de esperar a que
        el token expire (protección frente a tokens comprometidos).
        """
        resp = client.get(
            "/api/v1/cameras/",
            headers=_auth(TestScenario3Rbac._analyst_token),
        )
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# ESCENARIO 4 — Blindaje de integridad (rechazo de datos inválidos)
#
# Actores: Cámara (API Key)
# Flujo: la cámara intenta enviar hashes malformados, duplicados o con
#        parámetros fuera de rango — la API los rechaza siempre
#
# Propósito: verificar que el sistema no acepta datos corruptos o
# maliciosos que podrían invalidar la cadena de custodia digital.
# (OWASP ASVS v4.0 §5.1 — Input Validation)
# ══════════════════════════════════════════════════════════════════════════════


class TestScenario4DataIntegrityGuard:
    """
    Escenario 4: Blindaje de integridad — rechazo de datos inválidos.

    Verifica que la API de EVIDETH rechaza cualquier dato que pueda
    comprometer la cadena de custodia forense, incluyendo hashes
    malformados, segmentos duplicados y parámetros fuera de rango.
    """

    camera_id = "CAM-FEAT-GUARD-001"

    def test_step1_setup_camera_and_video(self, client, admin_token):
        """Configuración: registrar cámara e iniciar video para los tests."""
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": self.camera_id, "name": "Cámara Blindaje", "location": "Lab"},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201
        api_key = resp.json()["api_key"]
        TestScenario4DataIntegrityGuard._api_key = api_key

        resp = client.post(
            "/api/v1/cameras/videos",
            json={"filename": "guard_test.mp4", "fps": 25.0},
            headers={"X-API-Key": api_key},
        )
        assert resp.status_code == 201
        TestScenario4DataIntegrityGuard._video_id = resp.json()["id"]

    def test_step2_reject_truncated_hash(self, client):
        """
        La API rechaza un hash SHA-256 truncado (< 64 caracteres).
        Un hash incompleto no puede garantizar integridad del segmento.
        """
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": "abc123",  # solo 6 chars — inválido
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422

    def test_step3_reject_non_hex_hash(self, client):
        """
        La API rechaza un hash con caracteres no hexadecimales.
        SHA-256 solo produce dígitos 0-9 y letras a-f.
        """
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": "z" * 64,  # 64 chars pero no hex
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422

    def test_step4_accept_valid_segment(self, client):
        """
        Con datos correctos el segmento se acepta (baseline de los rechazos anteriores).
        """
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 201

    def test_step5_reject_duplicate_segment(self, client):
        """
        La API rechaza un segundo intento de registrar el mismo segment_index.
        La inmutabilidad de los segmentos es un principio forense fundamental:
        ningún dato almacenado puede sobrescribirse (HTTP 409 Conflict).
        """
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,  # ya existe — conflicto
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 409

    def test_step6_reject_negative_time_range(self, client):
        """
        La API rechaza un segmento con end_time <= start_time.
        Un rango temporal inválido indica datos corruptos o manipulados.
        """
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 99,
                "start_time_secs": 60,
                "end_time_secs": 30,  # end < start — inválido
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# ESCENARIO 5 — Operación multi-cámara sin interferencias
#
# Actores: Dos cámaras independientes (API Keys distintas)
# Flujo: dos cámaras operan en paralelo — cada una tiene su video y
#        sus segmentos; los datos no se mezclan entre cámaras
#
# Propósito: verificar el aislamiento de datos entre cámaras.
# Cada cámara tiene su propio espacio de nombres lógico;
# los segmentos de una cámara no son accesibles ni modificables
# desde otra (aislamiento de tenant).
# ══════════════════════════════════════════════════════════════════════════════


class TestScenario5MultiCamera:
    """
    Escenario 5: Operación de dos cámaras en paralelo sin interferencias.

    Verifica que el sistema acomoda múltiples cámaras simultáneas y que
    los datos de cada una permanecen aislados: una cámara no puede enviar
    segmentos al video de otra cámara.
    """

    cam_a_id = "CAM-FEAT-MULTI-A"
    cam_b_id = "CAM-FEAT-MULTI-B"

    def test_step1_register_two_cameras(self, client, admin_token):
        """El admin registra dos cámaras independientes."""
        for cam_id in (self.cam_a_id, self.cam_b_id):
            resp = client.post(
                "/api/v1/cameras/",
                json={"camera_id": cam_id, "name": f"Multi Cam {cam_id}", "location": "Planta 1"},
                headers=_auth(admin_token),
            )
            assert resp.status_code == 201
            attr = f"_api_key_{cam_id.split('-')[-1].lower()}"
            setattr(TestScenario5MultiCamera, attr, resp.json()["api_key"])

    def test_step2_each_camera_starts_own_video(self, client):
        """Cada cámara inicia su propio video de forma independiente."""
        for cam_id in (self.cam_a_id, self.cam_b_id):
            suffix = cam_id.split("-")[-1].lower()
            api_key = getattr(TestScenario5MultiCamera, f"_api_key_{suffix}")
            resp = client.post(
                "/api/v1/cameras/videos",
                json={"filename": f"video_{suffix}.mp4", "fps": 25.0},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 201
            setattr(TestScenario5MultiCamera, f"_video_id_{suffix}", resp.json()["id"])

    def test_step3_cameras_upload_segments_independently(self, client):
        """
        Cada cámara sube segmentos a su propio video.
        Los hashes son distintos entre cámaras (diferentes escenas).
        """
        for cam_id in (self.cam_a_id, self.cam_b_id):
            suffix = cam_id.split("-")[-1].lower()
            api_key = getattr(TestScenario5MultiCamera, f"_api_key_{suffix}")
            video_id = getattr(TestScenario5MultiCamera, f"_video_id_{suffix}")

            for i in range(2):
                resp = client.post(
                    "/api/v1/cameras/segments",
                    json={
                        "video_id": video_id,
                        "segment_index": i,
                        "start_time_secs": i * 30,
                        "end_time_secs": (i + 1) * 30,
                        "sha256_hash": _valid_sha256(),
                    },
                    headers={"X-API-Key": api_key},
                )
                assert resp.status_code == 201, \
                    f"Cámara {cam_id}, segmento {i}: {resp.json()}"

    def test_step4_camera_b_cannot_write_to_camera_a_video(self, client):
        """
        La cámara B no puede enviar segmentos al video de la cámara A.
        El sistema valida que la API Key pertenece a la cámara propietaria
        del video, garantizando el aislamiento de datos entre cámaras.
        """
        video_id_a = TestScenario5MultiCamera._video_id_a
        api_key_b = TestScenario5MultiCamera._api_key_b

        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": video_id_a,       # video de cámara A
                "segment_index": 99,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": api_key_b},  # pero API Key de cámara B
        )
        # El sistema debe rechazar la operación (403 o 401)
        assert resp.status_code in (401, 403), \
            f"Cámara B no debería poder escribir en video de cámara A: {resp.status_code}"

    def test_step5_verify_segment_counts_are_independent(self, client, admin_token):
        """
        Cada video tiene exactamente sus propios 2 segmentos.
        Los conteos no se mezclan entre cámaras.
        """
        for cam_id in (self.cam_a_id, self.cam_b_id):
            suffix = cam_id.split("-")[-1].lower()
            video_id = getattr(TestScenario5MultiCamera, f"_video_id_{suffix}")
            resp = client.get(
                f"/api/v1/cameras/videos/{video_id}/segments",
                headers=_auth(admin_token),
            )
            assert resp.status_code == 200
            segments = resp.json().get("items", resp.json())
            assert len(segments) == 2, \
                f"Cámara {cam_id} debería tener 2 segmentos, tiene {len(segments)}"
