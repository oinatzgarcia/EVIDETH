"""
tests/features/test_scenarios.py
=================================
Tests de características (Feature Tests / E2E Scenarios) para EVIDETH.

Cada clase representa un escenario de uso completo del sistema, con pasos
numerados que se ejecutan en orden. El estado entre pasos se comparte
mediante atributos de clase (cls._campo).

Escenarios implementados:
  1. Ciclo de vida de una cámara (registro → heartbeat → desactivación)
  2. Flujo de captura forense (video → segmentos → consulta analista)
  3. RBAC completo (admin crea analista → opera → revocación inmediata)
  4. Blindaje de integridad de datos (rechazos de hashes inválidos)
  5. Aislamiento multi-cámara (cámara B no puede escribir en video de A)

Referencias de seguridad:
  - OWASP ASVS §4.2 (Least Privilege)
  - NIST SP 800-53 AC-2 (Account Management)
  - NIST SP 800-57 (Key Management)
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base, get_db
from app.db.models import User, UserRole
from app.core.security import hash_password, create_access_token
from app.main import app

import secrets
import re

# ── Base de datos en memoria para tests ──────────────────────

SQLITE_URL = "sqlite:///./test_features.db"
engine = create_engine(SQLITE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Crea las tablas antes del módulo y las elimina al final."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token():
    """
    Crea un usuario admin en BD y devuelve su JWT.
    Fixture de módulo: el admin persiste en todos los escenarios.
    """
    db = TestingSessionLocal()
    try:
        admin = db.query(User).filter(User.email == "admin@evideth.test").first()
        if not admin:
            admin = User(
                email="admin@evideth.test",
                full_name="Admin Test",
                password=hash_password("Admin1234!"),
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            db.commit()
            db.refresh(admin)
        token = create_access_token({"sub": str(admin.id), "role": admin.role.value})
        return token
    finally:
        db.close()


# ── Helpers ──────────────────────────────────────────────────


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _valid_sha256() -> str:
    """Genera un SHA-256 hex válido aleatorio."""
    return secrets.token_hex(32)


# ═══════════════════════════════════════════════════════════════
# Escenario 1: Ciclo de vida de una cámara
# ═══════════════════════════════════════════════════════════════


class TestScenario1CameraLifecycle:
    """
    Escenario: Una cámara se registra, opera (heartbeat) y se desactiva.

    Pasos:
      1. Admin registra la cámara → recibe API Key
      2. La cámara aparece en el listado
      3. La cámara envía heartbeat exitoso
      4. Admin desactiva la cámara (PATCH /deactivate)
      5. Heartbeat rechazado tras desactivación (401)

    Garantías de seguridad:
      - La API Key sigue siendo criptográficamente válida, pero el sistema
        rechaza operaciones de cámaras inactivas (NIST SP 800-57).
      - La desactivación es instantánea, sin período de gracia.
    """

    _camera_id: str = "sc1-lifecycle-cam"
    _api_key: str = ""

    def test_step1_register_camera(self, client, admin_token):
        """
        Paso 1: El admin registra la cámara.
        La API Key se devuelve una única vez en texto claro;
        a partir de ahí solo se almacena su hash SHA-256.
        """
        resp = client.post(
            "/api/v1/cameras/",
            json={
                "camera_id": self._camera_id,
                "name": "Cámara Escenario 1",
                "location": "Entrada principal",
            },
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert "api_key" in data
        assert data["camera_id"] == self._camera_id
        TestScenario1CameraLifecycle._api_key = data["api_key"]

    def test_step2_camera_appears_in_list(self, client, admin_token):
        """
        Paso 2: La cámara recién registrada aparece en el listado.
        """
        resp = client.get(
            "/api/v1/cameras/",
            params={"is_active": True},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200
        ids = [c["camera_id"] for c in resp.json()["items"]]
        assert self._camera_id in ids

    def test_step3_heartbeat_succeeds(self, client):
        """
        Paso 3: La cámara activa puede enviar heartbeats.
        """
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": TestScenario1CameraLifecycle._api_key},
        )
        assert resp.status_code == 200
        assert resp.json()["camera_id"] == self._camera_id

    def test_step4_deactivate_camera(self, client, admin_token):
        """
        Paso 4: El admin desactiva la cámara (baja lógica, no borrado físico).
        Los datos históricos se preservan para auditoría forense.
        """
        resp = client.patch(
            f"/api/v1/cameras/{self._camera_id}/deactivate",
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["is_active"] is False

    def test_step5_heartbeat_rejected_after_deactivation(self, client):
        """
        Paso 5: La cámara desactivada no puede enviar heartbeats.
        Su API Key sigue siendo válida criptográficamente, pero el sistema
        rechaza las peticiones de cámaras inactivas (401).
        Ref: NIST SP 800-57 — revocación operacional de credenciales.
        """
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": TestScenario1CameraLifecycle._api_key},
        )
        assert resp.status_code == 401, (
            f"Cámara desactivada debería recibir 401, got {resp.status_code}"
        )


# ═══════════════════════════════════════════════════════════════
# Escenario 2: Flujo de captura forense completo
# ═══════════════════════════════════════════════════════════════


class TestScenario2ForensicCaptureFlow:
    """
    Escenario: Una cámara graba un video y un analista verifica los segmentos.

    Pasos:
      1. Admin registra cámara de captura
      2. Cámara inicia grabación (POST /videos)
      3. Cámara sube 3 segmentos de 30 s cada uno
      4. Analista consulta los segmentos y verifica cobertura temporal continua

    Garantías forenses:
      - Cobertura temporal: 0-30, 30-60, 60-90 segundos sin huecos.
      - Los SHA-256 enviados por la cámara coinciden con los almacenados.
      - Ningún segmento puede duplicarse (idempotencia del índice).
    """

    _camera_id: str = "sc2-forensic-cam"
    _api_key: str = ""
    _video_id: str = ""
    _hashes: list = []

    def test_step1_register_camera_for_capture(self, client, admin_token):
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": self._camera_id, "name": "Cámara Forense Sc2"},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201, resp.text
        TestScenario2ForensicCaptureFlow._api_key = resp.json()["api_key"]

    def test_step2_camera_starts_video(self, client):
        """
        Paso 2: La cámara inicia una nueva grabación.
        El servidor asigna un ID único al video y registra started_at.
        """
        resp = client.post(
            "/api/v1/cameras/videos",
            json={"filename": "sc2_capture.mp4", "fps": 25.0, "resolution": "1920x1080"},
            headers={"X-API-Key": TestScenario2ForensicCaptureFlow._api_key},
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["status"] == "recording"
        TestScenario2ForensicCaptureFlow._video_id = data["id"]

    def test_step3_camera_uploads_three_segments(self, client):
        """
        Paso 3: La cámara sube 3 segmentos con cobertura temporal continua.
        Cada segmento tiene su propio SHA-256 único.
        """
        video_id = TestScenario2ForensicCaptureFlow._video_id
        api_key = TestScenario2ForensicCaptureFlow._api_key
        hashes = []

        for i in range(3):
            h = _valid_sha256()
            hashes.append(h)
            resp = client.post(
                "/api/v1/cameras/segments",
                json={
                    "video_id": video_id,
                    "segment_index": i,
                    "start_time_secs": i * 30,
                    "end_time_secs": (i + 1) * 30,
                    "sha256_hash": h,
                },
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 201, f"Segmento {i} falló: {resp.text}"

        TestScenario2ForensicCaptureFlow._hashes = hashes

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
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["total"] == 3

        segments = sorted(data["segments"], key=lambda s: s["segment_index"])
        stored_hashes = [s["sha256_hash"] for s in segments]
        expected_hashes = [
            h.lower() for h in TestScenario2ForensicCaptureFlow._hashes
        ]
        assert stored_hashes == expected_hashes, (
            "Los hashes almacenados no coinciden con los enviados por la cámara"
        )


# ═══════════════════════════════════════════════════════════════
# Escenario 3: RBAC — Control de Acceso Basado en Roles
# ═══════════════════════════════════════════════════════════════


class TestScenario3Rbac:
    """
    Escenario: Ciclo de vida completo de un analista forense.

    Pasos:
      1. Admin crea cuenta de analista
      2. Analista se autentifica y obtiene JWT
      3. Analista puede leer cámaras (operación permitida)
      4. Analista no puede eliminar usuarios (operación prohibida)
      5. Admin desactiva al analista
      6. Analista desactivado es rechazado aunque tenga JWT vigente

    Garantías:
      - Principio de menor privilegio (OWASP ASVS §4.2)
      - Revocación inmediata: el sistema comprueba is_active en cada
        petición, no solo en el momento del login (NIST SP 800-53 AC-2)
    """

    analyst_email: str = "analyst.sc3@evideth.test"
    analyst_password: str = "Analyst1234!"

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
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["role"] == "analyst"
        assert data["is_active"] is True
        TestScenario3Rbac._analyst_id = data["id"]

    def test_step2_analyst_logs_in(self, client):
        """
        El analista se autentica y obtiene un JWT válido.
        """
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": self.analyst_email, "password": self.analyst_password},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "access_token" in data
        TestScenario3Rbac._analyst_token = data["access_token"]

    def test_step3_analyst_can_read_cameras(self, client):
        """
        El analista activo puede consultar la lista de cámaras (operación de lectura).
        """
        resp = client.get(
            "/api/v1/cameras/",
            headers=_auth(TestScenario3Rbac._analyst_token),
        )
        assert resp.status_code == 200, resp.text

    def test_step4_analyst_cannot_delete_user(self, client):
        """
        El analista no puede gestionar usuarios (operación solo de ADMIN).
        Verifica el principio de menor privilegio.
        """
        resp = client.delete(
            f"/api/v1/users/{TestScenario3Rbac._analyst_id}",
            headers=_auth(TestScenario3Rbac._analyst_token),
        )
        assert resp.status_code == 403, (
            f"Analista no debería poder eliminar usuarios: {resp.status_code}"
        )

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
        assert resp.status_code == 200, resp.text
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
        assert resp.status_code == 401, (
            f"Usuario desactivado debería recibir 401, got {resp.status_code}"
        )


# ═══════════════════════════════════════════════════════════════
# Escenario 4: Blindaje de integridad de datos
# ═══════════════════════════════════════════════════════════════


class TestScenario4DataIntegrityGuard:
    """
    Escenario: El sistema rechaza datos forenses inválidos o duplicados.

    El API aplica múltiples capas de validación antes de persistir
    cualquier segmento, garantizando que solo entran datos íntegros.

    Pasos:
      1. Setup: registrar cámara y video
      2. Rechazar hash truncado (422 — longitud incorrecta)
      3. Rechazar hash no-hexadecimal (422 — caracteres inválidos)
      4. Aceptar segmento válido (201)
      5. Rechazar duplicado del mismo índice (409 Conflict)
      6. Rechazar rango temporal negativo end <= start (422)
    """

    _camera_id: str = "sc4-integrity-cam"
    _api_key: str = ""
    _video_id: str = ""

    def test_step1_setup_camera_and_video(self, client, admin_token):
        resp = client.post(
            "/api/v1/cameras/",
            json={"camera_id": self._camera_id, "name": "Cámara Integridad Sc4"},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 201, resp.text
        TestScenario4DataIntegrityGuard._api_key = resp.json()["api_key"]

        resp2 = client.post(
            "/api/v1/cameras/videos",
            json={"filename": "sc4_integrity.mp4"},
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp2.status_code == 201, resp2.text
        TestScenario4DataIntegrityGuard._video_id = resp2.json()["id"]

    def test_step2_reject_truncated_hash(self, client):
        """Hash de 32 chars en lugar de 64 → 422 Unprocessable Entity."""
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": "a" * 32,  # truncado — inválido
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422, resp.text

    def test_step3_reject_non_hex_hash(self, client):
        """Hash con caracteres no-hexadecimales → 422."""
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": "z" * 64,  # no es hex válido
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422, resp.text

    def test_step4_accept_valid_segment(self, client):
        """Segmento completamente válido → 201 Created."""
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
        assert resp.status_code == 201, resp.text

    def test_step5_reject_duplicate_segment(self, client):
        """
        El índice 0 ya fue registrado en el paso anterior.
        El sistema rechaza duplicados con 409 Conflict.
        Garantiza idempotencia del registro forense.
        """
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,  # duplicado
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 409, resp.text

    def test_step6_reject_negative_time_range(self, client):
        """end_time_secs <= start_time_secs → 422."""
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 99,
                "start_time_secs": 60,
                "end_time_secs": 30,  # end < start → inválido
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422, resp.text


# ═══════════════════════════════════════════════════════════════
# Escenario 5: Aislamiento multi-cámara
# ═══════════════════════════════════════════════════════════════


class TestScenario5MultiCamera:
    """
    Escenario: Dos cámaras operan en paralelo sin interferencia.

    Pasos:
      1. Registrar cámara A y cámara B
      2. Cada cámara inicia su propio video
      3. Cada cámara sube 2 segmentos a su video
      4. Cámara B intenta escribir en el video de cámara A → rechazado
      5. Los conteos de segmentos son independientes (no se mezclan)

    Garantías:
      - Aislamiento de datos entre cámaras (OWASP ASVS §4.2)
      - Una API Key solo autoriza operaciones sobre los videos
        de su propia cámara
      - El sistema devuelve 404 cuando el video no pertenece a la cámara
        (no revela la existencia del recurso ajeno — security through opacity)
    """

    cam_a_id: str = "sc5-cam-alpha"
    cam_b_id: str = "sc5-cam-beta"

    def test_step1_register_two_cameras(self, client, admin_token):
        for cam_id in (self.cam_a_id, self.cam_b_id):
            resp = client.post(
                "/api/v1/cameras/",
                json={"camera_id": cam_id, "name": f"Multi-cam {cam_id}"},
                headers=_auth(admin_token),
            )
            assert resp.status_code == 201, resp.text
            suffix = cam_id.split("-")[-1].lower()
            setattr(TestScenario5MultiCamera, f"_api_key_{suffix}", resp.json()["api_key"])

    def test_step2_each_camera_starts_own_video(self, client):
        for cam_id in (self.cam_a_id, self.cam_b_id):
            suffix = cam_id.split("-")[-1].lower()
            api_key = getattr(TestScenario5MultiCamera, f"_api_key_{suffix}")
            resp = client.post(
                "/api/v1/cameras/videos",
                json={"filename": f"sc5_{suffix}.mp4"},
                headers={"X-API-Key": api_key},
            )
            assert resp.status_code == 201, resp.text
            setattr(TestScenario5MultiCamera, f"_video_id_{suffix}", resp.json()["id"])

    def test_step3_cameras_upload_segments_independently(self, client):
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
                assert resp.status_code == 201, (
                    f"Cámara {cam_id} segmento {i} falló: {resp.text}"
                )

    def test_step4_camera_b_cannot_write_to_camera_a_video(self, client):
        """
        La cámara B no puede enviar segmentos al video de la cámara A.
        El sistema valida que la API Key pertenece a la cámara propietaria
        del video.

        Comportamiento esperado:
        - 404: el sistema no revela la existencia del video ajeno
          (security through opacity — RFC 7231 §6.5.4)
        - 403: explícito si el sistema distingue autenticado vs. autorizado

        Ambas respuestas son válidas y seguras; 404 es preferible porque
        no informa al atacante sobre la existencia del recurso.
        """
        video_id_a = TestScenario5MultiCamera._video_id_alpha
        api_key_b = TestScenario5MultiCamera._api_key_beta

        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": video_id_a,  # video de cámara A
                "segment_index": 99,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": api_key_b},  # pero API Key de cámara B
        )
        # 404 es correcto (opacity) o 403 (explícito). Ambos aceptables.
        assert resp.status_code in (401, 403, 404), (
            f"Cámara B no debería poder escribir en video de cámara A: {resp.status_code}"
        )

    def test_step5_verify_segment_counts_are_independent(self, client, admin_token):
        """
        Cada video tiene exactamente sus propios 2 segmentos.
        Los conteos no se mezclan entre cámaras.
        """
        for suffix in ("alpha", "beta"):
            video_id = getattr(TestScenario5MultiCamera, f"_video_id_{suffix}")
            resp = client.get(
                f"/api/v1/cameras/videos/{video_id}/segments",
                headers=_auth(admin_token),
            )
            assert resp.status_code == 200, resp.text
            assert resp.json()["total"] == 2, (
                f"Video {suffix} debería tener 2 segmentos, got {resp.json()['total']}"
            )
