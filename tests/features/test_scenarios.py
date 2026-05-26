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
from sqlalchemy.pool import StaticPool

from app.db.session import Base, get_db
from app.db.models import User, UserRole
from app.core.security import hash_password, create_access_token
from app.main import app

import secrets

# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture(scope="class")
def client():
    """
    TestClient con BD SQLite en memoria aislada por escenario.
    StaticPool garantiza que todos los hilos/conexiones comparten
    exactamente el mismo objeto de conexión en memoria.
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
        # Exponemos la sesión en el cliente para que admin_token pueda usarla
        c._test_session_local = SessionLocal
        yield c

    app.dependency_overrides.pop(get_db, None)
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(scope="class")
def admin_token(client):
    """
    Crea un usuario admin usando la misma BD que el client y devuelve su JWT.
    Depende de `client` para garantizar que el override ya está activo.
    """
    SessionLocal = client._test_session_local
    db = SessionLocal()
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
        return create_access_token({"sub": str(admin.id), "role": admin.role.value})
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


@pytest.mark.usefixtures("client", "admin_token")
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
        resp = client.get(
            "/api/v1/cameras/",
            params={"is_active": True},
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200
        ids = [c["camera_id"] for c in resp.json()["items"]]
        assert self._camera_id in ids

    def test_step3_heartbeat_succeeds(self, client):
        resp = client.post(
            "/api/v1/cameras/heartbeat",
            headers={"X-API-Key": TestScenario1CameraLifecycle._api_key},
        )
        assert resp.status_code == 200
        assert resp.json()["camera_id"] == self._camera_id

    def test_step4_deactivate_camera(self, client, admin_token):
        resp = client.patch(
            f"/api/v1/cameras/{self._camera_id}/deactivate",
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["is_active"] is False

    def test_step5_heartbeat_rejected_after_deactivation(self, client):
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


@pytest.mark.usefixtures("client", "admin_token")
class TestScenario2ForensicCaptureFlow:
    """
    Escenario: Una cámara graba un video y un analista verifica los segmentos.
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
        expected_hashes = [h.lower() for h in TestScenario2ForensicCaptureFlow._hashes]
        assert stored_hashes == expected_hashes


# ═══════════════════════════════════════════════════════════════
# Escenario 3: RBAC — Control de Acceso Basado en Roles
# ═══════════════════════════════════════════════════════════════


@pytest.mark.usefixtures("client", "admin_token")
class TestScenario3Rbac:
    """
    Escenario: Ciclo de vida completo de un analista forense.
    """

    analyst_email: str = "analyst.sc3@evideth.test"
    analyst_password: str = "Analyst1234!"

    def test_step1_admin_creates_analyst(self, client, admin_token):
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
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": self.analyst_email, "password": self.analyst_password},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "access_token" in data
        TestScenario3Rbac._analyst_token = data["access_token"]

    def test_step3_analyst_can_read_cameras(self, client):
        resp = client.get(
            "/api/v1/cameras/",
            headers=_auth(TestScenario3Rbac._analyst_token),
        )
        assert resp.status_code == 200, resp.text

    def test_step4_analyst_cannot_delete_user(self, client):
        resp = client.delete(
            f"/api/v1/users/{TestScenario3Rbac._analyst_id}",
            headers=_auth(TestScenario3Rbac._analyst_token),
        )
        assert resp.status_code == 403, (
            f"Analista no debería poder eliminar usuarios: {resp.status_code}"
        )

    def test_step5_admin_deactivates_analyst(self, client, admin_token):
        resp = client.patch(
            f"/api/v1/users/{TestScenario3Rbac._analyst_id}/deactivate",
            headers=_auth(admin_token),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["is_active"] is False

    def test_step6_deactivated_analyst_cannot_operate(self, client):
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


@pytest.mark.usefixtures("client", "admin_token")
class TestScenario4DataIntegrityGuard:
    """
    Escenario: El sistema rechaza datos forenses inválidos o duplicados.
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
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": "a" * 32,
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422, resp.text

    def test_step3_reject_non_hex_hash(self, client):
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 0,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": "z" * 64,
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422, resp.text

    def test_step4_accept_valid_segment(self, client):
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
        assert resp.status_code == 409, resp.text

    def test_step6_reject_negative_time_range(self, client):
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": TestScenario4DataIntegrityGuard._video_id,
                "segment_index": 99,
                "start_time_secs": 60,
                "end_time_secs": 30,
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": TestScenario4DataIntegrityGuard._api_key},
        )
        assert resp.status_code == 422, resp.text


# ═══════════════════════════════════════════════════════════════
# Escenario 5: Aislamiento multi-cámara
# ═══════════════════════════════════════════════════════════════


@pytest.mark.usefixtures("client", "admin_token")
class TestScenario5MultiCamera:
    """
    Escenario: Dos cámaras operan en paralelo sin interferencia.
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
        video_id_a = TestScenario5MultiCamera._video_id_alpha
        api_key_b = TestScenario5MultiCamera._api_key_beta
        resp = client.post(
            "/api/v1/cameras/segments",
            json={
                "video_id": video_id_a,
                "segment_index": 99,
                "start_time_secs": 0,
                "end_time_secs": 30,
                "sha256_hash": _valid_sha256(),
            },
            headers={"X-API-Key": api_key_b},
        )
        assert resp.status_code in (401, 403, 404), (
            f"Cámara B no debería poder escribir en video de cámara A: {resp.status_code}"
        )

    def test_step5_verify_segment_counts_are_independent(self, client, admin_token):
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
