from sqlalchemy import (
    Column, String, Boolean, DateTime, Enum,
    ForeignKey, Text, Integer, Float, LargeBinary
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base
import uuid
import enum


# ── Enums ─────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN   = "admin"
    ANALYST = "analyst"
    VIEWER  = "viewer"

class VideoStatus(str, enum.Enum):
    RECORDING  = "recording"   # Grabando actualmente
    COMPLETED  = "completed"   # Grabación finalizada
    CORRUPTED  = "corrupted"   # Integridad comprometida
    ARCHIVED   = "archived"    # Archivado en cold storage

class SegmentStatus(str, enum.Enum):
    PENDING   = "pending"      # Pendiente de verificar
    VALID     = "valid"        # Hash verificado OK
    INVALID   = "invalid"      # Hash no coincide → manipulado
    MISSING   = "missing"      # Segmento no encontrado

class VerificationResult(str, enum.Enum):
    PASS    = "pass"           # Verificación exitosa
    FAIL    = "fail"           # Verificación fallida
    ERROR   = "error"          # Error durante verificación


# ── User ────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id         = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email      = Column(String(255), unique=True, nullable=False, index=True)
    full_name  = Column(String(255), nullable=False)
    password   = Column(String(255), nullable=False)       # bcrypt hash
    role       = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active  = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relaciones
    cameras       = relationship("Camera", back_populates="owner")
    videos        = relationship("Video", back_populates="created_by")
    verifications = relationship("Verification", back_populates="verified_by")

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"


# ── Camera ───────────────────────────────────────────────

class Camera(Base):
    __tablename__ = "cameras"

    id          = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    camera_id   = Column(String(100), unique=True, nullable=False, index=True)  # ID físico
    name        = Column(String(255), nullable=False)
    location    = Column(String(255))
    description = Column(Text)
    api_key     = Column(String(255), nullable=False)      # SHA-256 hash de la API Key
    is_active   = Column(Boolean, default=True)
    last_seen   = Column(DateTime(timezone=True))          # Último heartbeat / segmento
    created_at  = Column(DateTime(timezone=True), server_default=func.now())
    updated_at  = Column(DateTime(timezone=True), onupdate=func.now())
    owner_id    = Column(String(36), ForeignKey("users.id"))

    # ── Criptografía ──────────────────────────────────────────
    # Clave pública ECDSA P-256 en formato PEM.
    # Generada automáticamente por el simulador en el primer arranque
    # y exportada a /keys/camera_public.pem.
    # El administrador la registra mediante:
    #   POST /api/v1/cameras/{camera_id}/public-key
    # Usada por verifier.py para validar firmas de segmentos.
    # NIST FIPS 186-5 — Digital Signature Standard (ECDSA)
    public_key_pem = Column(Text, nullable=True)

    # Relaciones
    owner  = relationship("User", back_populates="cameras")
    videos = relationship("Video", back_populates="camera")

    def __repr__(self):
        return f"<Camera {self.camera_id} @ {self.location}>"


# ── Video ────────────────────────────────────────────────

class Video(Base):
    __tablename__ = "videos"

    id              = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename        = Column(String(500), nullable=False)
    blob_url        = Column(String(1000))                 # Azure Blob Storage URL
    duration_secs   = Column(Integer)                      # Duración total en segundos
    file_size_bytes = Column(Integer)                      # Tamaño en bytes
    fps             = Column(Float)                        # Frames por segundo
    resolution      = Column(String(50))                   # Ej: "1920x1080"
    codec           = Column(String(50))                   # Ej: "H264"
    sha256_full     = Column(String(64))                   # Hash SHA-256 del video completo
    status          = Column(Enum(VideoStatus), default=VideoStatus.RECORDING, nullable=False)
    started_at      = Column(DateTime(timezone=True))      # Inicio de grabación
    ended_at        = Column(DateTime(timezone=True))      # Fin de grabación
    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    updated_at      = Column(DateTime(timezone=True), onupdate=func.now())

    # FK
    camera_id      = Column(String(36), ForeignKey("cameras.id"), nullable=False)
    created_by_id  = Column(String(36), ForeignKey("users.id"))

    # Relaciones
    camera     = relationship("Camera", back_populates="videos")
    created_by = relationship("User", back_populates="videos")
    segments   = relationship("Segment", back_populates="video",
                              cascade="all, delete-orphan",
                              order_by="Segment.segment_index")

    def __repr__(self):
        return f"<Video {self.filename} [{self.status}]>"


# ── Segment ──────────────────────────────────────────────

class Segment(Base):
    __tablename__ = "segments"

    id              = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    segment_index   = Column(Integer, nullable=False)      # Nº de segmento (0, 1, 2...)
    duration_secs   = Column(Integer, default=30)          # Duración (siempre 30 s en EVIDETH)
    start_time_secs = Column(Integer, nullable=False)      # Segundo de inicio en el video
    end_time_secs   = Column(Integer, nullable=False)      # Segundo de fin en el video
    file_size_bytes = Column(Integer)

    # ── Criptografía Nivel 1: hash del segmento completo (30 s) ─────────────
    sha256_hash     = Column(String(64), nullable=False)   # SHA-256 del segmento completo
    ecdsa_signature = Column(Text)                         # Firma ECDSA P-256 en base64url
    public_key_id   = Column(String(255))                  # Huella de la clave (fingerprint)

    # ── Criptografía Nivel 2: árbol Merkle de hashes por segundo ───────────
    # Permite localizar exactamente qué segundo(s) fueron manipulados.
    # Ref: Nakamoto (2008) Bitcoin Whitepaper §7 — Merkle branch SPV
    merkle_root     = Column(String(64))                   # Raíz del árbol Merkle (hex64)
    second_hashes   = Column(Text)                         # JSON: ["h0", "h1", ..., "h29"]

    blob_url        = Column(String(1000))                 # URL en Azure Blob Storage
    status          = Column(Enum(SegmentStatus), default=SegmentStatus.PENDING, nullable=False)
    signed_at       = Column(DateTime(timezone=True))      # Timestamp de firma
    created_at      = Column(DateTime(timezone=True), server_default=func.now())

    # FK
    video_id = Column(String(36), ForeignKey("videos.id"), nullable=False)

    # Relaciones
    video         = relationship("Video", back_populates="segments")
    verifications = relationship("Verification", back_populates="segment",
                                 cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Segment #{self.segment_index} [{self.status}] video={self.video_id}>"


# ── Verification ───────────────────────────────────────────

class Verification(Base):
    __tablename__ = "verifications"

    id                  = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    # Resultado
    result              = Column(Enum(VerificationResult), nullable=False)
    hash_match          = Column(Boolean)                  # ¿Hash SHA-256 coincide?
    signature_valid     = Column(Boolean)                  # ¿Firma ECDSA válida?
    error_message       = Column(Text)                     # Detalle si hay error

    # Hashes en el momento de verificación (para auditoría)
    computed_hash       = Column(String(64))               # Hash calculado en verificación
    stored_hash         = Column(String(64))               # Hash almacenado originalmente

    # Metadatos de auditoría
    verified_at         = Column(DateTime(timezone=True), server_default=func.now())
    ip_address          = Column(String(45))               # IP del verificador
    user_agent          = Column(String(500))              # Navegador/cliente

    # FK
    segment_id          = Column(String(36), ForeignKey("segments.id"), nullable=False)
    verified_by_id      = Column(String(36), ForeignKey("users.id"))

    # Relaciones
    segment     = relationship("Segment", back_populates="verifications")
    verified_by = relationship("User", back_populates="verifications")

    def __repr__(self):
        return f"<Verification {self.result} segment={self.segment_id}>"
