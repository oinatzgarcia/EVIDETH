from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Text,
    Integer,
    Float,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base
import uuid
import enum


# ── Enums ───────────────────────────────────────────────────────────


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class VideoStatus(str, enum.Enum):
    RECORDING = "recording"
    COMPLETED = "completed"
    CORRUPTED = "corrupted"
    ARCHIVED = "archived"


class SegmentStatus(str, enum.Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    MISSING = "missing"


class VerificationResult(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


# ── User ────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    # Si True, el frontend debe redirigir a la pantalla de cambio de contraseña
    # antes de permitir cualquier otra accion. Se pone a True en el admin por defecto
    # y en cualquier usuario creado por un admin.
    must_change_password = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    cameras = relationship("Camera", back_populates="owner")
    videos = relationship("Video", back_populates="created_by")
    verifications = relationship("Verification", back_populates="verified_by")

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"


# ── Camera ─────────────────────────────────────────────────────


class Camera(Base):
    __tablename__ = "cameras"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    camera_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    location = Column(String(255))
    description = Column(Text)
    api_key = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    owner_id = Column(String(36), ForeignKey("users.id"))
    public_key_pem = Column(Text, nullable=True)

    owner = relationship("User", back_populates="cameras")
    videos = relationship("Video", back_populates="camera")

    def __repr__(self):
        return f"<Camera {self.camera_id} @ {self.location}>"


# ── Video ────────────────────────────────────────────────────────


class Video(Base):
    __tablename__ = "videos"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String(500), nullable=False)
    blob_url = Column(String(1000))
    duration_secs = Column(Integer)
    file_size_bytes = Column(Integer)
    fps = Column(Float)
    resolution = Column(String(50))
    codec = Column(String(50))
    sha256_full = Column(String(64))
    status = Column(Enum(VideoStatus), default=VideoStatus.RECORDING, nullable=False)
    started_at = Column(DateTime(timezone=True))
    ended_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    camera_id = Column(String(36), ForeignKey("cameras.id"), nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id"))

    camera = relationship("Camera", back_populates="videos")
    created_by = relationship("User", back_populates="videos")
    segments = relationship(
        "Segment",
        back_populates="video",
        cascade="all, delete-orphan",
        order_by="Segment.segment_index",
    )

    def __repr__(self):
        return f"<Video {self.filename} [{self.status}]>"


# ── Segment ─────────────────────────────────────────────────────


class Segment(Base):
    __tablename__ = "segments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    segment_index = Column(Integer, nullable=False)
    duration_secs = Column(Integer, default=30)
    start_time_secs = Column(Integer, nullable=False)
    end_time_secs = Column(Integer, nullable=False)
    file_size_bytes = Column(Integer)

    # ── Criptografia Nivel 1 ───────────────────────────────────
    sha256_hash = Column(String(64), nullable=False)
    ecdsa_signature = Column(Text)
    public_key_id = Column(String(255))

    # ── Criptografia Nivel 2: arbol Merkle ──────────────────────
    merkle_root = Column(String(64))
    second_hashes = Column(Text)  # JSON: ["h0", "h1", ..., "h29"]

    # ── Thumbnails por segundo (JPEG base64) ─────────────────────
    frame_thumbnails = Column(Text, nullable=True)  # JSON: ["b64_jpg_sec0", ..., null]

    blob_url = Column(String(1000))
    status = Column(Enum(SegmentStatus), default=SegmentStatus.PENDING, nullable=False)
    signed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    video_id = Column(String(36), ForeignKey("videos.id"), nullable=False)

    video = relationship("Video", back_populates="segments")
    verifications = relationship(
        "Verification", back_populates="segment", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Segment #{self.segment_index} [{self.status}] video={self.video_id}>"


# ── Verification ───────────────────────────────────────────────


class Verification(Base):
    __tablename__ = "verifications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    result = Column(Enum(VerificationResult), nullable=False)
    hash_match = Column(Boolean)
    signature_valid = Column(Boolean)
    error_message = Column(Text)

    computed_hash = Column(String(64))
    stored_hash = Column(String(64))

    verified_at = Column(DateTime(timezone=True), server_default=func.now())
    ip_address = Column(String(45))
    user_agent = Column(String(500))

    segment_id = Column(String(36), ForeignKey("segments.id"), nullable=False)
    verified_by_id = Column(String(36), ForeignKey("users.id"))

    segment = relationship("Segment", back_populates="verifications")
    verified_by = relationship("User", back_populates="verifications")

    def __repr__(self):
        return f"<Verification {self.result} segment={self.segment_id}>"
