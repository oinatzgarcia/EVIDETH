from pydantic import BaseModel
from typing import Optional, List, Dict


class VerificationRequest(BaseModel):
    camera_id: str
    video_db_id: str  # ID del video en BD contra el que verificar


class SecondHashResult(BaseModel):
    """
    Resultado de verificación de un segundo individual dentro de un segmento.
    Corresponde a una hoja del árbol Merkle del segmento.
    """

    second_index: int  # 0 = primer segundo del segmento
    computed_hash: str  # SHA-256 calculado del segundo subido por el usuario
    stored_hash: Optional[str] = None  # SHA-256 almacenado (generado por la cámara)
    hash_match: bool  # True si computed_hash == stored_hash
    tampered: bool  # True si hash_match == False


class TamperedFrameData(BaseModel):
    """
    Par de imágenes JPEG (en base64) de un segundo manipulado.

    - current_frame:  frame extraído del vídeo subido por el usuario (manipulado).
    - original_frame: frame almacenado por la cámara en el momento de la grabación
                      (original, referencia forense).

    Ambos pueden ser None si no hay información disponible (p.ej. el simulador
    no había guardado thumbnails o ffmpeg no puede extraer el frame).
    """

    current_frame: Optional[str] = None  # JPEG codificado en base64
    original_frame: Optional[str] = None  # JPEG codificado en base64


class SegmentVerificationResult(BaseModel):
    segment_index: int
    start_time_secs: Optional[int] = None
    end_time_secs: Optional[int] = None
    duration_secs: Optional[int] = None
    complete: Optional[bool] = None

    # ── Nivel 1: hash del segmento completo (30 s) ────────────────────────
    computed_hash: Optional[str] = None
    stored_hash: Optional[str] = None
    hash_match: bool
    signature_valid: Optional[bool] = None
    result: str  # "pass" | "fail" | "error"
    detail: Optional[str] = None

    # ── Nivel 2: árbol Merkle (granularidad de segundo) ───────────────────
    # Solo se incluye cuando hay datos Merkle almacenados (daemon implementado)
    computed_merkle_root: Optional[str] = None
    stored_merkle_root: Optional[str] = None
    merkle_match: Optional[bool] = None
    second_results: Optional[List[SecondHashResult]] = None  # Solo si hay discrepancia

    # ── Nivel 2 visual: frames de los segundos manipulados ────────────────
    # Claves: índice del segundo (como str al serializar a JSON).
    # Valor:  par {current_frame, original_frame} en base64 JPEG.
    # Solo se incluye cuando hay segundos manipulados detectados.
    tampered_frames: Optional[Dict[str, TamperedFrameData]] = None


class VerificationReport(BaseModel):
    video_id: str
    camera_id: str
    integrity_ok: bool
    verdict: str  # "ÍNTEGRO" | "MANIPULADO O INCOMPLETO"

    # True si la cámara tiene clave pública registrada (firma ECDSA disponible).
    # Si es False, el Nivel 3 se omite en la verificación.
    ecdsa_available: bool = False

    summary: dict
    segments: List[SegmentVerificationResult]
    verified_at: str

    # Campos opcionales presentes solo en el caso de rechazo anticipado
    # (p.ej. file_hash_mismatch antes de procesar segmentos)
    reason: Optional[str] = None
    detail: Optional[str] = None
