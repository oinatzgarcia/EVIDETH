from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class VerificationRequest(BaseModel):
    camera_id: str
    video_db_id: str       # ID del video en BD contra el que verificar


class SecondHashResult(BaseModel):
    """
    Resultado de verificación de un segundo individual dentro de un segmento.
    Corresponde a una hoja del árbol Merkle del segmento.
    """
    second_index:  int              # 0 = primer segundo del segmento
    computed_hash: str              # SHA-256 calculado del segundo subido por el usuario
    stored_hash:   Optional[str] = None  # SHA-256 almacenado (generado por la cámara)
    hash_match:    bool             # True si computed_hash == stored_hash
    tampered:      bool             # True si hash_match == False


class SegmentVerificationResult(BaseModel):
    segment_index:   int
    start_time_secs: Optional[int]  = None
    end_time_secs:   Optional[int]  = None
    duration_secs:   Optional[int]  = None
    complete:        Optional[bool] = None

    # ── Nivel 1: hash del segmento completo (30 s) ────────────────────────
    computed_hash:   Optional[str]  = None
    stored_hash:     Optional[str]  = None
    hash_match:      bool
    signature_valid: Optional[bool] = None
    result:          str             # "pass" | "fail" | "error"
    detail:          Optional[str]  = None

    # ── Nivel 2: árbol Merkle (granularidad de segundo) ───────────────────
    # Solo se incluye cuando hay datos Merkle almacenados (daemon implementado)
    computed_merkle_root: Optional[str]                  = None
    stored_merkle_root:   Optional[str]                  = None
    merkle_match:         Optional[bool]                 = None
    second_results:       Optional[List[SecondHashResult]] = None  # Solo si hay discrepancia


class VerificationReport(BaseModel):
    video_id:     str
    camera_id:    str
    integrity_ok: bool
    verdict:      str            # "ÍNTEGRO" | "MANIPULADO O INCOMPLETO"
    summary:      dict
    segments:     List[SegmentVerificationResult]
    verified_at:  str
