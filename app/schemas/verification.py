from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class VerificationRequest(BaseModel):
    camera_id: str
    video_db_id: str       # ID del video en BD contra el que verificar


class SegmentVerificationResult(BaseModel):
    segment_index: int
    start_time_secs: Optional[int] = None
    end_time_secs: Optional[int] = None
    duration_secs: Optional[int] = None
    complete: Optional[bool] = None
    computed_hash: Optional[str]
    stored_hash: Optional[str]
    hash_match: bool
    signature_valid: Optional[bool]
    result: str             # "pass" | "fail" | "error"
    detail: Optional[str]


class VerificationReport(BaseModel):
    video_id: str
    camera_id: str
    integrity_ok: bool
    verdict: str            # "ÍNTEGRO" | "MANIPULADO O INCOMPLETO"
    summary: dict
    segments: List[SegmentVerificationResult]
    verified_at: str
