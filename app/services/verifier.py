import hashlib
import base64
import json
from typing import Callable, List, Dict, Optional, Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import os

from app.db.models import (
    Camera, Segment, Verification, Video,
    SegmentStatus, VerificationResult,
)
from app.services.video_processor import (
    segment_video, cleanup_segments, extract_frame_thumbnail
)
from app.utils.merkle import build_merkle_root
import tempfile


def verify_ecdsa_signature(
    merkle_root:    str,
    signature_b64:  str,
    public_key_pem: str,
) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        padded     = signature_b64 + "==" * (4 - len(signature_b64) % 4 if len(signature_b64) % 4 else 0)
        signature  = base64.urlsafe_b64decode(padded)
        data       = bytes.fromhex(merkle_root)
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _get_camera_public_key(camera_id: str, db: Session) -> Optional[str]:
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        return None
    return getattr(camera, "public_key_pem", None)


def _compare_second_hashes(
    computed_seconds:    List[str],
    stored_seconds_json: Optional[Union[str, list]],
) -> Optional[List[Dict]]:
    """
    Compara hashes por segundo del vídeo verificado vs. los almacenados.
    stored_seconds_json puede ser list (JSONB auto-deserializado) o str.
    """
    if not stored_seconds_json:
        return None

    if isinstance(stored_seconds_json, list):
        stored_seconds = stored_seconds_json
    else:
        stored_seconds = json.loads(stored_seconds_json)

    results = []
    count   = max(len(computed_seconds), len(stored_seconds))
    empty   = hashlib.sha256(b"").hexdigest()

    for i in range(count):
        comp  = computed_seconds[i] if i < len(computed_seconds) else empty
        stor  = stored_seconds[i]   if i < len(stored_seconds)  else None
        match = (comp == stor) if stor is not None else False
        results.append({
            "second_index":  i,
            "computed_hash": comp,
            "stored_hash":   stor,
            "hash_match":    match,
            "tampered":      not match,
        })

    return results


def _extract_tampered_frames(
    video_path:        str,
    second_results:    List[Dict],
    stored_thumbnails: Optional[Union[str, list]],
) -> Dict[str, Dict]:
    """
    Para cada segundo marcado como tampered, extrae:
      - current_frame:  frame del vídeo subido (manipulado)
      - original_frame: frame almacenado cuando la cámara grabó (original)
    Ambos en base64 JPEG.
    """
    stored: list = []
    if stored_thumbnails:
        if isinstance(stored_thumbnails, list):
            stored = stored_thumbnails
        else:
            try:
                stored = json.loads(stored_thumbnails)
            except Exception:
                stored = []

    frames: Dict[str, Dict] = {}

    for sr in second_results:
        if not sr["tampered"]:
            continue
        sec = sr["second_index"]

        current_frame  = extract_frame_thumbnail(video_path, sec)
        original_frame = stored[sec] if sec < len(stored) else None

        frames[str(sec)] = {
            "current_frame":  current_frame,
            "original_frame": original_frame,
        }

    return frames


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_video(
    video_path:     str,
    camera_id:      str,
    video_db_id:    str,
    db:             Session,
    verified_by_id: Optional[str] = None,
    ip_address:     Optional[str] = None,
    user_agent:     Optional[str] = None,
    progress_cb:    Optional[Callable[[int, str], None]] = None,
) -> Dict:
    """
    Verificación de integridad con 4 niveles criptográficos.
    El fichero de entrada debe ser un MP4/H.264 válido.

    Nivel 0 — Hash del fichero completo (INFORMATIVO)
               Compara el SHA-256 del fichero MP4 subido con el hash
               registrado en el momento de la grabación, si existe.
               No determina el veredicto final.

    Nivel 1 — SHA-256 del segmento (INFORMATIVO)
               Puede diferir si el fichero fue remuxado sin re-codificación
               (cambio de contenedor manteniendo el stream H.264 intacto).
               No determina el veredicto final.

    Nivel 2 — Árbol Merkle por segundo (DETERMINANTE del veredicto)
               Hashea los frames RGB decodificados segundo a segundo.
               Un mismatch aquí indica manipulación del contenido visual.

    Nivel 3 — Firma ECDSA P-256 del Merkle root (DETERMINANTE si disponible)
               Valida que el segmento fue firmado por la cámara legítima
               (NIST FIPS 186-5). Si la firma existe y no es válida → FAIL.
    """
    def _cb(pct: int, msg: str):
        if progress_cb:
            progress_cb(pct, msg)

    _cb(2, "Loading stored segments…")

    stored_segments = (
        db.query(Segment)
        .filter(Segment.video_id == video_db_id)
        .order_by(Segment.segment_index)
        .all()
    )
    if not stored_segments:
        raise ValueError(f"No hay segmentos almacenados para el video {video_db_id}")

    # Nivel 0: hash del fichero completo — INFORMATIVO, no bloquea
    video_record     = db.query(Video).filter(Video.id == video_db_id).first()
    stored_file_hash = getattr(video_record, "file_hash", None) if video_record else None
    file_hash_match: Optional[bool] = None
    if stored_file_hash:
        _cb(4, "Checking whole-file hash (informative)…")
        import hashlib as _hl
        with open(video_path, "rb") as f:
            computed_file_hash = _hl.sha256(f.read()).hexdigest()
        file_hash_match = (computed_file_hash == stored_file_hash)

    camera_public_key_pem = _get_camera_public_key(camera_id, db)
    temp_dir = tempfile.mkdtemp(prefix="evideth_verify_")

    try:
        _cb(8, "Segmenting video into 30 s chunks…")
        computed_segments = segment_video(video_path, temp_dir)

        results = []
        total   = passed = failed = missing = 0
        n_segs  = len(computed_segments)

        for i, computed in enumerate(computed_segments):
            idx    = computed["segment_index"]
            total += 1

            seg_pct = int(10 + 80 * (i + 1) / max(n_segs, 1))
            _cb(seg_pct, f"Verifying segment {i + 1}/{n_segs} — Merkle + ECDSA…")

            stored = next(
                (s for s in stored_segments if s.segment_index == idx), None
            )

            if not stored:
                missing += 1
                failed  += 1
                entry = _make_entry(
                    idx=idx, computed=computed, stored=None,
                    hash_match=False, signature_valid=None,
                    merkle_match=None, second_results=None,
                    tampered_frames={},
                    result="fail",
                    detail="Segmento no encontrado en base de datos",
                )
                _save_verification(db, None, entry, verified_by_id, ip_address, user_agent)
                results.append(entry)
                continue

            # ── Nivel 1: hash fichero — INFORMATIVO ──────────────────────────
            # El hash del segmento MP4 puede diferir si el fichero fue remuxado
            # (cambio de contenedor sin re-codificar el stream H.264).
            # No se usa como criterio de veredicto — solo se registra.
            hash_match = computed["sha256_hash"] == stored.sha256_hash

            # ── Nivel 2: Merkle root por segundo — DETERMINANTE ───────────
            computed_merkle = computed.get("merkle_root")
            stored_merkle   = stored.merkle_root
            merkle_match    = None
            second_results  = None
            tampered_frames: Dict[str, Dict] = {}

            if computed_merkle and stored_merkle:
                merkle_match = (computed_merkle == stored_merkle)
                if not merkle_match:
                    second_results = _compare_second_hashes(
                        computed.get("second_hashes", []),
                        stored.second_hashes,
                    )
                    if second_results:
                        work_path = computed.get("file_path", video_path)
                        if os.path.exists(work_path):
                            tampered_frames = _extract_tampered_frames(
                                video_path        = work_path,
                                second_results    = second_results,
                                stored_thumbnails = stored.frame_thumbnails,
                            )

            # ── Nivel 3: firma ECDSA — DETERMINANTE si disponible ──────
            signature_valid = None
            sig_detail      = ""

            if not stored.ecdsa_signature:
                sig_detail = "Sin firma ECDSA (segmento sin firmar)."
            elif not stored.merkle_root:
                sig_detail = "Sin Merkle root almacenado."
            elif not camera_public_key_pem:
                sig_detail = f"Clave pública de '{camera_id}' no registrada."
            else:
                signature_valid = verify_ecdsa_signature(
                    merkle_root    = stored.merkle_root,
                    signature_b64  = stored.ecdsa_signature,
                    public_key_pem = camera_public_key_pem,
                )
                sig_detail = (
                    "✓ Firma ECDSA válida" if signature_valid
                    else "⚠ Firma ECDSA INVÁLIDA"
                )

            # ── Veredicto: basado en Merkle (L2) + ECDSA (L3) ────────────
            # L1 (hash fichero) es informativo — no determina el resultado.
            #
            # PASS si:
            #   - Merkle coincide (o no hay Merkle almacenado)
            #   - ECDSA válida (o no disponible)
            # FAIL si:
            #   - Merkle NO coincide  →  frames manipulados
            #   - ECDSA explícitamente inválida

            tampered_secs = [
                s["second_index"] for s in (second_results or []) if s["tampered"]
            ]

            if signature_valid is False:
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID
                detail = f"⚠ FIRMA ECDSA INVÁLIDA. Merkle: {merkle_match}. Hash fichero (inf.): {hash_match}."

            elif merkle_match is False:
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID
                detail = (
                    f"⚠ Merkle root no coincide: manipulación detectada. "
                    f"Segundos sospechosos: {tampered_secs}. "
                    f"Hash fichero (informativo): {hash_match}. {sig_detail}"
                )

            else:
                passed += 1
                result  = "pass"
                stored.status = SegmentStatus.VALID
                parts = ["✓ Íntegro"]
                if merkle_match is True:      parts.append("Merkle OK")
                if signature_valid is True:   parts.append("ECDSA OK")
                elif signature_valid is None: parts.append(sig_detail)
                if not hash_match:            parts.append("Hash fichero difiere (remux sin re-codificación)")
                detail = " — ".join(parts)

            entry = _make_entry(
                idx=idx, computed=computed, stored=stored,
                hash_match=hash_match, signature_valid=signature_valid,
                merkle_match=merkle_match, second_results=second_results,
                tampered_frames=tampered_frames,
                result=result, detail=detail,
            )
            _save_verification(db, stored, entry, verified_by_id, ip_address, user_agent)
            results.append(entry)

        _cb(92, "Committing results to database…")
        db.commit()

        computed_indices = {s["segment_index"] for s in computed_segments}
        for seg in stored_segments:
            if seg.segment_index not in computed_indices:
                missing += 1
                total   += 1
                results.append({
                    "segment_index":        seg.segment_index,
                    "start_time_secs":      None,
                    "end_time_secs":        None,
                    "duration_secs":        None,
                    "complete":             False,
                    "computed_hash":        None,
                    "stored_hash":          seg.sha256_hash,
                    "hash_match":           False,
                    "signature_valid":      None,
                    "result":               "fail",
                    "detail":               "Segmento en BD pero ausente en el vídeo subido",
                    "computed_merkle_root": None,
                    "stored_merkle_root":   seg.merkle_root,
                    "merkle_match":         None,
                    "second_results":       None,
                    "tampered_frames":      {},
                })

        _cb(96, "Building final report…")
        integrity_ok = (failed == 0 and missing == 0)
        return {
            "video_id":        video_db_id,
            "camera_id":       camera_id,
            "integrity_ok":    integrity_ok,
            "verdict":         "ÍNTEGRO" if integrity_ok else "MANIPULADO O INCOMPLETO",
            "ecdsa_available": camera_public_key_pem is not None,
            "file_hash_match": file_hash_match,
            "summary": {
                "total_segments": total,
                "passed":         passed,
                "failed":         failed,
                "missing":        missing,
            },
            "segments":    results,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        cleanup_segments(temp_dir)
        try:
            os.rmdir(temp_dir)
        except Exception:
            pass


def _make_entry(
    idx:             int,
    computed:        Dict,
    stored:          Optional[object],
    hash_match:      bool,
    signature_valid: Optional[bool],
    merkle_match:    Optional[bool],
    second_results:  Optional[List],
    tampered_frames: Dict,
    result:          str,
    detail:          str,
) -> Dict:
    return {
        "segment_index":        idx,
        "start_time_secs":      computed.get("start_time_secs"),
        "end_time_secs":        computed.get("end_time_secs"),
        "duration_secs":        computed.get("duration_secs"),
        "complete":             computed.get("complete"),
        "computed_hash":        computed.get("sha256_hash"),
        "stored_hash":          stored.sha256_hash if stored else None,
        "hash_match":           hash_match,
        "signature_valid":      signature_valid,
        "result":               result,
        "detail":               detail,
        "computed_merkle_root": computed.get("merkle_root"),
        "stored_merkle_root":   stored.merkle_root if stored else None,
        "merkle_match":         merkle_match,
        "second_results":       second_results,
        "tampered_frames":      tampered_frames,
    }


def _save_verification(
    db:             Session,
    segment:        Optional[object],
    result:         Dict,
    verified_by_id: Optional[str],
    ip_address:     Optional[str],
    user_agent:     Optional[str],
) -> None:
    if segment is None:
        return
    verification = Verification(
        segment_id      = segment.id,
        result          = (
            VerificationResult.PASS if result["result"] == "pass"
            else VerificationResult.FAIL
        ),
        hash_match      = result["hash_match"],
        signature_valid = result["signature_valid"],
        computed_hash   = result["computed_hash"],
        stored_hash     = result["stored_hash"],
        error_message   = result.get("detail") if result["result"] != "pass" else None,
        verified_by_id  = verified_by_id,
        ip_address      = ip_address,
        user_agent      = user_agent,
        verified_at     = datetime.now(timezone.utc),
    )
    db.add(verification)
