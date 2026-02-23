import hashlib
import base64
import json
from typing import List, Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db.models import Segment, Verification, Video, SegmentStatus, VerificationResult
from app.services.video_processor import segment_video, cleanup_segments
from app.utils.merkle import build_merkle_root
import tempfile
import os


def verify_ecdsa_signature(
    sha256_hash: str,
    signature_b64: str,
    public_key_pem: str
) -> bool:
    """
    Verifica la firma ECDSA P-256 de un hash SHA-256.
    - sha256_hash: string hexadecimal de 64 chars
    - signature_b64: firma en base64
    - public_key_pem: clave pública en formato PEM
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        signature = base64.b64decode(signature_b64)
        data = bytes.fromhex(sha256_hash)

        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except (InvalidSignature, Exception):
        return False


def _compare_second_hashes(
    computed_seconds: List[str],
    stored_seconds_json: Optional[str]
) -> Optional[List[Dict]]:
    """
    Compara los hashes por segundo del video verificado contra los almacenados.
    Devuelve lista de SecondHashResult dicts, o None si no hay datos almacenados.
    Permite identificar exactamente qué segundos fueron manipulados.
    """
    if not stored_seconds_json:
        return None

    stored_seconds = json.loads(stored_seconds_json)
    results = []
    count = max(len(computed_seconds), len(stored_seconds))

    for i in range(count):
        comp = computed_seconds[i] if i < len(computed_seconds) else hashlib.sha256(b"").hexdigest()
        stor = stored_seconds[i]   if i < len(stored_seconds)  else None
        match = (comp == stor) if stor is not None else False
        results.append({
            "second_index":  i,
            "computed_hash": comp,
            "stored_hash":   stor,
            "hash_match":    match,
            "tampered":      not match,
        })

    return results


def verify_video(
    video_path: str,
    camera_id: str,
    video_db_id: str,
    db: Session,
    verified_by_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict:
    """
    Verificación de integridad con doble nivel criptográfico:

    **Nivel 1 — Segmento (30 s):**
        SHA-256 del segmento completo vs. hash almacenado en BD.
        → Detección rápida: ¿el segmento fue alterado?

    **Nivel 2 — Segundo (1 s) + Árbol Merkle:**
        SHA-256 de cada chunk de 1 s → árbol Merkle → comparar raíces.
        Si las raíces difieren: se identifican exactamente los segundos alterados.
        → Detección precisa: ¿qué segundo(s) exactamente fueron manipulados?
        Análogo al árbol Merkle de Bitcoin para localizar transacciones sin
        descargar el bloque completo (Nakamoto 2008, §7).

    Nota: El Nivel 2 requiere que el daemon de cámara almacene `merkle_root`
    y `second_hashes` en la BD. Si estos campos son NULL, se usa solo Nivel 1.
    """

    stored_segments = db.query(Segment).filter(
        Segment.video_id == video_db_id
    ).order_by(Segment.segment_index).all()

    if not stored_segments:
        raise ValueError(f"No hay segmentos almacenados para el video {video_db_id}")

    temp_dir = tempfile.mkdtemp(prefix="evideth_verify_")

    try:
        computed_segments = segment_video(video_path, temp_dir)

        results  = []
        total    = 0
        passed   = 0
        failed   = 0
        missing  = 0

        for computed in computed_segments:
            idx   = computed["segment_index"]
            total += 1

            stored = next(
                (s for s in stored_segments if s.segment_index == idx),
                None
            )

            # ── Segmento no encontrado en BD ──────────────────────────────
            if not stored:
                missing += 1
                failed  += 1
                result_entry = {
                    "segment_index":       idx,
                    "start_time_secs":     computed["start_time_secs"],
                    "end_time_secs":       computed["end_time_secs"],
                    "duration_secs":       computed["duration_secs"],
                    "complete":            computed["complete"],
                    "computed_hash":       computed["sha256_hash"],
                    "stored_hash":         None,
                    "hash_match":          False,
                    "signature_valid":     None,
                    "result":              "fail",
                    "detail":              "Segmento no encontrado en base de datos",
                    "computed_merkle_root": computed.get("merkle_root"),
                    "stored_merkle_root":   None,
                    "merkle_match":         None,
                    "second_results":       None,
                }
                _save_verification(db, None, result_entry, verified_by_id, ip_address, user_agent)
                results.append(result_entry)
                continue

            # ── Nivel 1: SHA-256 del segmento completo ────────────────────
            hash_match = computed["sha256_hash"] == stored.sha256_hash

            # ── Nivel 2: Árbol Merkle + hashes por segundo ────────────────
            computed_merkle = computed.get("merkle_root")
            stored_merkle   = stored.merkle_root
            merkle_match    = None
            second_results  = None

            if computed_merkle and stored_merkle:
                merkle_match = (computed_merkle == stored_merkle)

                if not merkle_match:
                    # Localizar segundos manipulados mediante comparación de hojas
                    second_results = _compare_second_hashes(
                        computed.get("second_hashes", []),
                        stored.second_hashes
                    )

            # ── Verifica firma ECDSA si existe ────────────────────────────
            signature_valid = None
            if stored.ecdsa_signature and stored.public_key_id:
                # TODO: obtener clave pública desde Azure Key Vault
                signature_valid = None
                detail = "Firma ECDSA pendiente de Azure Key Vault."
            elif not stored.ecdsa_signature:
                detail = "Sin firma ECDSA (segmento PENDING)."
            else:
                detail = "Firma ECDSA presente pero sin clave pública."

            # ── Determina resultado final ──────────────────────────────────
            if hash_match and merkle_match is not False:
                # Nivel 1 OK y Nivel 2 OK (o no disponible)
                passed += 1
                result  = "pass"
                stored.status = SegmentStatus.VALID
                if merkle_match is True:
                    detail = "✓ Íntegro — SHA-256 de segmento y Merkle root coinciden"
                else:
                    detail = "✓ Íntegro — SHA-256 de segmento verificado (Merkle N/D)"

            elif hash_match and merkle_match is False:
                # Anomalía: hash de segmento OK pero Merkle difiere
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID
                tampered = [s["second_index"] for s in (second_results or []) if s["tampered"]]
                detail = (
                    f"⚠ SHA-256 de segmento correcto pero Merkle root no coincide. "
                    f"Segundos sospechosos: {tampered}"
                )
            else:
                # Nivel 1 falla → manipulación confirmada
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID
                tampered = [s["second_index"] for s in (second_results or []) if s["tampered"]]
                if tampered:
                    detail = (
                        f"MANIPULACIÓN DETECTADA en segundo(s): {tampered}. "
                        f"Hash esperado: {stored.sha256_hash[:16]}... "
                        f"Calculado: {computed['sha256_hash'][:16]}..."
                    )
                else:
                    detail = (
                        f"MANIPULACIÓN DETECTADA. "
                        f"Hash esperado: {stored.sha256_hash[:16]}... "
                        f"Calculado: {computed['sha256_hash'][:16]}..."
                    )

            result_entry = {
                "segment_index":       idx,
                "start_time_secs":     computed["start_time_secs"],
                "end_time_secs":       computed["end_time_secs"],
                "duration_secs":       computed["duration_secs"],
                "complete":            computed["complete"],
                "computed_hash":       computed["sha256_hash"],
                "stored_hash":         stored.sha256_hash,
                "hash_match":          hash_match,
                "signature_valid":     signature_valid,
                "result":              result,
                "detail":              detail,
                "computed_merkle_root": computed_merkle,
                "stored_merkle_root":   stored_merkle,
                "merkle_match":         merkle_match,
                "second_results":       second_results,
            }

            _save_verification(db, stored, result_entry, verified_by_id, ip_address, user_agent)
            results.append(result_entry)

        db.commit()

        # ── Segmentos en BD que no están en el video subido ───────────────
        computed_indices = {s["segment_index"] for s in computed_segments}
        for stored_seg in stored_segments:
            if stored_seg.segment_index not in computed_indices:
                missing += 1
                total   += 1
                results.append({
                    "segment_index":       stored_seg.segment_index,
                    "computed_hash":       None,
                    "stored_hash":         stored_seg.sha256_hash,
                    "hash_match":          False,
                    "signature_valid":     None,
                    "result":              "fail",
                    "detail":              "Segmento en BD pero ausente en el video subido",
                    "computed_merkle_root": None,
                    "stored_merkle_root":   stored_seg.merkle_root,
                    "merkle_match":         None,
                    "second_results":       None,
                })

        integrity_ok = (failed == 0 and missing == 0)

        return {
            "video_id":     video_db_id,
            "camera_id":    camera_id,
            "integrity_ok": integrity_ok,
            "verdict":      "ÍNTEGRO" if integrity_ok else "MANIPULADO O INCOMPLETO",
            "summary": {
                "total_segments": total,
                "passed":         passed,
                "failed":         failed,
                "missing":        missing,
            },
            "segments":     results,
            "verified_at":  datetime.now(timezone.utc).isoformat(),
        }

    finally:
        cleanup_segments(temp_dir)
        try:
            os.rmdir(temp_dir)
        except Exception:
            pass


def _save_verification(
    db: Session,
    segment: Optional[Segment],
    result: Dict,
    verified_by_id: Optional[str],
    ip_address: Optional[str],
    user_agent: Optional[str]
):
    """Guarda el resultado de verificación de un segmento en BD."""
    if segment is None:
        return

    verification = Verification(
        segment_id=segment.id,
        result=VerificationResult.PASS if result["result"] == "pass" else VerificationResult.FAIL,
        hash_match=result["hash_match"],
        signature_valid=result["signature_valid"],
        computed_hash=result["computed_hash"],
        stored_hash=result["stored_hash"],
        error_message=result.get("detail") if result["result"] != "pass" else None,
        verified_by_id=verified_by_id,
        ip_address=ip_address,
        user_agent=user_agent,
        verified_at=datetime.now(timezone.utc)
    )
    db.add(verification)
