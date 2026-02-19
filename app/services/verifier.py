import hashlib
import base64
from typing import List, Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db.models import Segment, Verification, Video, SegmentStatus, VerificationResult
from app.services.video_processor import segment_video, cleanup_segments
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
    Proceso completo de verificación de integridad:
    1. Segmenta el video en chunks de 30s
    2. Calcula SHA-256 de cada chunk
    3. Compara con hashes almacenados en BD
    4. Verifica firmas ECDSA si existen
    5. Guarda resultados en tabla verifications
    6. Devuelve informe completo
    """

    # Obtiene los segmentos almacenados en BD para este video
    stored_segments = db.query(Segment).filter(
        Segment.video_id == video_db_id
    ).order_by(Segment.segment_index).all()

    if not stored_segments:
        raise ValueError(f"No hay segmentos almacenados para el video {video_db_id}")

    # Segmenta el video subido en directorio temporal
    temp_dir = tempfile.mkdtemp(prefix="evideth_verify_")

    try:
        computed_segments = segment_video(video_path, temp_dir)

        results = []
        total = 0
        passed = 0
        failed = 0
        missing = 0

        for computed in computed_segments:
            idx = computed["segment_index"]
            total += 1

            # Busca el segmento almacenado correspondiente
            stored = next(
                (s for s in stored_segments if s.segment_index == idx),
                None
            )

            # ── Segmento no encontrado en BD ──────────────
            if not stored:
                missing += 1
                result_entry = {
                    "segment_index":  idx,
                    "start_time_secs": computed["start_time_secs"],
                    "end_time_secs":   computed["end_time_secs"],
                    "duration_secs":   computed["duration_secs"],
                    "complete":        computed["complete"],
                    "computed_hash":   computed["sha256_hash"],
                    "stored_hash":     None,
                    "hash_match":      False,
                    "signature_valid": None,
                    "result":          "fail",
                    "detail":          "Segmento no encontrado en base de datos"
                }
                # Guarda en BD
                _save_verification(
                    db, stored, result_entry,
                    verified_by_id, ip_address, user_agent
                )
                results.append(result_entry)
                failed += 1
                continue

            # ── Compara hashes SHA-256 ─────────────────────
            hash_match = computed["sha256_hash"] == stored.sha256_hash

            # ── Verifica firma ECDSA si existe ─────────────
            signature_valid = None
            if stored.ecdsa_signature and stored.public_key_id:
                # TODO: obtener clave pública desde Azure Key Vault
                # Por ahora se marca como no verificada
                signature_valid = None
                detail = "Hash verificado. Firma ECDSA pendiente de Azure Key Vault."
            elif stored.ecdsa_signature:
                signature_valid = None
                detail = "Hash verificado. Firma ECDSA presente pero sin clave pública."
            else:
                detail = "Hash verificado. Sin firma ECDSA (segmento PENDING)."

            # ── Determina resultado final ──────────────────
            if hash_match:
                passed += 1
                result = "pass"
                # Actualiza estado del segmento en BD
                stored.status = SegmentStatus.VALID
            else:
                failed += 1
                result = "fail"
                detail = f"MANIPULACIÓN DETECTADA. Hash esperado: {stored.sha256_hash[:16]}... | Calculado: {computed['sha256_hash'][:16]}..."
                # Marca segmento como inválido
                stored.status = SegmentStatus.INVALID

            result_entry = {
                "segment_index":   idx,
                "start_time_secs": computed["start_time_secs"],
                "end_time_secs":   computed["end_time_secs"],
                "duration_secs":   computed["duration_secs"],
                "complete":        computed["complete"],
                "computed_hash":   computed["sha256_hash"],
                "stored_hash":     stored.sha256_hash,
                "hash_match":      hash_match,
                "signature_valid": signature_valid,
                "result":          result,
                "detail":          detail
            }

            # Guarda verificación en BD
            _save_verification(
                db, stored, result_entry,
                verified_by_id, ip_address, user_agent
            )
            results.append(result_entry)

        db.commit()

        # ── Segmentos en BD que no están en el video ───────
        computed_indices = {s["segment_index"] for s in computed_segments}
        for stored in stored_segments:
            if stored.segment_index not in computed_indices:
                missing += 1
                total += 1
                results.append({
                    "segment_index":   stored.segment_index,
                    "computed_hash":   None,
                    "stored_hash":     stored.sha256_hash,
                    "hash_match":      False,
                    "signature_valid": None,
                    "result":          "fail",
                    "detail":          "Segmento presente en BD pero falta en el video subido"
                })

        # ── Informe final ──────────────────────────────────
        integrity_ok = failed == 0 and missing == 0

        return {
            "video_id":     video_db_id,
            "camera_id":    camera_id,
            "integrity_ok": integrity_ok,
            "verdict":      "ÍNTEGRO" if integrity_ok else "MANIPULADO O INCOMPLETO",
            "summary": {
                "total_segments":   total,
                "passed":           passed,
                "failed":           failed,
                "missing":          missing,
            },
            "segments": results,
            "verified_at": datetime.now(timezone.utc).isoformat()
        }

    finally:
        # Limpia archivos temporales siempre
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
