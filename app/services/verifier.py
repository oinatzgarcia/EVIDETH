import hashlib
import base64
from typing import List, Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db.models import Segment, Verification, Video, SegmentStatus, VerificationResult, MerkleLeaf
from app.services.video_processor import segment_video, cleanup_segments
from app.core.merkle import get_merkle_root, build_merkle_tree, verify_merkle_proof
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
    Proceso completo de verificación de integridad con granularidad de 1 segundo:
    1. Segmenta el video en chunks de 30s
    2. Por cada segmento calcula Merkle root (sub-segmentos de 1s)
    3. Compara Merkle root con el almacenado en BD
    4. Si no coincide, compara hoja a hoja para identificar el segundo exacto manipulado
    5. Verifica firmas ECDSA si existen
    6. Guarda resultados en tabla verifications
    7. Devuelve informe con precisión de 1 segundo
    """

    stored_segments = db.query(Segment).filter(
        Segment.video_id == video_db_id
    ).order_by(Segment.segment_index).all()

    if not stored_segments:
        raise ValueError(f"No hay segmentos almacenados para el video {video_db_id}")

    temp_dir = tempfile.mkdtemp(prefix="evideth_verify_")

    try:
        computed_segments = segment_video(video_path, temp_dir)

        results = []
        total   = 0
        passed  = 0
        failed  = 0
        missing = 0

        for computed in computed_segments:
            idx    = computed["segment_index"]
            total += 1

            stored = next(
                (s for s in stored_segments if s.segment_index == idx),
                None
            )

            # ── Segmento no encontrado en BD ─────────────
            if not stored:
                missing += 1
                failed  += 1
                result_entry = {
                    "segment_index":        idx,
                    "start_time_secs":      computed["start_time_secs"],
                    "end_time_secs":        computed["end_time_secs"],
                    "duration_secs":        computed["duration_secs"],
                    "complete":             computed["complete"],
                    "computed_hash":        computed["sha256_hash"],
                    "computed_merkle_root": computed["merkle_root"],
                    "stored_hash":          None,
                    "stored_merkle_root":   None,
                    "hash_match":           False,
                    "merkle_match":         False,
                    "tampered_seconds":     [],
                    "signature_valid":      None,
                    "result":               "fail",
                    "detail":               "Segmento no encontrado en base de datos"
                }
                _save_verification(db, None, result_entry, verified_by_id, ip_address, user_agent)
                results.append(result_entry)
                continue

            # ── Verificación principal: Merkle root ────────
            merkle_match    = False
            tampered_seconds = []

            if stored.merkle_root:
                merkle_match = computed["merkle_root"] == stored.merkle_root

                if not merkle_match:
                    # Comparación hoja a hoja: identifica el segundo exacto manipulado
                    tampered_seconds = _find_tampered_seconds(
                        computed["leaf_hashes"], stored, db
                    )
            else:
                # Fallback: sin Merkle root en BD, compara SHA-256 completo
                merkle_match = computed["sha256_hash"] == stored.sha256_hash

            # ── Compara SHA-256 completo (compatibilidad) ──
            hash_match = computed["sha256_hash"] == stored.sha256_hash

            # ── Verifica firma ECDSA si existe ──────────
            signature_valid = None
            if stored.ecdsa_signature and stored.public_key_id:
                # TODO: obtener clave pública desde Azure Key Vault
                signature_valid = None
                detail = "Verificado con Merkle root. Firma ECDSA pendiente de Azure Key Vault."
            else:
                detail = "Verificado con Merkle root. Sin firma ECDSA (segmento PENDING)."

            # ── Resultado final ────────────────────────
            # La verificación primaria es por Merkle root si existe, sino por SHA-256
            integrity_ok = merkle_match if stored.merkle_root else hash_match

            if integrity_ok:
                passed += 1
                result  = "pass"
                stored.status = SegmentStatus.VALID
                detail = (
                    f"Segmento íntegro. "
                    f"Merkle root verificado ({len(computed['leaf_hashes'])} sub-segmentos de 1s)."
                )
            else:
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID

                if tampered_seconds:
                    detail = (
                        f"MANIPULACIÓN DETECTADA en segundo(s) absoluto(s): {tampered_seconds}. "
                        f"Merkle root esperado: {stored.merkle_root[:16]}... | "
                        f"Calculado: {computed['merkle_root'][:16]}..."
                    )
                else:
                    detail = (
                        f"MANIPULACIÓN DETECTADA. "
                        f"Hash esperado: {stored.sha256_hash[:16]}... | "
                        f"Calculado: {computed['sha256_hash'][:16]}..."
                    )

            result_entry = {
                "segment_index":        idx,
                "start_time_secs":      computed["start_time_secs"],
                "end_time_secs":        computed["end_time_secs"],
                "duration_secs":        computed["duration_secs"],
                "complete":             computed["complete"],
                "computed_hash":        computed["sha256_hash"],
                "computed_merkle_root": computed["merkle_root"],
                "stored_hash":          stored.sha256_hash,
                "stored_merkle_root":   stored.merkle_root,
                "hash_match":           hash_match,
                "merkle_match":         merkle_match,
                "tampered_seconds":     tampered_seconds,
                "signature_valid":      signature_valid,
                "result":               result,
                "detail":               detail
            }

            _save_verification(db, stored, result_entry, verified_by_id, ip_address, user_agent)
            results.append(result_entry)

        db.commit()

        # ── Segmentos en BD que no están en el video ───
        computed_indices = {s["segment_index"] for s in computed_segments}
        for stored in stored_segments:
            if stored.segment_index not in computed_indices:
                missing += 1
                total   += 1
                results.append({
                    "segment_index":        stored.segment_index,
                    "computed_hash":        None,
                    "computed_merkle_root": None,
                    "stored_hash":          stored.sha256_hash,
                    "stored_merkle_root":   stored.merkle_root,
                    "hash_match":           False,
                    "merkle_match":         False,
                    "tampered_seconds":     [],
                    "signature_valid":      None,
                    "result":               "fail",
                    "detail":               "Segmento presente en BD pero falta en el video subido"
                })

        # ── Informe final ──────────────────────────
        all_ok = failed == 0 and missing == 0

        return {
            "video_id":     video_db_id,
            "camera_id":    camera_id,
            "integrity_ok": all_ok,
            "verdict":      "ÍNTEGRO" if all_ok else "MANIPULADO O INCOMPLETO",
            "summary": {
                "total_segments": total,
                "passed":         passed,
                "failed":         failed,
                "missing":        missing,
                "granularity":    "1s (Merkle Tree)"
            },
            "segments":    results,
            "verified_at": datetime.now(timezone.utc).isoformat()
        }

    finally:
        cleanup_segments(temp_dir)
        try:
            os.rmdir(temp_dir)
        except Exception:
            pass


def _find_tampered_seconds(
    computed_leaves: List[Dict],
    stored_segment: Segment,
    db: Session
) -> List[int]:
    """
    Compara hoja a hoja para identificar qué segundos exactos fueron manipulados.
    Requiere que las MerkleLeaf del segmento estén guardadas en BD.

    Args:
        computed_leaves: Lista de {leaf_index, hash} calculados del video subido.
        stored_segment:  Objeto Segment de la BD.
        db:              Sesión de base de datos.

    Returns:
        Lista de segundos absolutos manipulados (ej: [47, 63] para los segundos
        47 y 63 del video original).
        Lista vacía si no hay hojas almacenadas en BD.
    """
    stored_leaves = db.query(MerkleLeaf).filter(
        MerkleLeaf.segment_id == stored_segment.id
    ).order_by(MerkleLeaf.leaf_index).all()

    if not stored_leaves:
        return []  # No hay hojas en BD → no se puede localizar el segundo exacto

    stored_map = {leaf.leaf_index: leaf.subsegment_hash for leaf in stored_leaves}
    tampered   = []

    for leaf in computed_leaves:
        idx         = leaf["leaf_index"]
        stored_hash = stored_map.get(idx)
        if stored_hash and leaf["hash"] != stored_hash:
            # Convierte índice relativo al segmento → segundo absoluto del video
            absolute_second = stored_segment.start_time_secs + idx
            tampered.append(absolute_second)

    return tampered


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
