import hashlib
import base64
import json
from typing import List, Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db.models import (
    Camera, Segment, Verification, Video,
    SegmentStatus, VerificationResult,
)
from app.services.video_processor import segment_video, cleanup_segments
from app.utils.merkle import build_merkle_root
import tempfile
import os


def verify_ecdsa_signature(
    merkle_root:    str,
    signature_b64:  str,
    public_key_pem: str,
) -> bool:
    """
    Verifica la firma ECDSA P-256 del Merkle root de un segmento.

    CONVENCIÓN (debe coincidir con simulator.py CryptoService.sign()):
        datos firmados = bytes.fromhex(merkle_root)  ← 32 bytes raw del SHA-256
        algoritmo      = ec.ECDSA(hashes.SHA256())
        codificación   = base64url (urlsafe, sin padding)

    Args:
        merkle_root:    Raíz Merkle almacenada, string hex de 64 chars.
        signature_b64:  Firma ECDSA en base64url (generada por el simulador).
        public_key_pem: Clave pública ECDSA P-256 en formato PEM.

    Returns:
        True si la firma es válida, False en caso contrario.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        # Decodificar base64url — el simulador usa urlsafe_b64encode sin padding
        # Se añade "==" para que b64decode no falle con cadenas sin padding
        padded    = signature_b64 + "==" * (4 - len(signature_b64) % 4 if len(signature_b64) % 4 else 0)
        signature = base64.urlsafe_b64decode(padded)

        # Datos firmados: 32 bytes raw del Merkle root
        data = bytes.fromhex(merkle_root)

        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True

    except InvalidSignature:
        return False
    except Exception:
        return False


def _get_camera_public_key(camera_id: str, db: Session) -> Optional[str]:
    """
    Obtiene la clave pública PEM de una cámara por su camera_id.
    Devuelve None si la cámara no existe o no tiene clave registrada.

    La clave pública se registra mediante
    POST /api/v1/cameras/{camera_id}/public-key
    tras el primer arranque del simulador.
    """
    camera = db.query(Camera).filter(Camera.camera_id == camera_id).first()
    if not camera:
        return None
    return getattr(camera, "public_key_pem", None)


def _compare_second_hashes(
    computed_seconds:   List[str],
    stored_seconds_json: Optional[str],
) -> Optional[List[Dict]]:
    """
    Compara los hashes por segundo del vídeo verificado vs. los almacenados.
    Permite identificar exactamente qué segundos fueron manipulados.

    Returns:
        Lista de dicts {second_index, computed_hash, stored_hash, hash_match, tampered},
        o None si no hay datos almacenados (Nivel 2 no disponible).
    """
    if not stored_seconds_json:
        return None

    stored_seconds = json.loads(stored_seconds_json)
    results        = []
    count          = max(len(computed_seconds), len(stored_seconds))
    empty          = hashlib.sha256(b"").hexdigest()

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


def verify_video(
    video_path:     str,
    camera_id:      str,
    video_db_id:    str,
    db:             Session,
    verified_by_id: Optional[str] = None,
    ip_address:     Optional[str] = None,
    user_agent:     Optional[str] = None,
) -> Dict:
    """
    Verificación de integridad con doble nivel criptográfico + firma ECDSA.

    Nivel 1 — SHA-256 del segmento (30 s):
        SHA-256 del fichero completo vs. hash almacenado en BD.
        → Detección rápida: ¿el segmento fue alterado?

    Nivel 2 — Árbol Merkle por segundo:
        SHA-256 de cada chunk de 1 s → árbol Merkle → comparar raíces.
        Si las raíces difieren: se identifican exactamente los segundos alterados.
        → Detección precisa: ¿qué segundo(s) exactamente fueron manipulados?
        Analógico al SPV de Bitcoin (Nakamoto 2008, §7).

    Nivel 3 — Firma ECDSA P-256 del Merkle root:
        Verifica que la cámara firmó el Merkle root en el momento de grabación.
        → Autenticidad: prueba que los datos provienen de la cámara legítima.
        Requiere que la clave pública de la cámara esté registrada en BD
        (POST /api/v1/cameras/{camera_id}/public-key).
    """
    stored_segments = (
        db.query(Segment)
        .filter(Segment.video_id == video_db_id)
        .order_by(Segment.segment_index)
        .all()
    )
    if not stored_segments:
        raise ValueError(f"No hay segmentos almacenados para el video {video_db_id}")

    # Obtener clave pública de la cámara para verificar firmas ECDSA
    camera_public_key_pem = _get_camera_public_key(camera_id, db)

    temp_dir = tempfile.mkdtemp(prefix="evideth_verify_")

    try:
        computed_segments = segment_video(video_path, temp_dir)

        results = []
        total   = passed = failed = missing = 0

        for computed in computed_segments:
            idx    = computed["segment_index"]
            total += 1

            stored = next(
                (s for s in stored_segments if s.segment_index == idx),
                None,
            )

            # ── Segmento no encontrado en BD ──────────────────────────
            if not stored:
                missing += 1
                failed  += 1
                entry = _make_entry(
                    idx=idx,
                    computed=computed,
                    stored=None,
                    hash_match=False,
                    signature_valid=None,
                    merkle_match=None,
                    second_results=None,
                    result="fail",
                    detail="Segmento no encontrado en base de datos",
                )
                _save_verification(db, None, entry, verified_by_id, ip_address, user_agent)
                results.append(entry)
                continue

            # ── Nivel 1: SHA-256 del segmento completo ────────────────
            hash_match = computed["sha256_hash"] == stored.sha256_hash

            # ── Nivel 2: Árbol Merkle + hashes por segundo ─────────────
            computed_merkle = computed.get("merkle_root")
            stored_merkle   = stored.merkle_root
            merkle_match    = None
            second_results  = None

            if computed_merkle and stored_merkle:
                merkle_match = (computed_merkle == stored_merkle)
                if not merkle_match:
                    second_results = _compare_second_hashes(
                        computed.get("second_hashes", []),
                        stored.second_hashes,
                    )

            # ── Nivel 3: Firma ECDSA P-256 del Merkle root ────────────
            signature_valid = None
            sig_detail      = ""

            if not stored.ecdsa_signature:
                sig_detail = "Sin firma ECDSA (segmento sin firmar)."

            elif not stored.merkle_root:
                sig_detail = "Sin Merkle root almacenado — no se puede verificar firma."

            elif not camera_public_key_pem:
                sig_detail = (
                    f"Clave pública de la cámara '{camera_id}' no registrada. "
                    "Registrar con POST /api/v1/cameras/{camera_id}/public-key"
                )

            else:
                # Verificar que la cámara firmó el Merkle root almacenado
                signature_valid = verify_ecdsa_signature(
                    merkle_root    = stored.merkle_root,
                    signature_b64  = stored.ecdsa_signature,
                    public_key_pem = camera_public_key_pem,
                )
                sig_detail = (
                    "✓ Firma ECDSA válida" if signature_valid
                    else "⚠ Firma ECDSA INVÁLIDA — posible suplantación de cámara"
                )

            # ── Resultado final ────────────────────────────────────
            tampered_secs = [
                s["second_index"] for s in (second_results or []) if s["tampered"]
            ]

            if hash_match and merkle_match is not False and signature_valid is not False:
                # Todo correcto (o datos incompletos pero lo que hay es válido)
                passed += 1
                result  = "pass"
                stored.status = SegmentStatus.VALID

                parts = ["\u2713 Íntegro"]
                if merkle_match is True:
                    parts.append("Merkle OK")
                if signature_valid is True:
                    parts.append("ECDSA OK")
                elif signature_valid is None:
                    parts.append(sig_detail)
                detail = " — ".join(parts)

            elif hash_match and merkle_match is False:
                # Hash OK pero Merkle difiere — anomalía forense
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID
                detail = (
                    f"⚠ SHA-256 correcto pero Merkle root no coincide. "
                    f"Segundos sospechosos: {tampered_secs}. {sig_detail}"
                )

            elif signature_valid is False:
                # Firma inválida — posible suplantación
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID
                detail = (
                    f"⚠ FIRMA ECDSA INVÁLIDA — posible suplantación de cámara. "
                    f"Hash match: {hash_match}. Merkle match: {merkle_match}."
                )

            else:
                # Hash no coincide — manipulación confirmada
                failed += 1
                result  = "fail"
                stored.status = SegmentStatus.INVALID
                if tampered_secs:
                    detail = (
                        f"MANIPULACIÓN DETECTADA en segundo(s): {tampered_secs}. "
                        f"Hash esperado: {stored.sha256_hash[:16]}... "
                        f"Calculado: {computed['sha256_hash'][:16]}... {sig_detail}"
                    )
                else:
                    detail = (
                        f"MANIPULACIÓN DETECTADA. "
                        f"Hash esperado: {stored.sha256_hash[:16]}... "
                        f"Calculado: {computed['sha256_hash'][:16]}... {sig_detail}"
                    )

            entry = _make_entry(
                idx=idx,
                computed=computed,
                stored=stored,
                hash_match=hash_match,
                signature_valid=signature_valid,
                merkle_match=merkle_match,
                second_results=second_results,
                result=result,
                detail=detail,
            )
            _save_verification(db, stored, entry, verified_by_id, ip_address, user_agent)
            results.append(entry)

        db.commit()

        # Segmentos en BD que no aparecen en el vídeo subido
        computed_indices = {s["segment_index"] for s in computed_segments}
        for seg in stored_segments:
            if seg.segment_index not in computed_indices:
                missing += 1
                total   += 1
                results.append({
                    "segment_index":        seg.segment_index,
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
                })

        integrity_ok = (failed == 0 and missing == 0)
        return {
            "video_id":     video_db_id,
            "camera_id":    camera_id,
            "integrity_ok": integrity_ok,
            "verdict":      "ÍNTEGRO" if integrity_ok else "MANIPULADO O INCOMPLETO",
            "ecdsa_available": camera_public_key_pem is not None,
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
    result:          str,
    detail:          str,
) -> Dict:
    """Construye el dict de resultado de un segmento para la respuesta y la BD."""
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
    }


def _save_verification(
    db:             Session,
    segment:        Optional[object],
    result:         Dict,
    verified_by_id: Optional[str],
    ip_address:     Optional[str],
    user_agent:     Optional[str],
) -> None:
    """Guarda el resultado de verificación de un segmento en BD."""
    if segment is None:
        return

    verification = Verification(
        segment_id     = segment.id,
        result         = (
            VerificationResult.PASS if result["result"] == "pass"
            else VerificationResult.FAIL
        ),
        hash_match     = result["hash_match"],
        signature_valid= result["signature_valid"],
        computed_hash  = result["computed_hash"],
        stored_hash    = result["stored_hash"],
        error_message  = result.get("detail") if result["result"] != "pass" else None,
        verified_by_id = verified_by_id,
        ip_address     = ip_address,
        user_agent     = user_agent,
        verified_at    = datetime.now(timezone.utc),
    )
    db.add(verification)
