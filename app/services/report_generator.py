"""
EVIDETH Report Generator
========================
Servicio de generacion de informes forenses en PDF y CSV.

Uso:
    from app.services.report_generator import (
        generate_video_report_pdf,
        generate_video_csv,
        generate_verifications_csv,
    )

Dependencia: fpdf2>=2.7.0
"""
from fpdf import FPDF
from io import StringIO
import csv
from datetime import datetime, timezone
from typing import Optional


# ── Paleta de colores EVIDETH ──────────────────────
_BG_HEADER    = (15,  23,  42)   # slate-900
_FG_WHITE     = (255, 255, 255)
_BG_SUBHEADER = (51,  65,  85)   # slate-700
_BG_SECTION   = (226, 232, 240)  # slate-200
_FG_SECTION   = (30,  41,  59)   # slate-800
_FG_LABEL     = (71,  85,  105)  # slate-500
_BG_TH        = (30,  41,  59)   # slate-800
_BG_VALID     = (240, 253, 244)  # green-50
_BG_INVALID   = (254, 242, 242)  # red-50
_BG_MISSING   = (254, 249, 195)  # yellow-50
_BG_PENDING   = (248, 250, 252)  # slate-50
_VERDICT_OK   = (21,  128, 61)   # green-700
_VERDICT_KO   = (185, 28,  28)   # red-700


def _safe(value, max_len: int = 80) -> str:
    """Convierte un valor a str seguro para fpdf2 (truncado, sin None)."""
    if value is None:
        return "-"
    s = str(value)
    return (s[:max_len - 3] + "...") if len(s) > max_len else s


def _trunc_hash(h: Optional[str], n: int = 24) -> str:
    """Trunca un hash hex para que quepa en la tabla del PDF."""
    if not h:
        return "-"
    return h[:n] + "..." if len(h) > n else h


# ── Clase PDF ─────────────────────────────────────

class EvidethPDF(FPDF):
    """Subclase FPDF con cabecera, pie y helpers de estilo para EVIDETH."""

    def header(self):
        # Banda principal
        self.set_fill_color(*_BG_HEADER)
        self.set_text_color(*_FG_WHITE)
        self.set_font("Helvetica", "B", 13)
        self.cell(0, 11, "EVIDETH - Sistema de Verificacion de Integridad de Video",
                  border=0, align="C", fill=True)
        self.ln()
        # Sub-banda
        self.set_fill_color(*_BG_SUBHEADER)
        self.set_font("Helvetica", "", 7)
        self.cell(0, 5, "  Informe Forense de Integridad  |  Ingenieria de Ciberseguridad 2026",
                  border=0, align="L", fill=True)
        self.ln()
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-13)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(120, 120, 120)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.cell(0, 8,
                  f"EVIDETH v2.0  |  {ts}  |  Pagina {self.page_no()}  |  DOCUMENTO CONFIDENCIAL",
                  align="C")

    def section_title(self, title: str) -> None:
        """Barra de titulo de seccion con fondo gris slate."""
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(*_BG_SECTION)
        self.set_text_color(*_FG_SECTION)
        self.cell(0, 7, f"  {title}", border=0, fill=True)
        self.ln()
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def kv_row(self, key: str, value: str, col_w: int = 55) -> None:
        """Fila clave-valor alineada en dos columnas."""
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*_FG_LABEL)
        self.cell(col_w, 5, f"  {key}")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(0, 0, 0)
        self.cell(0, 5, value)
        self.ln()
        self.ln(0.3)


# ── Generador PDF ─────────────────────────────────

def generate_video_report_pdf(
    video,
    camera,
    segments,
    verifications,
    analyst=None,
) -> bytes:
    """
    Genera el informe PDF forense completo para un video.

    Args:
        video:         ORM objeto Video
        camera:        ORM objeto Camera (puede ser None)
        segments:      lista de ORM Segment, ordenados por segment_index
        verifications: lista de ORM Verification
        analyst:       ORM objeto User que genera el informe (opcional)

    Returns:
        bytes del PDF listo para devolver como Response
    """
    pdf = EvidethPDF(orientation="L", unit="mm", format="A4")
    pdf.set_margins(10, 10, 10)
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Anchos de las dos columnas (total printable = 277mm)
    L_W = 133   # columna izquierda
    GAP = 7     # separacion
    R_W = 137   # columna derecha  (277 - 133 - 7 = 137)
    LM  = 10    # left margin

    # ── Columna izquierda ─────────────────────────────
    left_y = pdf.get_y()

    # Bloque: datos del informe
    pdf.set_fill_color(*_BG_SECTION);  pdf.set_text_color(*_FG_SECTION)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(L_W, 6, "  DATOS DEL INFORME", fill=True); pdf.ln()
    pdf.set_text_color(0, 0, 0)
    for k, v in [
        ("Fecha de generacion:",  now_str),
        ("Analista:",             _safe(analyst.full_name if analyst else "Sistema EVIDETH", 40)),
        ("ID del informe:",       str(video.id)),
    ]:
        pdf.set_font("Helvetica", "B", 7); pdf.set_text_color(*_FG_LABEL)
        pdf.cell(44, 4.2, f"  {k}")
        pdf.set_font("Helvetica", "",  7); pdf.set_text_color(0, 0, 0)
        pdf.cell(L_W - 44, 4.2, v)
        pdf.ln()
    pdf.ln(3)

    # Bloque: informacion del video
    pdf.set_fill_color(*_BG_SECTION);  pdf.set_text_color(*_FG_SECTION)
    pdf.set_font("Helvetica", "B", 8")
    pdf.cell(L_W, 6, "  INFORMACION DEL VIDEO", fill=True); pdf.ln()
    pdf.set_text_color(0, 0, 0)
    for k, v in [
        ("Nombre:",        _safe(video.filename, 50)),
        ("ID Video:",      str(video.id)),
        ("Estado:",        str(video.status).upper()),
        ("Duracion:",      f"{video.duration_secs}s" if video.duration_secs else "-"),
        ("Resolucion:",    _safe(video.resolution)),
        ("Codec:",         _safe(video.codec)),
        ("FPS:",           str(video.fps) if video.fps else "-"),
        ("Inicio grab.:",  str(video.started_at)[:19] if video.started_at else "-"),
        ("Fin grab.:",     str(video.ended_at)[:19]   if video.ended_at   else "-"),
    ]:
        pdf.set_font("Helvetica", "B", 7); pdf.set_text_color(*_FG_LABEL)
        pdf.cell(44, 4.2, f"  {k}")
        pdf.set_font("Helvetica", "",  7); pdf.set_text_color(0, 0, 0)
        pdf.cell(L_W - 44, 4.2, v)
        pdf.ln()

    left_end_y = pdf.get_y()

    # ── Columna derecha ───────────────────────────────
    # Calcula estadisticas de integridad
    total_seg    = len(segments)
    valid_segs   = sum(1 for s in segments if str(s.status) == "valid")
    invalid_segs = sum(1 for s in segments if str(s.status) == "invalid")
    missing_segs = sum(1 for s in segments if str(s.status) == "missing")
    pending_segs = sum(1 for s in segments if str(s.status) == "pending")
    integrity_ok = (invalid_segs == 0 and missing_segs == 0 and total_seg > 0)
    rate         = round(valid_segs / total_seg * 100, 1) if total_seg > 0 else 0.0

    right_x = LM + L_W + GAP
    cur_y   = left_y

    # Bloque: camara
    pdf.set_xy(right_x, cur_y)
    pdf.set_fill_color(*_BG_SECTION);  pdf.set_text_color(*_FG_SECTION)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(R_W, 6, "  INFORMACION DE LA CAMARA", fill=True)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)
    for k, v in [
        ("ID Camara:",   _safe(camera.camera_id   if camera else None)),
        ("Nombre:",      _safe(camera.name        if camera else None, 45)),
        ("Ubicacion:",   _safe(camera.location    if camera else None, 45)),
        ("Descripcion:", _safe(camera.description if camera else None, 45)),
    ]:
        pdf.set_x(right_x)
        pdf.set_font("Helvetica", "B", 7); pdf.set_text_color(*_FG_LABEL)
        pdf.cell(44, 4.2, f"  {k}")
        pdf.set_font("Helvetica", "",  7); pdf.set_text_color(0, 0, 0)
        pdf.cell(R_W - 44, 4.2, v)
        pdf.ln()
    pdf.ln(3)

    # Bloque: resumen de integridad
    pdf.set_x(right_x)
    pdf.set_fill_color(*_BG_SECTION);  pdf.set_text_color(*_FG_SECTION)
    pdf.set_font("Helvetica", "B", 8")
    pdf.cell(R_W, 6, "  RESUMEN DE INTEGRIDAD", fill=True)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)
    for k, v in [
        ("Total segmentos:",  str(total_seg)),
        ("Validos:",          f"{valid_segs}  ({rate}%)"),
        ("Invalidos:",        str(invalid_segs)),
        ("Ausentes:",         str(missing_segs)),
        ("Pendientes:",       str(pending_segs)),
    ]:
        pdf.set_x(right_x)
        pdf.set_font("Helvetica", "B", 7); pdf.set_text_color(*_FG_LABEL)
        pdf.cell(44, 4.2, f"  {k}")
        pdf.set_font("Helvetica", "B" if (v != "0" and k != "Total segmentos:") else "", 7)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(R_W - 44, 4.2, v)
        pdf.ln()

    right_end_y = pdf.get_y()

    # ── Veredicto ─────────────────────────────────────
    pdf.set_y(max(left_end_y, right_end_y) + 5)
    verdict = "INTEGRO" if integrity_ok else "MANIPULADO O INCOMPLETO"
    pdf.set_fill_color(*(_VERDICT_OK if integrity_ok else _VERDICT_KO))
    pdf.set_text_color(*_FG_WHITE)
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 13, f"  VEREDICTO: {verdict}", fill=True)
    pdf.ln()
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # ── Tabla de segmentos ────────────────────────────
    pdf.section_title("TABLA DE SEGMENTOS")

    # Anchos de columna (total = 277mm para landscape A4 con margenes de 10mm)
    COL = [12, 15, 15, 60, 60, 16, 16, 18, 65]
    HDR = ["Seg.", "Inicio", "Fin",
           "Hash SHA-256 almacenado", "Hash SHA-256 calculado",
           "Hash OK", "Firma OK", "Estado", "Mensaje"]

    # Cabecera de tabla
    pdf.set_font("Helvetica", "B", 6)
    pdf.set_fill_color(*_BG_TH)
    pdf.set_text_color(*_FG_WHITE)
    for w, h in zip(COL, HDR):
        pdf.cell(w, 6, h, border=1, fill=True, align="C")
    pdf.ln()
    pdf.set_text_color(0, 0, 0)

    # Lookup: segment_id -> verificacion mas reciente
    verif_by_seg: dict = {}
    for v in sorted(verifications, key=lambda x: (x.verified_at or datetime.min)):
        verif_by_seg[str(v.segment_id)] = v

    pdf.set_font("Helvetica", "", 5.5)
    for seg in sorted(segments, key=lambda s: s.segment_index):
        v   = verif_by_seg.get(str(seg.id))
        st  = str(seg.status)
        bg  = {"valid": _BG_VALID, "invalid": _BG_INVALID,
               "missing": _BG_MISSING}.get(st, _BG_PENDING)
        pdf.set_fill_color(*bg)

        hash_ok  = ("SI" if v.hash_match      else "NO") if v and v.hash_match      is not None else "-"
        sig_ok   = ("SI" if v.signature_valid else "NO") if v and v.signature_valid is not None else "-"
        stored   = _trunc_hash(seg.sha256_hash)
        computed = _trunc_hash(v.computed_hash if v else None)
        error    = _safe(v.error_message if v else None, 40)

        for w, cell_val in zip(COL, [
            str(seg.segment_index),
            f"{seg.start_time_secs}s",
            f"{seg.end_time_secs}s",
            stored, computed,
            hash_ok, sig_ok,
            st.upper(), error,
        ]):
            pdf.cell(w, 5, cell_val, border=1, fill=True, align="C")
        pdf.ln()

    return bytes(pdf.output())


# ── Generador CSV por video ──────────────────────────

def generate_video_csv(video, camera, segments, verifications) -> str:
    """
    Genera un CSV con todos los segmentos de un video y sus verificaciones.
    Compatible con Excel (se debe devolver con BOM utf-8-sig).
    """
    output = StringIO()
    w = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Cabecera de metadatos
    w.writerow(["# EVIDETH - Exportacion CSV de Segmentos"])
    w.writerow(["# Video ID",    str(video.id)])
    w.writerow(["# Filename",    str(video.filename)])
    w.writerow(["# Camera ID",   camera.camera_id if camera else "-"])
    w.writerow(["# Camera Name", camera.name      if camera else "-"])
    w.writerow(["# Generated",   datetime.now(timezone.utc).isoformat()])
    w.writerow([])

    # Cabecera de columnas
    w.writerow([
        "segment_index", "start_time_secs", "end_time_secs", "duration_secs",
        "sha256_hash", "ecdsa_signature", "segment_status", "signed_at",
        "hash_match", "signature_valid", "computed_hash", "stored_hash",
        "verification_result", "error_message", "verified_at", "ip_address",
    ])

    # Lookup: segment_id -> verificacion mas reciente
    verif_by_seg: dict = {}
    for v in sorted(verifications, key=lambda x: (x.verified_at or datetime.min)):
        verif_by_seg[str(v.segment_id)] = v

    for seg in sorted(segments, key=lambda s: s.segment_index):
        v = verif_by_seg.get(str(seg.id))
        w.writerow([
            seg.segment_index,
            seg.start_time_secs,
            seg.end_time_secs,
            seg.duration_secs   or "",
            seg.sha256_hash     or "",
            seg.ecdsa_signature or "",
            str(seg.status),
            seg.signed_at.isoformat() if seg.signed_at else "",
            # Verificacion (puede no existir)
            ("true" if v.hash_match      else "false") if v and v.hash_match      is not None else "",
            ("true" if v.signature_valid else "false") if v and v.signature_valid is not None else "",
            v.computed_hash  or "" if v else "",
            v.stored_hash    or "" if v else "",
            str(v.result)       if v else "",
            v.error_message  or "" if v else "",
            v.verified_at.isoformat() if v and v.verified_at else "",
            v.ip_address     or "" if v else "",
        ])

    return output.getvalue()


# ── Generador CSV masivo de verificaciones ───────────────

def generate_verifications_csv(verifications_data: list) -> str:
    """
    Genera un CSV de una lista de verificaciones (export masivo).
    verifications_data: lista de dicts serializada (no ORM objects).
    """
    output = StringIO()
    w = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    w.writerow(["# EVIDETH - Exportacion CSV de Verificaciones"])
    w.writerow(["# Generated", datetime.now(timezone.utc).isoformat()])
    w.writerow([])
    w.writerow([
        "verification_id", "camera_id", "video_id", "segment_id",
        "result", "hash_match", "signature_valid",
        "computed_hash", "stored_hash", "error_message",
        "verified_at", "ip_address", "verified_by_id",
    ])

    for v in verifications_data:
        ts = v.get("verified_at")
        w.writerow([
            v["id"],
            v.get("camera_id",       ""),
            v.get("video_id",        ""),
            v["segment_id"],
            str(v["result"]),
            v.get("hash_match",      ""),
            v.get("signature_valid", ""),
            v.get("computed_hash",   ""),
            v.get("stored_hash",     ""),
            v.get("error_message",   ""),
            ts.isoformat() if ts else "",
            v.get("ip_address",      ""),
            v.get("verified_by_id",  ""),
        ])

    return output.getvalue()
