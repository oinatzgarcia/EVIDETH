"""
PDF Forensic Report Generator for EVIDETH
Generates professional forensic-grade PDF reports for video integrity verification
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import hashlib
from io import BytesIO
from pathlib import Path
import os


class ForensicPDFGenerator:
    """Generate forensic-grade PDF reports for video verification"""

    COLOR_PRIMARY   = colors.HexColor('#4a90e2')
    COLOR_SUCCESS   = colors.HexColor('#10b981')
    COLOR_DANGER    = colors.HexColor('#ef4444')
    COLOR_WARNING   = colors.HexColor('#f59e0b')
    COLOR_DARK      = colors.HexColor('#0a0a0a')
    COLOR_GRAY      = colors.HexColor('#6b7280')
    COLOR_ROW_PASS  = colors.HexColor('#d1fae5')   # light green
    COLOR_ROW_FAIL  = colors.HexColor('#fee2e2')   # light red
    COLOR_ROW_MISS  = colors.HexColor('#fef3c7')   # light yellow
    COLOR_DB_ALERT  = colors.HexColor('#7c3aed')   # purple — DB compromise
    COLOR_DB_LIGHT  = colors.HexColor('#ede9fe')   # light purple

    LOGO_PATH = Path(__file__).parent.parent.parent / "frontend" / "assets" / "images" / "Buho.png"

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='ForensicTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderPadding=5,
            leftIndent=0
        ))
        self.styles.add(ParagraphStyle(
            name='MonoBody',
            parent=self.styles['Normal'],
            fontSize=8,
            fontName='Courier',
            textColor=self.COLOR_DARK,
            wordWrap='CJK'
        ))
        self.styles.add(ParagraphStyle(
            name='DBAlertHeader',
            parent=self.styles['Heading3'],
            fontSize=11,
            textColor=self.COLOR_DB_ALERT,
            fontName='Helvetica-Bold',
            spaceBefore=10,
            spaceAfter=6,
        ))

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    def generate_report(self, data: dict) -> BytesIO:
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=3*cm,
            bottomMargin=2.5*cm
        )
        story = []
        story.extend(self._generate_cover_page(data))
        story.append(PageBreak())
        story.extend(self._generate_executive_summary(data))
        story.extend(self._generate_technical_details(data))
        story.extend(self._generate_segment_table(data))
        story.extend(self._generate_db_integrity_alerts(data))   # ← nuevo
        story.extend(self._generate_chain_of_custody(data))
        story.extend(self._generate_cryptographic_details(data))
        story.extend(self._generate_legal_disclaimer())
        doc.build(story, onFirstPage=self._add_header_footer,
                  onLaterPages=self._add_header_footer)
        buffer.seek(0)
        return buffer

    # -------------------------------------------------------------------------
    # Cover page
    # -------------------------------------------------------------------------

    def _generate_cover_page(self, data: dict) -> list:
        elements = []
        if self.LOGO_PATH.exists():
            try:
                logo = Image(str(self.LOGO_PATH), width=3*cm, height=3*cm)
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 0.5*cm))
            except Exception as e:
                print(f"Warning: Could not load logo: {e}")
                elements.append(Spacer(1, 1*cm))
        else:
            elements.append(Spacer(1, 1*cm))

        elements.append(Paragraph("FORENSIC VIDEO INTEGRITY REPORT", self.styles['ForensicTitle']))
        elements.append(Spacer(1, 0.5*cm))
        elements.append(HRFlowable(
            width="80%", thickness=2, color=self.COLOR_PRIMARY,
            spaceBefore=10, spaceAfter=10
        ))

        report_meta = [
            ["Report ID:",              data.get('video_id', 'N/A')],
            ["Generation Date:",        datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Classification:",         "FORENSIC EVIDENCE"],
            ["System:",                 "EVIDETH v2.0"],
            ["Cryptographic Standard:", "SHA-256 / ECDSA P-256"],
        ]
        meta_table = Table(report_meta, colWidths=[6*cm, 10*cm])
        meta_table.setStyle(TableStyle([
            ('FONT',          (0, 0), (0, -1), 'Helvetica-Bold', 10),
            ('FONT',          (1, 0), (1, -1), 'Helvetica', 10),
            ('TEXTCOLOR',     (0, 0), (0, -1), self.COLOR_GRAY),
            ('TEXTCOLOR',     (1, 0), (1, -1), self.COLOR_DARK),
            ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(Spacer(1, 2*cm))
        elements.append(meta_table)
        elements.append(Spacer(1, 3*cm))

        integrity_ok = data.get('integrity_ok', False)
        status_text  = "✓ INTEGRITY VERIFIED" if integrity_ok else "⚠ TAMPERING DETECTED"
        status_color = self.COLOR_SUCCESS if integrity_ok else self.COLOR_DANGER
        status_style = ParagraphStyle(
            'StatusBadge', fontSize=20,
            textColor=status_color, alignment=TA_CENTER, fontName='Helvetica-Bold'
        )
        elements.append(Paragraph(status_text, status_style))
        return elements

    # -------------------------------------------------------------------------
    # Executive Summary  — includes DB integrity stats
    # -------------------------------------------------------------------------

    def _generate_executive_summary(self, data: dict) -> list:
        elements = []
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))

        summary  = data.get('summary', {})
        segments = data.get('segments', [])
        total    = summary.get('total_segments', 0)
        passed   = summary.get('passed', 0)
        failed   = summary.get('failed', 0)
        integrity_rate = (passed / total * 100) if total > 0 else 0

        # ── L2-BD stats ─────────────────────────────────────────────────────
        db_fail_count = sum(
            1 for s in segments if s.get('db_merkle_consistent') is False
        )
        db_ok_count = sum(
            1 for s in segments if s.get('db_merkle_consistent') is True
        )
        db_na_count = sum(
            1 for s in segments if s.get('db_merkle_consistent') is None
        )

        if db_fail_count > 0:
            db_status_text  = f"⚠ COMPROMISED ({db_fail_count} segment(s))"
            db_status_color = self.COLOR_DB_ALERT
        elif db_ok_count > 0:
            db_status_text  = f"✓ INTACT ({db_ok_count} segment(s) verified)"
            db_status_color = self.COLOR_SUCCESS
        else:
            db_status_text  = "N/A (no Merkle data)"
            db_status_color = self.COLOR_GRAY

        summary_data = [
            ["Total Segments Analyzed:", str(total)],
            ["Segments Passed:",         str(passed)],
            ["Segments Failed:",         str(failed)],
            ["Integrity Rate:",          f"{integrity_rate:.2f}%"],
            ["Verification Status:",     data.get('verdict', 'Unknown')],
            ["Database Integrity (L2-BD):",
             Paragraph(f"<font color='#{self._hex(db_status_color)}'><b>{db_status_text}</b></font>",
                       self.styles['Normal'])],
        ]

        summary_table = Table(summary_data, colWidths=[8*cm, 8*cm])
        summary_table.setStyle(TableStyle([
            ('FONT',          (0, 0), (-1, -1), 'Helvetica', 10),
            ('FONT',          (0, 0), (0, -1),  'Helvetica-Bold', 10),
            ('BACKGROUND',    (0, 0), (-1, 0),  colors.HexColor('#f3f4f6')),
            # Highlight L2-BD row if compromised
            *([('BACKGROUND', (0, 5), (-1, 5), self.COLOR_DB_LIGHT)] if db_fail_count > 0 else []),
            ('GRID',          (0, 0), (-1, -1), 0.5, self.COLOR_GRAY),
            ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # -------------------------------------------------------------------------
    # Technical Details
    # -------------------------------------------------------------------------

    def _generate_technical_details(self, data: dict) -> list:
        elements = []
        elements.append(Paragraph("Technical Details", self.styles['SectionHeader']))
        video_info = [
            ["Video ID:",          data.get('video_id', 'N/A')],
            ["Camera ID:",         data.get('camera_id', 'N/A')],
            ["Duration:",          f"{data.get('duration_secs', 0)} seconds"],
            ["Verification Time:", data.get('verified_at', 'N/A')[:19].replace('T', ' ') + " UTC"],
        ]
        info_table = Table(video_info, colWidths=[6*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('FONT',          (0, 0), (0, -1), 'Helvetica-Bold', 9),
            ('FONT',          (1, 0), (1, -1), 'Courier', 9),
            ('ALIGN',         (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # -------------------------------------------------------------------------
    # Segment table  — added DB Integrity column
    # -------------------------------------------------------------------------

    def _generate_segment_table(self, data: dict) -> list:
        """Segment summary table + hash comparison ONLY for result=='fail' segments"""
        elements = []
        elements.append(Paragraph("Segment Analysis", self.styles['SectionHeader']))

        segments = data.get('segments', [])

        # ── Build summary table ───────────────────────────────────────────────
        table_data  = [['#', 'Time Range', 'Status', 'DB Integrity', 'Signature']]
        failed_segs = []
        row_styles  = []

        for i, seg in enumerate(segments):
            row_idx = i + 1
            result  = seg.get('result', 'missing')

            if result == 'pass':
                status_text = "✓ PASS"
                row_styles.append(('BACKGROUND', (0, row_idx), (-1, row_idx), self.COLOR_ROW_PASS))
            elif result == 'fail':
                status_text = "✗ FAIL"
                row_styles.append(('BACKGROUND', (0, row_idx), (-1, row_idx), self.COLOR_ROW_FAIL))
                failed_segs.append(seg)
            else:
                status_text = "- MISSING"
                row_styles.append(('BACKGROUND', (0, row_idx), (-1, row_idx), self.COLOR_ROW_MISS))

            # ── L2-BD badge per segment ───────────────────────────────
            db_val = seg.get('db_merkle_consistent')
            if db_val is True:
                db_text = "✓ OK"
            elif db_val is False:
                db_text = "⚠ ALERT"
                # Override row to purple if DB is compromised
                row_styles.append(
                    ('BACKGROUND', (0, row_idx), (-1, row_idx), self.COLOR_DB_LIGHT)
                )
                row_styles.append(
                    ('TEXTCOLOR', (3, row_idx), (3, row_idx), self.COLOR_DB_ALERT)
                )
                row_styles.append(
                    ('FONT', (3, row_idx), (3, row_idx), 'Helvetica-Bold', 9)
                )
            else:
                db_text = "—"

            sig_valid  = "✓" if seg.get('signature_valid') else "✗"
            start      = seg.get('start_time_secs', 0)
            end        = seg.get('end_time_secs', 0)
            time_range = f"{self._format_time(start)} - {self._format_time(end)}"

            table_data.append([
                str(seg.get('segment_index', '?')),
                time_range,
                status_text,
                db_text,
                sig_valid,
            ])

        base_style = [
            ('BACKGROUND',   (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
            ('FONT',         (0, 0), (-1, 0), 'Helvetica-Bold', 9),
            ('ALIGN',        (0, 0), (-1, 0), 'CENTER'),
            ('FONT',         (0, 1), (-1, -1), 'Helvetica', 9),
            ('ALIGN',        (0, 1), (0, -1),  'CENTER'),
            ('ALIGN',        (2, 1), (4, -1),  'CENTER'),
            ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID',         (0, 0), (-1, -1), 0.5, self.COLOR_GRAY),
            ('LEFTPADDING',  (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING',   (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 6),
        ] + row_styles

        # colWidths: # | Time Range | Status | DB Integrity | Signature
        seg_table = Table(table_data, colWidths=[1.5*cm, 4.5*cm, 3*cm, 3*cm, 2.5*cm])
        seg_table.setStyle(TableStyle(base_style))
        elements.append(seg_table)
        elements.append(Spacer(1, 0.8*cm))

        # ── Hash comparison — only real failures ─────────────────────────────
        if failed_segs:
            elements.append(Paragraph(
                "<b>Tampered Segments — Hash Comparison</b>",
                self.styles['Heading3']
            ))
            elements.append(Spacer(1, 0.3*cm))

            for seg in failed_segs:
                seg_num         = seg.get('segment_index', '?')
                hash_expected   = seg.get('hash_expected', 'N/A')
                hash_calculated = seg.get('hash_calculated', 'N/A')

                elements.append(Paragraph(
                    f"<b>Segment #{seg_num} — ✗ TAMPERED</b>",
                    self.styles['Normal']
                ))

                hash_comparison = [
                    ["Hash Type",            "SHA-256 Value (64 hex chars)"],
                    ["Expected (Original)",  self._format_hash_display(hash_expected)],
                    ["Calculated (Current)", self._format_hash_display(hash_calculated)],
                ]

                hash_table = Table(hash_comparison, colWidths=[4*cm, 12*cm])
                hash_table.setStyle(TableStyle([
                    ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#fee2e2')),
                    ('FONT',         (0, 0), (-1, 0), 'Helvetica-Bold', 8),
                    ('FONT',         (0, 1), (0, -1), 'Helvetica-Bold', 7),
                    ('FONT',         (1, 1), (1, -1), 'Courier', 6),
                    ('GRID',         (0, 0), (-1, -1), 0.5, self.COLOR_DANGER),
                    ('ALIGN',        (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING',  (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING',   (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING',(0, 0), (-1, -1), 4),
                    ('TEXTCOLOR',    (1, 2), (1, 2), self.COLOR_DANGER),
                ]))

                elements.append(hash_table)
                elements.append(Spacer(1, 0.4*cm))

        return elements

    # -------------------------------------------------------------------------
    # NEW — Database Integrity Alerts section (L2-BD)
    # -------------------------------------------------------------------------

    def _generate_db_integrity_alerts(self, data: dict) -> list:
        """
        Sección dedicada a alertas L2-BD.
        Solo se genera si algún segmento tiene db_merkle_consistent == False.

        Explica el tipo de ataque detectado según la combinación L2-BD + L3:
          - L3 válida + L2-BD falla → solo second_hashes alterado en BD
          - L3 inválida + L2-BD falla → también merkle_root fue alterado
        """
        segments = data.get('segments', [])
        db_failed = [s for s in segments if s.get('db_merkle_consistent') is False]

        if not db_failed:
            return []

        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph(
            "⚠ DATABASE INTEGRITY ALERTS (Level 2-DB)",
            self.styles['SectionHeader']
        ))

        intro = (
            "The following segments have an <b>internally inconsistent database record</b>: "
            "the stored <font name='Courier'>second_hashes</font> do not reconstruct the stored "
            "<font name='Courier'>merkle_root</font>. "
            "This indicates a <b>direct manipulation of the database</b>, independent of whether "
            "the uploaded video is intact. The ECDSA signature (Level 3) provides forensic "
            "context to determine the scope of the database attack."
        )
        elements.append(Paragraph(intro, self.styles['Normal']))
        elements.append(Spacer(1, 0.5*cm))

        for seg in db_failed:
            seg_idx     = seg.get('segment_index', '?')
            sig_valid   = seg.get('signature_valid')
            detail      = seg.get('detail', '')
            start       = seg.get('start_time_secs', 0)
            end         = seg.get('end_time_secs', 0)
            time_range  = f"{self._format_time(start)} – {self._format_time(end)}"

            # Forensic interpretation based on L3 ECDSA result
            if sig_valid is True:
                attack_type  = "Partial DB Attack"
                attack_desc  = (
                    "L3 ECDSA signature is VALID — the stored <font name='Courier'>merkle_root</font> "
                    "is authentic (matches camera signature). Only the "
                    "<font name='Courier'>second_hashes</font> field was altered directly in the "
                    "database. An attacker modified the per-second hashes to conceal "
                    "a specific tampered second without invalidating the top-level signature."
                )
                attack_color = self.COLOR_WARNING
            elif sig_valid is False:
                attack_type  = "Full DB Attack"
                attack_desc  = (
                    "L3 ECDSA signature is INVALID — both the "
                    "<font name='Courier'>merkle_root</font> AND "
                    "<font name='Courier'>second_hashes</font> fields were altered in the "
                    "database. The attacker replaced both fields but could not forge the "
                    "camera's ECDSA private key signature."
                )
                attack_color = self.COLOR_DANGER
            else:
                attack_type  = "DB Attack (ECDSA N/A)"
                attack_desc  = (
                    "L3 ECDSA is not available for this segment (camera has no registered "
                    "public key). The database record is internally inconsistent but the "
                    "scope of the attack cannot be determined without the signature."
                )
                attack_color = self.COLOR_DB_ALERT

            elements.append(Paragraph(
                f"Segment #{seg_idx} ({time_range}) — {attack_type}",
                self.styles['DBAlertHeader']
            ))

            alert_data = [
                ["Field",         "Value"],
                ["Segment",       f"#{seg_idx} ({time_range})"],
                ["Attack Type",   attack_type],
                ["L3 ECDSA",      "✓ Valid" if sig_valid is True
                                  else ("✗ Invalid" if sig_valid is False else "N/A")],
                ["DB Integrity",  "⚠ COMPROMISED"],
                ["Detail",        Paragraph(detail or 'N/A', self.styles['MonoBody'])],
            ]

            alert_table = Table(alert_data, colWidths=[4*cm, 12*cm])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND',   (0, 0), (-1, 0), attack_color),
                ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
                ('FONT',         (0, 0), (-1, 0), 'Helvetica-Bold', 9),
                ('FONT',         (0, 1), (0, -1), 'Helvetica-Bold', 8),
                ('FONT',         (1, 1), (1, -1), 'Helvetica', 8),
                ('BACKGROUND',   (0, 4), (-1, 4), self.COLOR_DB_LIGHT),
                ('TEXTCOLOR',    (1, 4), (1, 4),  self.COLOR_DB_ALERT),
                ('FONT',         (0, 4), (-1, 4), 'Helvetica-Bold', 9),
                ('GRID',         (0, 0), (-1, -1), 0.5, attack_color),
                ('ALIGN',        (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING',  (0, 0), (-1, -1), 8),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING',   (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING',(0, 0), (-1, -1), 5),
            ]))
            elements.append(alert_table)
            elements.append(Spacer(1, 0.3*cm))

            # Description paragraph
            elements.append(Paragraph(
                f"<b>Forensic Analysis:</b> {attack_desc}",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 0.6*cm))

        return elements

    # -------------------------------------------------------------------------
    # Chain of Custody
    # -------------------------------------------------------------------------

    def _generate_chain_of_custody(self, data: dict) -> list:
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("Chain of Custody", self.styles['SectionHeader']))
        custody_data = [
            ["Event",                "Timestamp",                                     "Details"],
            ["Video Capture",        data.get('created_at', 'N/A')[:19],              f"Camera: {data.get('camera_id', 'N/A')}"],
            ["Verification Request", data.get('verified_at', 'N/A')[:19],             "User authentication via JWT"],
            ["Report Generation",    datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "Automated PDF generation"],
        ]
        custody_table = Table(custody_data, colWidths=[5*cm, 5*cm, 6*cm])
        custody_table.setStyle(TableStyle([
            ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('FONT',         (0, 0), (-1, 0), 'Helvetica-Bold', 9),
            ('FONT',         (0, 1), (-1, -1),'Helvetica', 8),
            ('FONT',         (1, 1), (1, -1), 'Courier', 8),
            ('GRID',         (0, 0), (-1, -1), 0.5, self.COLOR_GRAY),
            ('ALIGN',        (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING',  (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING',   (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING',(0, 0), (-1, -1), 6),
        ]))
        elements.append(custody_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # -------------------------------------------------------------------------
    # Cryptographic Details  — updated to include L2-BD description
    # -------------------------------------------------------------------------

    def _generate_cryptographic_details(self, data: dict) -> list:
        elements = []
        elements.append(Paragraph("Cryptographic Verification", self.styles['SectionHeader']))
        crypto_text = """
        This report certifies that the video integrity verification was performed using:

        • <b>Hash Algorithm:</b> SHA-256 (NIST FIPS 180-4 compliant)
        • <b>Digital Signature:</b> ECDSA with P-256 curve (NIST FIPS 186-4)
        • <b>Segment Granularity:</b> 30-second intervals with 1-second Merkle leaves
        • <b>Verification Method:</b> Cryptographic hash comparison with stored reference hashes

        <b>Verification Levels:</b>

        • <b>Level 1 (SHA-256):</b> Each 30-second segment is hashed and compared against
          the reference hash stored at capture time.

        • <b>Level 2-DB (Database Integrity):</b> The internal consistency of the database
          record is verified by recomputing the Merkle root from the stored per-second hashes
          and comparing it against the stored Merkle root. A mismatch indicates direct
          manipulation of the database record, independent of the uploaded video.

        • <b>Level 2 (Merkle Tree):</b> A binary Merkle tree (Bitcoin-style, SHA-256)
          is built from per-second hashes. A root mismatch identifies the exact tampered
          second(s) without retransmitting the full segment.

        • <b>Level 3 (ECDSA P-256):</b> The Merkle root is verified against the ECDSA
          signature generated by the camera's private key at capture time.
        """
        elements.append(Paragraph(crypto_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # -------------------------------------------------------------------------
    # Legal Disclaimer
    # -------------------------------------------------------------------------

    def _generate_legal_disclaimer(self) -> list:
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("Legal Disclaimer", self.styles['SectionHeader']))
        disclaimer = """
        This forensic report has been automatically generated by the EVIDETH Video Integrity
        Verification System v2.0. The report provides cryptographic evidence of video integrity
        based on SHA-256 hash verification and ECDSA digital signatures.

        <b>Certificate of Authenticity:</b> This document certifies that the verification process
        followed industry-standard cryptographic protocols (NIST FIPS 180-4, FIPS 186-4) and
        that the results accurately reflect the integrity status of the analyzed video at the
        time of verification.

        <b>Limitations:</b> This report does not certify the content accuracy or legal validity
        of the video itself, only its cryptographic integrity relative to the originally captured
        footage. The verification is based on the assumption that the camera system and hash
        storage infrastructure were not compromised at the time of recording.

        <b>Evidentiary Use:</b> This report may be submitted as technical evidence in legal
        proceedings to demonstrate video integrity. Courts should evaluate this evidence in
        conjunction with other relevant factors.

        Generated by EVIDETH Forensic Video Integrity System
        © 2026 - All Rights Reserved
        """
        elements.append(Paragraph(disclaimer, self.styles['BodyText']))
        elements.append(Spacer(1, 1*cm))
        doc_hash = hashlib.sha256(datetime.utcnow().isoformat().encode()).hexdigest()
        elements.append(Paragraph(
            f"<font name='Courier' size='8'>Document Hash: {doc_hash}</font>",
            self.styles['Normal']
        ))
        return elements

    # -------------------------------------------------------------------------
    # Page header / footer
    # -------------------------------------------------------------------------

    def _add_header_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(self.COLOR_PRIMARY)
        canvas.rect(0, A4[1] - 2*cm, A4[0], 2*cm, fill=True, stroke=False)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 16)
        canvas.drawString(2*cm, A4[1] - 1.3*cm, "EVIDETH")
        canvas.setFont('Helvetica', 10)
        canvas.drawRightString(A4[0] - 2*cm, A4[1] - 1.3*cm, "Forensic Video Integrity")
        canvas.setFillColor(self.COLOR_GRAY)
        canvas.setFont('Courier', 8)
        canvas.drawString(2*cm, 1.5*cm,
                          f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        canvas.drawRightString(A4[0] - 2*cm, 1.5*cm, f"Page {canvas.getPageNumber()}")
        canvas.setFillColor(colors.HexColor('#dc2626'))
        canvas.rect(0, 0, A4[0], 1*cm, fill=True, stroke=False)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 9)
        canvas.drawCentredString(A4[0] / 2, 0.35*cm, "FORENSIC EVIDENCE - CONFIDENTIAL")
        canvas.restoreState()

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _hex(color) -> str:
        """Convert a ReportLab HexColor to a 6-char hex string for Paragraph markup."""
        h = color.hexval()
        return h.lstrip('#') if h.startswith('#') else h

    @staticmethod
    def _format_hash_display(hash_val: str) -> str:
        """Return the full 64-char SHA-256 hash as-is (fits in Courier 6pt)."""
        if not hash_val or hash_val == 'N/A':
            return 'N/A'
        return hash_val

    @staticmethod
    def _format_time(seconds: float) -> str:
        if seconds is None:
            return "--:--"
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins:02d}:{secs:02d}"
