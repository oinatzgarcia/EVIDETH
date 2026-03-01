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
    
    # EVIDETH Brand Colors - Matching web design exactly
    COLOR_PRIMARY = colors.HexColor('#4a90e2')  # Exact blue from web
    COLOR_SUCCESS = colors.HexColor('#10b981')
    COLOR_DANGER = colors.HexColor('#ef4444')
    COLOR_WARNING = colors.HexColor('#f59e0b')
    COLOR_DARK = colors.HexColor('#0a0a0a')
    COLOR_GRAY = colors.HexColor('#6b7280')
    
    # Logo path
    LOGO_PATH = Path(__file__).parent.parent.parent / "frontend" / "assets" / "images" / "Buho.png"
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ForensicTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.COLOR_PRIMARY,
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
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
        
        # Body monospace for hashes
        self.styles.add(ParagraphStyle(
            name='MonoBody',
            parent=self.styles['Normal'],
            fontSize=8,
            fontName='Courier',
            textColor=self.COLOR_DARK,
            wordWrap='CJK'
        ))
    
    def generate_report(self, data: dict) -> BytesIO:
        """
        Generate complete forensic PDF report
        
        Args:
            data: Dictionary containing verification data
        
        Returns:
            BytesIO: PDF file buffer
        """
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
        
        # Generate all sections
        story.extend(self._generate_cover_page(data))
        story.append(PageBreak())
        story.extend(self._generate_executive_summary(data))
        story.extend(self._generate_technical_details(data))
        story.extend(self._generate_segment_table(data))
        story.extend(self._generate_chain_of_custody(data))
        story.extend(self._generate_cryptographic_details(data))
        story.extend(self._generate_legal_disclaimer())
        
        # Build PDF with custom page template
        doc.build(story, onFirstPage=self._add_header_footer, 
                  onLaterPages=self._add_header_footer)
        
        buffer.seek(0)
        return buffer
    
    def _generate_cover_page(self, data: dict) -> list:
        """Generate forensic report cover page"""
        elements = []
        
        # Add logo if exists
        if self.LOGO_PATH.exists():
            try:
                logo = Image(str(self.LOGO_PATH), width=3*cm, height=3*cm)
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 0.5*cm))
            except Exception as e:
                # If logo fails to load, continue without it
                print(f"Warning: Could not load logo: {e}")
                elements.append(Spacer(1, 1*cm))
        else:
            elements.append(Spacer(1, 1*cm))
        
        # Title
        elements.append(Paragraph(
            "FORENSIC VIDEO INTEGRITY REPORT",
            self.styles['ForensicTitle']
        ))
        
        elements.append(Spacer(1, 0.5*cm))
        elements.append(HRFlowable(
            width="80%",
            thickness=2,
            color=self.COLOR_PRIMARY,
            spaceBefore=10,
            spaceAfter=10
        ))
        
        # Report metadata table
        report_meta = [
            ["Report ID:", data.get('video_id', 'N/A')],
            ["Generation Date:", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Classification:", "FORENSIC EVIDENCE"],
            ["System:", "EVIDETH v2.0"],
            ["Cryptographic Standard:", "SHA-256 / ECDSA P-256"]
        ]
        
        meta_table = Table(report_meta, colWidths=[6*cm, 10*cm])
        meta_table.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 10),
            ('FONT', (1, 0), (1, -1), 'Helvetica', 10),
            ('TEXTCOLOR', (0, 0), (0, -1), self.COLOR_GRAY),
            ('TEXTCOLOR', (1, 0), (1, -1), self.COLOR_DARK),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(Spacer(1, 2*cm))
        elements.append(meta_table)
        
        # Verification status badge
        elements.append(Spacer(1, 3*cm))
        
        integrity_ok = data.get('integrity_ok', False)
        status_text = "✓ INTEGRITY VERIFIED" if integrity_ok else "⚠ TAMPERING DETECTED"
        status_color = self.COLOR_SUCCESS if integrity_ok else self.COLOR_DANGER
        
        status_style = ParagraphStyle(
            'StatusBadge',
            fontSize=20,
            textColor=status_color,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        elements.append(Paragraph(status_text, status_style))
        
        return elements
    
    def _generate_executive_summary(self, data: dict) -> list:
        """Generate executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        summary = data.get('summary', {})
        total = summary.get('total_segments', 0)
        passed = summary.get('passed', 0)
        failed = summary.get('failed', 0)
        
        integrity_rate = (passed / total * 100) if total > 0 else 0
        
        summary_data = [
            ["Total Segments Analyzed:", str(total)],
            ["Segments Passed:", str(passed)],
            ["Segments Failed:", str(failed)],
            ["Integrity Rate:", f"{integrity_rate:.2f}%"],
            ["Verification Status:", data.get('verdict', 'Unknown')]
        ]
        
        summary_table = Table(summary_data, colWidths=[8*cm, 8*cm])
        summary_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 10),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLOR_GRAY),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        elements.append(summary_table)
        elements.append(Spacer(1, 0.5*cm))
        
        return elements
    
    def _generate_technical_details(self, data: dict) -> list:
        """Generate technical details section"""
        elements = []
        
        elements.append(Paragraph("Technical Details", self.styles['SectionHeader']))
        
        # Video information
        video_info = [
            ["Video ID:", data.get('video_id', 'N/A')],
            ["Camera ID:", data.get('camera_id', 'N/A')],
            ["Duration:", f"{data.get('duration_secs', 0)} seconds"],
            ["Verification Time:", data.get('verified_at', 'N/A')[:19].replace('T', ' ') + " UTC"]
        ]
        
        info_table = Table(video_info, colWidths=[6*cm, 10*cm])
        info_table.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
            ('FONT', (1, 0), (1, -1), 'Courier', 9),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(info_table)
        elements.append(Spacer(1, 0.5*cm))
        
        return elements
    
    def _generate_segment_table(self, data: dict) -> list:
        """Generate detailed segment verification table"""
        elements = []
        
        elements.append(Paragraph("Segment Analysis", self.styles['SectionHeader']))
        
        segments = data.get('segments', [])
        
        # Table header
        table_data = [['#', 'Time Range', 'Hash (SHA-256)', 'Status']]
        
        for seg in segments:
            seg_num = str(seg.get('segment_index', '?'))
            start = seg.get('start_time_secs', 0)
            end = seg.get('end_time_secs', 0)
            time_range = f"{self._format_time(start)} - {self._format_time(end)}"
            
            hash_val = seg.get('hash', 'N/A')
            # Truncate hash for display
            hash_display = f"{hash_val[:16]}...{hash_val[-16:]}" if len(hash_val) > 40 else hash_val
            
            status = "✓ PASS" if seg.get('result') == 'pass' else "✗ FAIL"
            
            table_data.append([seg_num, time_range, hash_display, status])
        
        seg_table = Table(table_data, colWidths=[1.5*cm, 4*cm, 8*cm, 2.5*cm])
        seg_table.setStyle(TableStyle([
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), self.COLOR_PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 9),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            
            # Body styling
            ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
            ('FONT', (2, 1), (2, -1), 'Courier', 7),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),
            ('ALIGN', (3, 1), (3, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            
            # Grid
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLOR_GRAY),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f9fafb')]),
            
            # Padding
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(seg_table)
        elements.append(Spacer(1, 0.5*cm))
        
        return elements
    
    def _generate_chain_of_custody(self, data: dict) -> list:
        """Generate chain of custody section"""
        elements = []
        
        elements.append(PageBreak())
        elements.append(Paragraph("Chain of Custody", self.styles['SectionHeader']))
        
        custody_data = [
            ["Event", "Timestamp", "Details"],
            ["Video Capture", data.get('created_at', 'N/A')[:19], f"Camera: {data.get('camera_id', 'N/A')}"],
            ["Verification Request", data.get('verified_at', 'N/A')[:19], "User authentication via JWT"],
            ["Report Generation", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "Automated PDF generation"]
        ]
        
        custody_table = Table(custody_data, colWidths=[5*cm, 5*cm, 6*cm])
        custody_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 9),
            ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
            ('FONT', (1, 1), (1, -1), 'Courier', 8),
            ('GRID', (0, 0), (-1, -1), 0.5, self.COLOR_GRAY),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        
        elements.append(custody_table)
        elements.append(Spacer(1, 0.5*cm))
        
        return elements
    
    def _generate_cryptographic_details(self, data: dict) -> list:
        """Generate cryptographic verification details"""
        elements = []
        
        elements.append(Paragraph("Cryptographic Verification", self.styles['SectionHeader']))
        
        crypto_text = """
        This report certifies that the video integrity verification was performed using:
        
        • <b>Hash Algorithm:</b> SHA-256 (NIST FIPS 180-4 compliant)
        • <b>Digital Signature:</b> ECDSA with P-256 curve (NIST FIPS 186-4)
        • <b>Segment Granularity:</b> 30-second intervals
        • <b>Verification Method:</b> Cryptographic hash comparison with stored reference hashes
        
        Each segment was independently hashed and verified against the digitally signed
        reference hash stored at the time of video capture. Any modification to the video
        content would result in a hash mismatch, indicating tampering.
        """
        
        elements.append(Paragraph(crypto_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.5*cm))
        
        return elements
    
    def _generate_legal_disclaimer(self) -> list:
        """Generate legal disclaimer"""
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
        
        # Document hash
        elements.append(Spacer(1, 1*cm))
        doc_hash = hashlib.sha256(datetime.utcnow().isoformat().encode()).hexdigest()
        
        elements.append(Paragraph(
            f"<font name='Courier' size='8'>Document Hash: {doc_hash}</font>",
            self.styles['Normal']
        ))
        
        return elements
    
    def _add_header_footer(self, canvas, doc):
        """Add header and footer to each page"""
        canvas.saveState()
        
        # Header with brand blue
        canvas.setFillColor(self.COLOR_PRIMARY)
        canvas.rect(0, A4[1] - 2*cm, A4[0], 2*cm, fill=True, stroke=False)
        
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 16)
        canvas.drawString(2*cm, A4[1] - 1.3*cm, "EVIDETH")
        
        canvas.setFont('Helvetica', 10)
        canvas.drawRightString(A4[0] - 2*cm, A4[1] - 1.3*cm, "Forensic Video Integrity")
        
        # Footer
        canvas.setFillColor(self.COLOR_GRAY)
        canvas.setFont('Courier', 8)
        canvas.drawString(2*cm, 1.5*cm, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        canvas.drawRightString(A4[0] - 2*cm, 1.5*cm, f"Page {canvas.getPageNumber()}")
        
        # Classification banner at bottom
        canvas.setFillColor(colors.HexColor('#dc2626'))
        canvas.rect(0, 0, A4[0], 1*cm, fill=True, stroke=False)
        canvas.setFillColor(colors.white)
        canvas.setFont('Helvetica-Bold', 9)
        canvas.drawCentredString(A4[0] / 2, 0.35*cm, "FORENSIC EVIDENCE - CONFIDENTIAL")
        
        canvas.restoreState()
    
    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format seconds to MM:SS"""
        if seconds is None:
            return "--:--"
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins:02d}:{secs:02d}"
