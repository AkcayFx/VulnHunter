"""PDF report generator using ReportLab."""
from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Any

from vulnhunter.models import ScanReport, Vulnerability
from vulnhunter.reporting.cvss import (
    CVSSVector,
    calculate_base_score,
    estimate_vector_from_vuln,
    score_to_severity,
)

logger = logging.getLogger("vulnhunter.reporting")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    _HAS_REPORTLAB = True
except ImportError:
    _HAS_REPORTLAB = False

SEVERITY_COLORS: dict[str, Any] = {}
if _HAS_REPORTLAB:
    SEVERITY_COLORS = {
        "critical": colors.HexColor("#FF0000"),
        "high": colors.HexColor("#FF6600"),
        "medium": colors.HexColor("#FFB800"),
        "low": colors.HexColor("#00AA00"),
        "info": colors.HexColor("#0088FF"),
    }


def generate_pdf(report: ScanReport, output_path: Path | str) -> Path:
    """Generate a PDF security report and write it to *output_path*."""
    if not _HAS_REPORTLAB:
        raise ImportError("reportlab is required for PDF generation — pip install reportlab")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("VHTitle", parent=styles["Title"], fontSize=22, spaceAfter=12)
    h2_style = ParagraphStyle("VH2", parent=styles["Heading2"], fontSize=14, spaceAfter=8)
    body_style = ParagraphStyle("VHBody", parent=styles["BodyText"], fontSize=10, leading=14)

    elements: list[Any] = []

    elements.append(Paragraph("VulnHunter Security Report", title_style))
    elements.append(Spacer(1, 6 * mm))

    meta_data = [
        ["Target", report.target.host],
        ["Scan Date", report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Threat Level", report.threat_level],
        ["Risk Score", f"{report.risk_score:.1f} / 10.0"],
        ["Total Vulnerabilities", str(report.total_vulns)],
        ["Duration", f"{report.total_duration_seconds:.1f}s"],
    ]
    meta_table = Table(meta_data, colWidths=[120, 350])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 8 * mm))

    if report.ai_summary:
        elements.append(Paragraph("Executive Summary", h2_style))
        safe_summary = report.ai_summary.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elements.append(Paragraph(safe_summary[:3000], body_style))
        elements.append(Spacer(1, 6 * mm))

    counts = report.vuln_counts
    if counts:
        elements.append(Paragraph("Vulnerability Summary", h2_style))
        count_data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                count_data.append([sev.upper(), str(counts[sev])])

        count_table = Table(count_data, colWidths=[200, 100])
        style_cmds: list[Any] = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ]
        for row_idx in range(1, len(count_data)):
            sev_name = count_data[row_idx][0].lower()
            colour = SEVERITY_COLORS.get(sev_name, colors.grey)
            style_cmds.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), colour))

        count_table.setStyle(TableStyle(style_cmds))
        elements.append(count_table)
        elements.append(Spacer(1, 6 * mm))

    if report.vulnerabilities:
        elements.append(Paragraph("Detailed Findings", h2_style))
        for i, v in enumerate(report.vulnerabilities, 1):
            vec = estimate_vector_from_vuln(v.title, v.description)
            cvss = calculate_base_score(vec)

            sev_label = v.severity.value.upper()
            elements.append(Paragraph(
                f"<b>{i}. [{sev_label}] {_safe(v.title)}</b>  (CVSS {cvss:.1f})",
                body_style,
            ))
            elements.append(Paragraph(f"Tool: {_safe(v.tool)}", body_style))
            elements.append(Paragraph(_safe(v.description[:800]), body_style))
            if v.evidence:
                elements.append(Paragraph(f"<i>Evidence:</i> {_safe(v.evidence[:400])}", body_style))
            if v.remediation:
                elements.append(Paragraph(f"<i>Remediation:</i> {_safe(v.remediation[:400])}", body_style))
            elements.append(Spacer(1, 3 * mm))

    if report.remediation_steps:
        elements.append(Paragraph("Remediation Roadmap", h2_style))
        for idx, step in enumerate(report.remediation_steps, 1):
            elements.append(Paragraph(f"{idx}. {_safe(step)}", body_style))
        elements.append(Spacer(1, 4 * mm))

    elements.append(Spacer(1, 10 * mm))
    elements.append(Paragraph(
        "<i>Generated by VulnHunter — autonomous AI penetration testing platform</i>",
        ParagraphStyle("footer", parent=body_style, fontSize=8, textColor=colors.grey),
    ))

    doc.build(elements)
    logger.info(f"PDF report written to {output_path}")
    return output_path


def _safe(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
