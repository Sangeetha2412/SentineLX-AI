"""
SentinelX - PDF Report Generator
Builds a branded PDF security report using ReportLab.
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_pdf_report(output_path: str, title: str, user, scans: list, risk_score: float, summary_text: str = ""):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SentinelTitle", parent=styles["Title"], textColor=colors.HexColor("#00E5FF"), fontSize=24
    )
    heading_style = ParagraphStyle(
        "SentinelHeading", parent=styles["Heading2"], textColor=colors.HexColor("#7C3AED")
    )
    normal = styles["Normal"]

    elements = []
    elements.append(Paragraph("SentinelX Security Report", title_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(title, styles["Heading3"]))
    elements.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", normal))
    elements.append(Paragraph(f"User: {user.username} ({user.email})", normal))
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("Overall Risk Score", heading_style))
    risk_color = "#22C55E" if risk_score < 30 else ("#F59E0B" if risk_score < 70 else "#EF4444")
    elements.append(Paragraph(
        f'<font color="{risk_color}"><b>{risk_score:.1f} / 100</b></font>', styles["Heading1"]
    ))
    elements.append(Spacer(1, 12))

    if summary_text:
        elements.append(Paragraph("Summary", heading_style))
        elements.append(Paragraph(summary_text, normal))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph("Scan History", heading_style))
    table_data = [["Tool", "Target", "Result", "Risk", "Date"]]
    for s in scans:
        table_data.append([
            s.tool_name,
            (s.target or "-")[:30],
            (s.result_summary or "-")[:40],
            f"{s.risk_score:.0f}",
            s.created_at.strftime("%Y-%m-%d %H:%M"),
        ])

    table = Table(table_data, colWidths=[3.5 * cm, 3.5 * cm, 5.5 * cm, 1.5 * cm, 3 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(table)

    elements.append(Spacer(1, 20))
    elements.append(Paragraph(
        "This report is generated for educational and authorized-use purposes only. "
        "SentinelX does not perform actions against systems without explicit authorization.",
        ParagraphStyle("footer", parent=normal, fontSize=7, textColor=colors.grey),
    ))

    doc.build(elements)
    return output_path
