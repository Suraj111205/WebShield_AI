from pathlib import Path
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

BASE_DIR = Path(__file__).resolve().parent.parent.parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

def generate_pdf_report(target, verification, crawl_result, findings):
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = REPORT_DIR / filename

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4)
    story = [
        Paragraph("WebShield AI", styles["Title"]),
        Paragraph("Security Advisor & Website Vulnerability Scanner — Report", styles["Heading2"]),
        Spacer(1, 12),
        Paragraph(f"<b>Target Website:</b> {target}", styles["BodyText"]),
        Paragraph(f"<b>Website Status:</b> {verification['message']}", styles["BodyText"]),
        Paragraph(f"<b>Scanned Pages:</b> {len(crawl_result['pages'])}", styles["BodyText"]),
        Paragraph(f"<b>Found Forms:</b> {len(crawl_result['forms'])}", styles["BodyText"]),
        Spacer(1, 12),
    ]

    data = [["Type", "Severity", "CVSS", "OWASP", "URL"]]
    for f in findings:
        data.append([
            f["type"], f["severity"], str(f["cvss_score"]),
            f["owasp_category"], f["url"][:55]
        ])

    if len(data) == 1:
        data.append(["No passive findings", "-", "-", "-", "-"])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
        ("GRID", (0,0), (-1,-1), 0.5, colors.black),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 4),
        ("RIGHTPADDING", (0,0), (-1,-1), 4),
    ]))
    story += [table, Spacer(1, 14)]

    for i, f in enumerate(findings, 1):
        story += [
            Paragraph(f"{i}. {f['type']} - {f['severity']}", styles["Heading3"]),
            Paragraph(f"<b>Description:</b> {f['description']}", styles["BodyText"]),
            Paragraph(f"<b>Evidence:</b> {f['evidence']}", styles["BodyText"]),
            Paragraph(f"<b>Recommendation:</b> {f['recommendation']}", styles["BodyText"]),
            Spacer(1, 8)
        ]

    story.append(Paragraph(
        "Note: Findings from automated scanners should be manually verified before remediation.",
        styles["Italic"]
    ))
    doc.build(story)
    return path
