
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether
)


# --------------------------------------------------
# Report configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
MAX_FINDINGS = 500

RECOMMENDATIONS = {
    "Content-Security-Policy": (
        "Configure a Content Security Policy that restricts the "
        "sources from which scripts, styles, and other resources load."
    ),
    "Strict-Transport-Security": (
        "Enable HTTP Strict Transport Security (HSTS) over HTTPS "
        "with an appropriate max-age value."
    ),
    "X-Content-Type-Options": (
        "Configure this header with the value nosniff to help prevent "
        "MIME-type sniffing."
    ),
    "X-Frame-Options": (
        "Configure DENY or SAMEORIGIN, depending on whether your "
        "application needs to be embedded in frames."
    ),
    "Referrer-Policy": (
        "Set a suitable Referrer-Policy, such as "
        "strict-origin-when-cross-origin."
    ),
    "Permissions-Policy": (
        "Restrict browser features and APIs to only those required "
        "by your application."
    )
}


# --------------------------------------------------
# Validation and helper functions
# --------------------------------------------------

def safe_text(value, max_length=10000):
    """Convert dynamic values into safe ReportLab paragraph text."""

    if value is None:
        return "Not available"

    return escape(str(value)[:max_length])


def validate_count(value, field_name):
    """Validate a non-negative integer count."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer.")

    return value


def get_missing_header_count(value):
    """Support both integer counts and lists of missing headers."""

    if isinstance(value, bool):
        raise ValueError("Invalid missing_headers value.")

    if isinstance(value, int):
        return validate_count(value, "missing_headers")

    if isinstance(value, list):
        return len(value)

    raise ValueError("missing_headers must be an integer or a list.")


def validate_scan_result(scan_result):
    """Validate the scan data before generating a PDF."""

    if not isinstance(scan_result, Mapping):
        raise ValueError("Scan result must be a dictionary.")

    if scan_result.get("success") is not True:
        raise ValueError("A successful scan result is required.")

    results = scan_result.get("results", [])

    if not isinstance(results, list):
        raise ValueError("Scan results must be a list.")

    if len(results) > MAX_FINDINGS:
        raise ValueError(
            f"Too many findings. Maximum allowed: {MAX_FINDINGS}."
        )

    for item in results:
        if not isinstance(item, Mapping):
            raise ValueError("Each scan finding must be a dictionary.")

    summary = scan_result.get("severity_summary", {})

    if not isinstance(summary, Mapping):
        raise ValueError("Severity summary must be a dictionary.")

    total_headers = validate_count(
        scan_result.get("total_headers_checked", 0),
        "total_headers_checked"
    )

    missing_headers = get_missing_header_count(
        scan_result.get("missing_headers", 0)
    )

    if missing_headers > total_headers:
        raise ValueError(
            "Missing headers cannot exceed the total headers checked."
        )

    for severity in ("High", "Medium", "Low"):
        validate_count(summary.get(severity, 0), f"{severity} count")

    return results, summary, total_headers, missing_headers


def validate_output_path(output_path):
    """Ensure the generated PDF stays inside the reports directory."""

    if not isinstance(output_path, (str, Path)):
        raise ValueError("Invalid report output path.")

    try:
        reports_directory = REPORTS_DIR.resolve()
        destination = Path(output_path).resolve()

        destination.relative_to(reports_directory)
    except (OSError, ValueError):
        raise ValueError(
            "Report files must be saved inside the reports directory."
        )

    if destination == reports_directory:
        raise ValueError("A PDF filename is required.")

    if destination.suffix.lower() != ".pdf":
        raise ValueError("Report filename must have a .pdf extension.")

    return destination


def create_styles():
    """Create professional PDF text styles."""

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=23,
        leading=28,
        textColor=colors.HexColor("#0F172A"),
        alignment=TA_CENTER,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0E7490"),
        spaceBefore=14,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        spaceAfter=6
    ))

    styles.add(ParagraphStyle(
        name="SmallText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#475569")
    ))

    return styles


def create_table(data, column_widths=None):
    """Create a consistently styled PDF table."""

    table = Table(
        data,
        colWidths=column_widths,
        repeatRows=1,
        hAlign="LEFT"
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 11),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
            colors.white,
            colors.HexColor("#F1F5F9")
        ])
    ]))

    return table


def add_page_number(canvas, document):
    """Add page numbers to the bottom of each PDF page."""

    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))

    canvas.drawRightString(
        A4[0] - 20 * mm,
        12 * mm,
        f"VulnScope | Page {document.page}"
    )

    canvas.restoreState()


# --------------------------------------------------
# Main PDF report generator
# --------------------------------------------------

def generate_pdf_report(scan_result, output_path):
    """
    Generate a PDF report from a successful HTTP header scan.

    The output file must be saved inside the project's reports directory.
    Returns the generated PDF path as a string.
    """

    results, summary, total_headers, missing_headers = (
        validate_scan_result(scan_result)
    )

    destination = validate_output_path(output_path)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise RuntimeError("Unable to create the report directory.")

    styles = create_styles()

    document = SimpleDocTemplate(
        str(destination),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=22 * mm,
        title="VulnScope Vulnerability Assessment Report",
        author="VulnScope"
    )

    story = []

    # 1. Report title

    story.append(Paragraph("VULNSCOPE", styles["ReportTitle"]))

    story.append(Paragraph(
        "Vulnerability Assessment Report",
        styles["Subtitle"]
    ))

    story.append(Paragraph(
        "HTTP Security Header Assessment",
        styles["SectionHeading"]
    ))

    # 2. Target information

    scan_date = datetime.now().astimezone().strftime(
        "%d %B %Y, %H:%M:%S %Z"
    )

    target_data = [
        ["Assessment Detail", "Value"],
        [
            "Target URL",
            Paragraph(
                safe_text(scan_result.get("final_url")),
                styles["ReportBody"]
            )
        ],
        ["Scan Date", safe_text(scan_date)],
        [
            "HTTP Status Code",
            safe_text(scan_result.get("status_code", "N/A"))
        ],
        ["Headers Checked", str(total_headers)]
    ]

    story.append(create_table(
        target_data,
        column_widths=[50 * mm, 110 * mm]
    ))

    story.append(Spacer(1, 12))

    # 3. Executive summary

    story.append(Paragraph(
        "Executive Summary",
        styles["SectionHeading"]
    ))

    risk_level = safe_text(scan_result.get("risk_level", "Unknown"))

    story.append(Paragraph(
        (
            f"The assessment checked <b>{total_headers}</b> HTTP security "
            f"headers. It identified <b>{missing_headers}</b> missing "
            f"headers. The preliminary header-based risk level is "
            f"<b>{risk_level}</b>."
        ),
        styles["ReportBody"]
    ))

    story.append(Paragraph(
        "This assessment evaluates HTTP security header configuration "
        "only. It does not establish whether the target has been "
        "compromised or identify every possible application vulnerability.",
        styles["ReportBody"]
    ))

    # 4. Severity summary

    story.append(Paragraph(
        "Risk Assessment Summary",
        styles["SectionHeading"]
    ))

    severity_data = [
        ["Severity", "Missing Headers"],
        ["High", str(summary.get("High", 0))],
        ["Medium", str(summary.get("Medium", 0))],
        ["Low", str(summary.get("Low", 0))]
    ]

    story.append(create_table(
        severity_data,
        column_widths=[80 * mm, 80 * mm]
    ))

    # 5. Detailed findings

    story.append(Paragraph(
        "Detailed Security Header Findings",
        styles["SectionHeading"]
    ))

    findings_data = [
        ["Security Header", "Status", "Severity"]
    ]

    for item in results:
        findings_data.append([
            Paragraph(
                safe_text(item.get("header")),
                styles["SmallText"]
            ),
            safe_text(item.get("status")),
            safe_text(item.get("severity"))
        ])

    story.append(create_table(
        findings_data,
        column_widths=[75 * mm, 40 * mm, 45 * mm]
    ))

    # 6. Remediation recommendations

    story.append(Paragraph(
        "Remediation Recommendations",
        styles["SectionHeading"]
    ))

    missing_findings = [
        item for item in results
        if str(item.get("status", "")).strip().lower() == "missing"
    ]

    if missing_findings:
        for item in missing_findings:
            header_name = str(
                item.get("header", "Unknown header")
            )

            recommendation = RECOMMENDATIONS.get(
                header_name,
                "Review the security configuration and configure "
                "the missing header where appropriate."
            )

            story.append(KeepTogether([
                Paragraph(
                    f"<b>{safe_text(header_name)}</b>",
                    styles["ReportBody"]
                ),
                Paragraph(
                    safe_text(recommendation),
                    styles["SmallText"]
                ),
                Spacer(1, 6)
            ]))
    else:
        story.append(Paragraph(
            "No missing security headers were identified in this assessment.",
            styles["ReportBody"]
        ))

    # 7. Limitations and disclaimer

    story.append(Paragraph(
        "Assessment Limitations",
        styles["SectionHeading"]
    ))

    story.append(Paragraph(
        "This report covers the HTTP security headers checked by "
        "VulnScope. It does not include a complete penetration test, "
        "source-code review, authentication testing, or comprehensive "
        "infrastructure assessment. A missing header does not by itself "
        "prove that an exploit is possible.",
        styles["SmallText"]
    ))

    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "Authorization Disclaimer",
        styles["SectionHeading"]
    ))

    story.append(Paragraph(
        "Assessments should only be performed against systems for which "
        "the tester has explicit authorization. The findings in this "
        "report are intended to support defensive security review and "
        "remediation.",
        styles["SmallText"]
    ))

    # Build the PDF

    try:
        document.build(
            story,
            onFirstPage=add_page_number,
            onLaterPages=add_page_number
        )
    except Exception:
        # Remove an incomplete PDF if generation fails.
        try:
            if destination.exists():
                destination.unlink()
        except OSError:
            pass

        raise RuntimeError("Unable to generate the PDF report.")

    return str(destination)
