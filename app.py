
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    send_file,
    abort,
    redirect,
    url_for,
    session
)

from scanners.header_scanner import scan_security_headers
from utils.database import get_connection, initialize_database
from utils.report_generator import generate_pdf_report


# Load environment variables from the .env file.
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# Read the Flask secret key securely.
SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is missing. Please configure it in your .env file."
    )


app = Flask(__name__)
app.secret_key = SECRET_KEY

REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

initialize_database()


def save_scan(scan_result):
    """Save a successful scan to SQLite and return its ID."""

    connection = get_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO scan_history (
                target_url,
                status_code,
                total_headers_checked,
                missing_headers,
                high_severity,
                medium_severity,
                low_severity,
                risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_result["final_url"],
                scan_result["status_code"],
                scan_result["total_headers_checked"],
                scan_result["missing_headers"],
                scan_result["severity_summary"]["High"],
                scan_result["severity_summary"]["Medium"],
                scan_result["severity_summary"]["Low"],
                scan_result["risk_level"]
            )
        )

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()


def save_report_record(scan_id, filename):
    """Save the generated PDF filename in SQLite."""

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO scan_reports (scan_id, filename)
            VALUES (?, ?)
            """,
            (scan_id, filename)
        )

        connection.commit()

    finally:
        connection.close()


def get_dashboard_stats(scan_result=None):
    """Retrieve dashboard statistics."""

    connection = get_connection()

    try:
        total_scans = connection.execute(
            "SELECT COUNT(*) FROM scan_history"
        ).fetchone()[0]

        reports_generated = connection.execute(
            "SELECT COUNT(*) FROM scan_reports"
        ).fetchone()[0]

    finally:
        connection.close()

    vulnerabilities = 0
    high_severity = 0

    if scan_result and scan_result.get("success"):
        vulnerabilities = scan_result["missing_headers"]
        high_severity = scan_result["severity_summary"]["High"]

    return {
        "total_scans": total_scans,
        "vulnerabilities": vulnerabilities,
        "high_severity": high_severity,
        "reports_generated": reports_generated
    }


def get_scan_history():
    """Retrieve the latest 10 scan records."""

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM scan_history
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

        return rows

    finally:
        connection.close()


@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        target_url = request.form.get("target_url", "").strip()

        if not target_url:
            session["scan_result"] = {
                "success": False,
                "error": "Please enter a target URL."
            }

            return redirect(url_for("home"))

        scan_result = scan_security_headers(target_url)

        if scan_result.get("success"):

            scan_id = save_scan(scan_result)

            try:
                filename = (
                    f"vulnscope_report_{scan_id}_"
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )

                output_path = REPORTS_DIR / filename

                generate_pdf_report(
                    scan_result,
                    output_path
                )

                save_report_record(scan_id, filename)

                session["report_id"] = scan_id

            except Exception:
                app.logger.exception(
                    "PDF report generation failed."
                )

                session["report_error"] = (
                    "The scan was saved, but PDF generation failed."
                )

        session["scan_result"] = scan_result

        return redirect(url_for("home"))

    scan_result = session.pop("scan_result", None)
    report_id = session.pop("report_id", None)
    report_error = session.pop("report_error", None)

    dashboard_stats = get_dashboard_stats(scan_result)
    scan_history = get_scan_history()

    return render_template(
        "index.html",
        scan_result=scan_result,
        dashboard_stats=dashboard_stats,
        scan_history=scan_history,
        report_id=report_id,
        report_error=report_error
    )


@app.route("/download-report/<int:scan_id>")
def download_report(scan_id):
    """Download a PDF report associated with a scan."""

    connection = get_connection()

    try:
        report = connection.execute(
            """
            SELECT filename
            FROM scan_reports
            WHERE scan_id = ?
            """,
            (scan_id,)
        ).fetchone()

    finally:
        connection.close()

    if report is None:
        abort(404)

    filename = report["filename"]

    if Path(filename).name != filename:
        abort(404)

    report_path = REPORTS_DIR / filename

    if not report_path.is_file():
        abort(404)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
