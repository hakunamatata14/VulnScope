
import os
import json
import hmac
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    render_template_string,
    request,
    send_file,
    abort,
    redirect,
    url_for,
    session
)

from scanners.header_scanner import scan_security_headers
from scanners.port_scanner import scan_ports
from scanners.ssl_scanner import scan_ssl_tls
from scanners.zap_scanner import scan_with_zap

from utils.database import (
    get_connection,
    initialize_database,
    save_unified_scan,
    get_unified_scan_history
)

from utils.report_generator import generate_pdf_report
from utils.risk_scoring import score_findings


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("VULNSCOPE_USERNAME")
ADMIN_PASSWORD = os.getenv("VULNSCOPE_PASSWORD")

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "SECRET_KEY must be configured in .env "
        "and contain at least 32 characters."
    )

if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError(
        "Configure VULNSCOPE_USERNAME and VULNSCOPE_PASSWORD "
        "in your .env file before starting VulnScope."
    )

if len(ADMIN_PASSWORD) < 16:
    raise RuntimeError(
        "VULNSCOPE_PASSWORD must contain at least 16 characters."
    )

app = Flask(__name__)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    ),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1024 * 1024
)

REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

initialize_database()


# --------------------------------------------------
# JSON TEMPLATE FILTER
# --------------------------------------------------

def safe_from_json(value):
    """Safely parse JSON stored in scan history."""

    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str):
        return {}

    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return {}


app.jinja_env.filters["from_json"] = safe_from_json


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>VulnScope Login</title>
    <style>
        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #0f172a;
            color: #e2e8f0;
            font-family: Arial, sans-serif;
        }

        .login-box {
            width: min(380px, 90%);
            padding: 32px;
            background: #1e293b;
            border-radius: 12px;
        }

        h1 {
            margin-top: 0;
            color: #38bdf8;
        }

        label {
            display: block;
            margin: 16px 0 6px;
        }

        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #475569;
            border-radius: 6px;
            background: #0f172a;
            color: white;
        }

        button {
            width: 100%;
            margin-top: 22px;
            padding: 12px;
            border: 0;
            border-radius: 6px;
            background: #0891b2;
            color: white;
            font-weight: bold;
            cursor: pointer;
        }

        .error {
            color: #fca5a5;
        }
    </style>
</head>
<body>
    <main class="login-box">
        <h1>VulnScope</h1>
        <p>Administrator sign in</p>

        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}

        <form method="POST" action="{{ url_for('login') }}">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token }}"
            >

            <label for="username">Username</label>
            <input
                id="username"
                name="username"
                autocomplete="username"
                required
            >

            <label for="password">Password</label>
            <input
                id="password"
                type="password"
                name="password"
                autocomplete="current-password"
                required
            >

            <button type="submit">Sign in</button>
        </form>
    </main>
</body>
</html>
"""


def validate_same_origin():
    """
    Reject cross-origin state-changing requests.

    Browser form submissions normally include Origin or Referer.
    Requests without either header are rejected.
    """

    origin = request.headers.get("Origin")

    if origin:
        supplied_host = urlsplit(origin).netloc.lower()

    else:
        referer = request.headers.get("Referer")

        if not referer:
            abort(403)

        supplied_host = urlsplit(referer).netloc.lower()

    if not supplied_host or supplied_host != request.host.lower():
        abort(403)


@app.before_request
def protect_application():
    """Protect application routes and state-changing requests."""

    # Allow static files.
    if request.endpoint == "static":
        return None

    # Login has its own CSRF-token validation.
    if request.endpoint == "login":
        return None

    # Redirect unauthenticated users before processing protected requests.
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    # Validate origin for authenticated state-changing requests.
    if request.method == "POST":
        validate_same_origin()

    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    """Administrator login."""

    if session.get("authenticated"):
        return redirect(url_for("home"))

    if "login_csrf" not in session:
        session["login_csrf"] = secrets.token_urlsafe(32)

    error = None

    if request.method == "POST":

        submitted_token = request.form.get("csrf_token", "")

        if not hmac.compare_digest(
            str(session.get("login_csrf", "")),
            str(submitted_token)
        ):
            abort(403)

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_username = hmac.compare_digest(
            username,
            ADMIN_USERNAME
        )

        valid_password = hmac.compare_digest(
            password,
            ADMIN_PASSWORD
        )

        if valid_username and valid_password:
            session.clear()
            session.permanent = True
            session["authenticated"] = True
            session["login_csrf"] = secrets.token_urlsafe(32)

            return redirect(url_for("home"))

        error = "Invalid username or password."

    return render_template_string(
        LOGIN_TEMPLATE,
        error=error,
        csrf_token=session["login_csrf"]
    )


@app.route("/logout", methods=["POST"])
def logout():
    """End the administrator session."""

    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# GENERAL HELPERS
# --------------------------------------------------

def safe_json_data(data):
    """Convert scan data into JSON-serializable Python data."""

    return json.loads(
        json.dumps(data, default=str, allow_nan=False)
    )


def get_header_finding_count(scan_result):
    """Calculate the number of missing HTTP security headers."""

    missing = scan_result.get("missing_headers")

    if isinstance(missing, (list, tuple, set)):
        return len(missing)

    if isinstance(missing, int) and not isinstance(missing, bool):
        return max(0, missing)

    severity = scan_result.get("severity_summary", {})

    return sum(
        int(severity.get(level, 0) or 0)
        for level in ("High", "Medium", "Low")
    )


def store_scan_reference(scan_type, scan_id):
    """Store only a database reference in the browser session."""

    session["scan_reference"] = {
        "scan_type": scan_type,
        "scan_id": scan_id
    }


def load_scan_reference(expected_type):
    """Retrieve the latest scan result from SQLite."""

    reference = session.pop("scan_reference", None)

    if not isinstance(reference, dict):
        return None

    if reference.get("scan_type") != expected_type:
        return None

    scan_id = reference.get("scan_id")

    if isinstance(scan_id, bool) or not isinstance(scan_id, int):
        return None

    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT scan_type, scan_data
            FROM unified_scan_history
            WHERE id = ?
            """,
            (scan_id,)
        ).fetchone()

    finally:
        connection.close()

    if row is None or row["scan_type"] != expected_type:
        return None

    result = safe_from_json(row["scan_data"])

    return result if isinstance(result, dict) else None


def store_error_result(session_key, error):
    """Store only a small error message in the session."""

    session[session_key] = {
        "success": False,
        "error": str(error)
    }


def pop_error_result(session_key):
    """Retrieve a small error result."""

    return session.pop(session_key, None)


# --------------------------------------------------
# DATABASE FUNCTIONS
# --------------------------------------------------

def save_scan(scan_result):
    """Save a successful HTTP security-header scan."""

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
                get_header_finding_count(scan_result),
                scan_result["severity_summary"]["High"],
                scan_result["severity_summary"]["Medium"],
                scan_result["severity_summary"]["Low"],
                scan_result["risk_level"]
            )
        )

        connection.commit()
        return cursor.lastrowid

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def save_report_record(scan_id, filename):
    """Save PDF report information in SQLite."""

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

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def save_header_scan_history(scan_result):
    """Save HTTP header scan in unified history."""

    severity = scan_result.get("severity_summary", {})

    high = int(severity.get("High", 0) or 0)
    medium = int(severity.get("Medium", 0) or 0)
    low = int(severity.get("Low", 0) or 0)

    return save_unified_scan(
        scan_type="HTTP Headers",
        target=scan_result.get(
            "final_url",
            scan_result.get("target_url", "")
        ),
        total_findings=get_header_finding_count(scan_result),
        critical_count=0,
        high_count=high,
        medium_count=medium,
        low_count=low,
        informational_count=0,
        overall_risk=scan_result.get("risk_level"),
        scan_data=safe_json_data(scan_result)
    )


def save_port_scan_history(scan_result):
    """Save complete port scan results."""

    return save_unified_scan(
        scan_type="Port Scanner",
        target=scan_result.get("target", ""),
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        informational_count=0,
        overall_risk="Informational",
        scan_data=safe_json_data(scan_result)
    )


def save_ssl_scan_history(scan_result):
    """Save complete SSL/TLS scan results."""

    return save_unified_scan(
        scan_type="SSL/TLS",
        target=scan_result.get("target", ""),
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        informational_count=0,
        overall_risk="Informational",
        scan_data=safe_json_data(scan_result)
    )


def save_zap_scan_history(scan_result):
    """Save ZAP results and scored findings."""

    findings = scan_result.get("findings", [])
    risk_summary = scan_result.get("risk_summary", {})
    severity_summary = risk_summary.get("severity_summary", {})

    return save_unified_scan(
        scan_type="ZAP",
        target=scan_result.get("target", ""),
        total_findings=risk_summary.get(
            "total_findings",
            len(findings)
        ),
        critical_count=severity_summary.get("critical", 0),
        high_count=severity_summary.get("high", 0),
        medium_count=severity_summary.get("medium", 0),
        low_count=severity_summary.get("low", 0),
        informational_count=severity_summary.get("informational", 0),
        average_score=risk_summary.get("average_score", 0),
        highest_score=risk_summary.get("highest_score", 0),
        overall_risk=risk_summary.get("overall_risk"),
        scan_data=safe_json_data(scan_result)
    )


# --------------------------------------------------
# DASHBOARD STATISTICS
# --------------------------------------------------

def get_dashboard_stats():
    """Calculate dashboard statistics without double-counting HTTP scans."""

    connection = get_connection()

    try:
        http_stats = connection.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(missing_headers), 0) AS findings,
                COALESCE(SUM(high_severity), 0) AS high_count,
                COALESCE(SUM(medium_severity), 0) AS medium_count,
                COALESCE(SUM(low_severity), 0) AS low_count
            FROM scan_history
            """
        ).fetchone()

        unified_stats = connection.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(total_findings), 0) AS findings,
                COALESCE(SUM(critical_count), 0) AS critical_count,
                COALESCE(SUM(high_count), 0) AS high_count,
                COALESCE(SUM(medium_count), 0) AS medium_count,
                COALESCE(SUM(low_count), 0) AS low_count,
                COALESCE(SUM(informational_count), 0)
                    AS informational_count
            FROM unified_scan_history
            WHERE scan_type != 'HTTP Headers'
            """
        ).fetchone()

        reports_generated = connection.execute(
            "SELECT COUNT(*) FROM scan_reports"
        ).fetchone()[0]

        return {
            "total_scans": (
                http_stats["total_scans"]
                + unified_stats["total_scans"]
            ),
            "vulnerabilities": (
                http_stats["findings"]
                + unified_stats["findings"]
            ),
            "critical_severity": unified_stats["critical_count"],
            "high_severity": (
                http_stats["high_count"]
                + unified_stats["high_count"]
            ),
            "medium_severity": (
                http_stats["medium_count"]
                + unified_stats["medium_count"]
            ),
            "low_severity": (
                http_stats["low_count"]
                + unified_stats["low_count"]
            ),
            "informational": unified_stats["informational_count"],
            "reports_generated": reports_generated
        }

    finally:
        connection.close()


# --------------------------------------------------
# HOME ROUTE - DASHBOARD + HTTP HEADER SCANNER
# --------------------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        target_url = request.form.get("target_url", "").strip()

        if not target_url:
            store_error_result(
                "header_error",
                "Please enter a target URL."
            )
            return redirect(url_for("home"))

        try:
            scan_result = scan_security_headers(target_url)

            if not scan_result.get("success"):
                session["header_error"] = scan_result.get(
                    "error",
                    "The HTTP header scan failed."
                )
                return redirect(url_for("home"))

            unified_scan_id = save_header_scan_history(scan_result)
            store_scan_reference("HTTP Headers", unified_scan_id)

            # Save legacy history separately for dashboard compatibility.
            try:
                legacy_scan_id = save_scan(scan_result)

                filename = (
                    f"vulnscope_report_{legacy_scan_id}_"
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                )

                output_path = REPORTS_DIR / filename

                generate_pdf_report(scan_result, output_path)

                if not output_path.is_file() or output_path.stat().st_size == 0:
                    raise RuntimeError("Generated PDF is missing or empty.")

                save_report_record(legacy_scan_id, filename)
                session["report_id"] = legacy_scan_id

            except Exception:
                app.logger.exception(
                    "Header scan report or legacy history saving failed."
                )
                session["report_error"] = (
                    "The scan was saved, but its PDF report "
                    "or legacy history could not be saved."
                )

        except Exception:
            app.logger.exception("HTTP header scan failed.")
            store_error_result(
                "header_error",
                "The scan could not be completed or saved."
            )

        return redirect(url_for("home"))

    scan_result = load_scan_reference("HTTP Headers")
    scan_error = pop_error_result("header_error")
    report_id = session.pop("report_id", None)
    report_error = session.pop("report_error", None)

    dashboard_stats = get_dashboard_stats()
    recent_scans = get_unified_scan_history(limit=10)

    return render_template(
        "index.html",
        scan_result=scan_result or scan_error,
        dashboard_stats=dashboard_stats,
        recent_scans=recent_scans,
        report_id=report_id,
        report_error=report_error
    )


# --------------------------------------------------
# NMAP PORT SCANNER
# --------------------------------------------------

@app.route("/port-scan", methods=["GET", "POST"])
def port_scan():

    if request.method == "POST":

        target = request.form.get("port_target", "").strip()

        if not target:
            store_error_result(
                "port_scan_error",
                "Please enter an IP address or hostname."
            )
            return redirect(url_for("port_scan"))

        try:
            result = scan_ports(target)

            if result.get("success"):
                scan_id = save_port_scan_history(result)
                store_scan_reference("Port Scanner", scan_id)
            else:
                store_error_result(
                    "port_scan_error",
                    result.get("error", "Port scan failed.")
                )

        except Exception:
            app.logger.exception("Port scan failed.")
            store_error_result(
                "port_scan_error",
                "The port scan could not be completed or saved."
            )

        return redirect(url_for("port_scan"))

    result = load_scan_reference("Port Scanner")
    error = pop_error_result("port_scan_error")

    return render_template(
        "port_scan.html",
        port_scan_result=result or error
    )


# --------------------------------------------------
# SSL/TLS ANALYZER
# --------------------------------------------------

@app.route("/ssl-scan", methods=["GET", "POST"])
def ssl_scan():

    if request.method == "POST":

        target = request.form.get("ssl_target", "").strip()

        if not target:
            store_error_result(
                "ssl_scan_error",
                "Please enter a domain name."
            )
            return redirect(url_for("ssl_scan"))

        try:
            result = scan_ssl_tls(target)

            if result.get("success"):
                scan_id = save_ssl_scan_history(result)
                store_scan_reference("SSL/TLS", scan_id)
            else:
                store_error_result(
                    "ssl_scan_error",
                    result.get("error", "SSL/TLS scan failed.")
                )

        except Exception:
            app.logger.exception("SSL/TLS scan failed.")
            store_error_result(
                "ssl_scan_error",
                "The SSL/TLS scan could not be completed or saved."
            )

        return redirect(url_for("ssl_scan"))

    result = load_scan_reference("SSL/TLS")
    error = pop_error_result("ssl_scan_error")

    return render_template(
        "ssl_scan.html",
        ssl_scan_result=result or error
    )


# --------------------------------------------------
# OWASP ZAP SCANNER
# --------------------------------------------------

@app.route("/zap-scan", methods=["GET", "POST"])
def zap_scan():

    if request.method == "POST":

        target = request.form.get("zap_target", "").strip()

        if not target:
            store_error_result(
                "zap_scan_error",
                "Please enter a target URL."
            )
            return redirect(url_for("zap_scan"))

        try:
            # Spider and passive scan only.
            result = scan_with_zap(
                target,
                max_children=5,
                timeout=180
            )

            if result.get("success"):

                findings = result.get("findings", [])
                scoring_result = score_findings(findings)

                result["scored_findings"] = scoring_result["findings"]
                result["risk_summary"] = scoring_result["summary"]

                scan_id = save_zap_scan_history(result)
                store_scan_reference("ZAP", scan_id)

            else:
                store_error_result(
                    "zap_scan_error",
                    result.get("error", "ZAP scan failed.")
                )

        except Exception:
            app.logger.exception("ZAP scan, scoring or saving failed.")
            store_error_result(
                "zap_scan_error",
                "The ZAP scan could not be completed, scored or saved."
            )

        return redirect(url_for("zap_scan"))

    result = load_scan_reference("ZAP")
    error = pop_error_result("zap_scan_error")

    return render_template(
        "zap_scan.html",
        zap_scan_result=result or error
    )


# --------------------------------------------------
# UNIFIED SCAN HISTORY
# --------------------------------------------------

@app.route("/scan-history")
def scan_history():

    history = get_unified_scan_history(limit=50)

    return render_template(
        "scan_history.html",
        scan_history=history
    )


# --------------------------------------------------
# PDF REPORT DOWNLOAD
# --------------------------------------------------

@app.route("/download-report/<int:scan_id>")
def download_report(scan_id):

    if scan_id <= 0:
        abort(404)

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

    if not isinstance(filename, str):
        abort(404)

    if Path(filename).name != filename:
        abort(404)

    if Path(filename).suffix.lower() != ".pdf":
        abort(404)

    try:
        report_path = (REPORTS_DIR / filename).resolve()
        report_path.relative_to(REPORTS_DIR.resolve())
    except (ValueError, OSError):
        abort(404)

    if not report_path.is_file():
        abort(404)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf"
    )


# --------------------------------------------------
# APPLICATION START
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False,
        use_reloader=False,
        threaded=True
    )
