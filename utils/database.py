
import json
import math
import sqlite3

from pathlib import Path


# --------------------------------------------------
# DATABASE CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATABASE_PATH = BASE_DIR / "database" / "vulnscope.db"

DATABASE_TIMEOUT = 10


# --------------------------------------------------
# VALIDATION HELPERS
# --------------------------------------------------

def validate_text(value, field_name):
    """Validate required text fields."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")

    return value.strip()


def validate_count(value, field_name):
    """Validate non-negative integer count fields."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer.")

    if value < 0:
        raise ValueError(f"{field_name} cannot be negative.")

    return value


def validate_score(value, field_name):
    """Validate a finite risk score between 0 and 10."""

    if isinstance(value, bool):
        raise ValueError(
            f"{field_name} must be a number between 0 and 10."
        )

    try:
        value = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} must be a valid number.")

    if not math.isfinite(value) or not 0 <= value <= 10:
        raise ValueError(
            f"{field_name} must be between 0 and 10."
        )

    return value


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_connection():
    """Create and return a configured SQLite connection."""

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=DATABASE_TIMEOUT
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")

    return connection


# --------------------------------------------------
# DATABASE INITIALIZATION
# --------------------------------------------------

def initialize_database():
    """
    Create all VulnScope database tables.

    Existing tables and records are preserved.
    """

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = get_connection()

    try:

        # Existing HTTP security-header scan history.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status_code INTEGER,
                total_headers_checked INTEGER,
                missing_headers INTEGER,
                high_severity INTEGER,
                medium_severity INTEGER,
                low_severity INTEGER,
                risk_level TEXT
            )
        """)

        # Existing PDF report records.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id)
                    REFERENCES scan_history(id)
            )
        """)

        # Unified history for all scanner types.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS unified_scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                scan_type TEXT NOT NULL,

                target TEXT NOT NULL,

                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                status TEXT NOT NULL DEFAULT 'Completed',

                total_findings INTEGER DEFAULT 0,

                critical_count INTEGER DEFAULT 0,

                high_count INTEGER DEFAULT 0,

                medium_count INTEGER DEFAULT 0,

                low_count INTEGER DEFAULT 0,

                informational_count INTEGER DEFAULT 0,

                average_score REAL DEFAULT 0,

                highest_score REAL DEFAULT 0,

                overall_risk TEXT,

                scan_data TEXT
            )
        """)

        # Indexes for faster history queries.
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_unified_scan_target
            ON unified_scan_history(target)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_unified_scan_date
            ON unified_scan_history(scanned_at)
        """)

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# --------------------------------------------------
# SAVE UNIFIED SCAN
# --------------------------------------------------

def save_unified_scan(
    scan_type,
    target,
    total_findings=0,
    critical_count=0,
    high_count=0,
    medium_count=0,
    low_count=0,
    informational_count=0,
    average_score=0,
    highest_score=0,
    overall_risk=None,
    scan_data=None,
    status="Completed"
):
    """Validate and save a scanner result in unified history."""

    # Validate text fields.
    scan_type = validate_text(scan_type, "scan_type")
    target = validate_text(target, "target")
    status = validate_text(status, "status")

    if overall_risk is not None:
        overall_risk = validate_text(
            overall_risk,
            "overall_risk"
        )

    # Validate finding counts.
    total_findings = validate_count(
        total_findings,
        "total_findings"
    )

    critical_count = validate_count(
        critical_count,
        "critical_count"
    )

    high_count = validate_count(
        high_count,
        "high_count"
    )

    medium_count = validate_count(
        medium_count,
        "medium_count"
    )

    low_count = validate_count(
        low_count,
        "low_count"
    )

    informational_count = validate_count(
        informational_count,
        "informational_count"
    )

    # Validate risk scores.
    average_score = validate_score(
        average_score,
        "average_score"
    )

    highest_score = validate_score(
        highest_score,
        "highest_score"
    )

    if average_score > highest_score and total_findings > 0:
        raise ValueError(
            "average_score cannot exceed highest_score."
        )

    if total_findings == 0 and (
        average_score != 0 or highest_score != 0
    ):
        raise ValueError(
            "Risk scores must be zero when there are no findings."
        )

    # Serialize scan data safely.
    serialized_data = None

    if scan_data is not None:

        try:
            serialized_data = json.dumps(
                scan_data,
                ensure_ascii=False,
                allow_nan=False
            )

        except (TypeError, ValueError, OverflowError):
            raise ValueError(
                "scan_data must contain valid JSON-serializable data."
            )

    connection = get_connection()

    try:

        cursor = connection.execute("""
            INSERT INTO unified_scan_history (
                scan_type,
                target,
                status,
                total_findings,
                critical_count,
                high_count,
                medium_count,
                low_count,
                informational_count,
                average_score,
                highest_score,
                overall_risk,
                scan_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_type,
            target,
            status,
            total_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
            informational_count,
            average_score,
            highest_score,
            overall_risk,
            serialized_data
        ))

        connection.commit()

        return cursor.lastrowid

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# --------------------------------------------------
# GET UNIFIED SCAN HISTORY
# --------------------------------------------------

def get_unified_scan_history(limit=50):
    """Return the most recent unified scan records."""

    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= 500
    ):
        raise ValueError(
            "History limit must be between 1 and 500."
        )

    connection = get_connection()

    try:

        cursor = connection.execute("""
            SELECT *
            FROM unified_scan_history
            ORDER BY scanned_at DESC, id DESC
            LIMIT ?
        """, (limit,))

        return [
            dict(row)
            for row in cursor.fetchall()
        ]

    finally:
        connection.close()


# --------------------------------------------------
# DIRECT EXECUTION
# --------------------------------------------------

if __name__ == "__main__":

    initialize_database()

    print("VulnScope database initialized successfully.")
    print(f"Database location: {DATABASE_PATH}")
