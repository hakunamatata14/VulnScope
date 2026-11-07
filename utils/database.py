import sqlite3
from pathlib import Path


# Find the main VulnScope project directory.
BASE_DIR = Path(__file__).resolve().parent.parent

# Database file location.
DATABASE_PATH = BASE_DIR / "database" / "vulnscope.db"


def get_connection():
    """Create and return a SQLite database connection."""

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create the scan history and PDF report tables."""

    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = get_connection()

    try:

        # Create scan history table.
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

        # Create PDF report records table.
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

        connection.commit()

    finally:
        connection.close()


if __name__ == "__main__":

    initialize_database()

    print("VulnScope database initialized successfully.")
    print(f"Database location: {DATABASE_PATH}")