
import json
import sqlite3
from datetime import datetime, timezone

from backend.app.config import PROJECT_ROOT

DATABASE_PATH = PROJECT_ROOT / "data" / "cyberguard.db"


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS prediction_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                predicted_category TEXT NOT NULL,
                confidence REAL NOT NULL,
                features_json TEXT NOT NULL
            )
            """
        )

        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(prediction_history)"
            ).fetchall()
        }

        if "risk_score" not in columns:
            connection.execute(
                "ALTER TABLE prediction_history ADD COLUMN risk_score INTEGER"
            )

        if "risk_level" not in columns:
            connection.execute(
                "ALTER TABLE prediction_history ADD COLUMN risk_level TEXT"
            )


def save_prediction(
    predicted_category,
    confidence,
    features,
    risk_score=None,
    risk_level=None,
):
    timestamp = datetime.now(timezone.utc).isoformat()
    features_json = json.dumps(features)

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO prediction_history (
                timestamp,
                predicted_category,
                confidence,
                features_json,
                risk_score,
                risk_level
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                predicted_category,
                confidence,
                features_json,
                risk_score,
                risk_level,
            ),
        )
        return cursor.lastrowid
