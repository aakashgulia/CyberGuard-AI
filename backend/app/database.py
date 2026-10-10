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


def save_prediction(predicted_category, confidence, features):
    timestamp = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO prediction_history (
                timestamp,
                predicted_category,
                confidence,
                features_json
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                predicted_category,
                confidence,
                json.dumps(features),
                json.dumps(features),
            ),
        )
        return cursor.lastrowid