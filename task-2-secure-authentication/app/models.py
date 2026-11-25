"""SQLite database connection and parameterized user data access layer."""

from datetime import datetime, timezone
import os
import sqlite3
from typing import Any
from flask import current_app, g


def get_db() -> sqlite3.Connection:
    """Return a request-scoped SQLite connection."""
    if "db" not in g:
        db_path = current_app.config["DATABASE_PATH"]
        db_dir = os.path.dirname(os.path.abspath(db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def close_db(_exception: BaseException | None = None) -> None:
    """Close the SQLite connection at the end of a request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create the users table if it does not already exist."""
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    db.commit()


def create_user(email: str, password_hash: str) -> tuple[bool, int | None]:
    """Insert a new user with parameterized SQL. Returns (created, user_id)."""
    db = get_db()
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        cursor = db.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, password_hash, created_at),
        )
        db.commit()
        return True, cursor.lastrowid
    except sqlite3.IntegrityError:
        return False, None


def get_user_for_auth(email: str) -> dict[str, Any] | None:
    """Fetch user record including password_hash strictly for server-side verification."""
    db = get_db()
    row = db.execute(
        "SELECT id, email, password_hash, created_at FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    return dict(row) if row is not None else None


def get_public_user_by_id(user_id: int) -> dict[str, Any] | None:
    """Fetch safe user metadata (never selects password_hash)."""
    db = get_db()
    row = db.execute(
        "SELECT id, email, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def init_app(app: Any) -> None:
    """Register database teardown and initialize schema."""
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
