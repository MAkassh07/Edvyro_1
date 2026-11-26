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
    """Create the application tables if they do not already exist."""
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
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS authenticated_sessions (
            session_id_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            issued_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            revoked_at REAL
        );
        """
    )
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_authenticated_sessions_expiry "
        "ON authenticated_sessions (expires_at);"
    )
    db.execute(
        "DELETE FROM authenticated_sessions WHERE expires_at <= ?",
        (datetime.now(timezone.utc).timestamp(),),
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


def create_authenticated_session_record(
    session_id_hash: str,
    user_id: int,
    issued_at: float,
    expires_at: float,
) -> None:
    """Persist a hashed session identifier and its absolute expiry."""
    db = get_db()
    db.execute(
        "DELETE FROM authenticated_sessions WHERE expires_at <= ?",
        (issued_at,),
    )
    db.execute(
        """
        INSERT INTO authenticated_sessions
            (session_id_hash, user_id, issued_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, NULL)
        """,
        (session_id_hash, user_id, issued_at, expires_at),
    )
    db.commit()


def get_authenticated_session_status(
    session_id_hash: str,
    user_id: int,
    now: float,
) -> str:
    """Return active, revoked, expired, or invalid for a stored session."""
    db = get_db()
    row = db.execute(
        """
        SELECT user_id, expires_at, revoked_at
        FROM authenticated_sessions
        WHERE session_id_hash = ?
        """,
        (session_id_hash,),
    ).fetchone()
    if row is None:
        return "invalid"
    if row["user_id"] != user_id:
        return "invalid"
    if row["revoked_at"] is not None:
        return "revoked"
    if float(row["expires_at"]) <= now:
        db.execute(
            "DELETE FROM authenticated_sessions WHERE session_id_hash = ?",
            (session_id_hash,),
        )
        db.commit()
        return "expired"
    return "active"


def revoke_authenticated_session(session_id_hash: str, revoked_at: float) -> None:
    """Revoke a session without persisting its client-side token."""
    db = get_db()
    db.execute(
        """
        UPDATE authenticated_sessions
        SET revoked_at = ?
        WHERE session_id_hash = ? AND revoked_at IS NULL
        """,
        (revoked_at, session_id_hash),
    )
    db.execute(
        "DELETE FROM authenticated_sessions WHERE expires_at <= ?",
        (revoked_at,),
    )
    db.commit()


def init_app(app: Any) -> None:
    """Register database teardown and initialize schema."""
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
