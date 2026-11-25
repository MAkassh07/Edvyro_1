"""Pytest fixtures and helpers for SecureAuth automated security tests."""

import re
import pytest
from app import create_app
from app.config import TestingConfig
from app.extensions import limiter

CSRF_PATTERN = re.compile(r'name="csrf_token"\s+value="([^"]+)"')
STRONG_PASSWORD = "Valid!Password#2026"


def extract_csrf_token(html_bytes: bytes) -> str:
    """Extract the Flask-WTF CSRF token from an HTML form response."""
    html = html_bytes.decode("utf-8")
    match = CSRF_PATTERN.search(html)
    assert match is not None, "Expected csrf_token hidden input in HTML form."
    return match.group(1)


@pytest.fixture()
def app(tmp_path):
    """Create an isolated SecureAuth app instance backed by a temporary SQLite DB."""
    db_file = tmp_path / "test_secureauth.db"
    application = create_app(
        {
            "TESTING": True,
            "DEBUG": False,
            "FLASK_ENV": "testing",
            "SECRET_KEY": TestingConfig.SECRET_KEY,
            "DATABASE_PATH": str(db_file),
            "SESSION_COOKIE_SECURE": False,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "WTF_CSRF_ENABLED": True,
            "RATELIMIT_STORAGE_URI": "memory://",
            "SESSION_LIFETIME_MINUTES": 15,
            "SESSION_TIMEOUT_SECONDS": 900,
        }
    )

    with application.app_context():
        limiter.reset()

    yield application

    with application.app_context():
        limiter.reset()


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


def register_user(client, email: str, password: str = STRONG_PASSWORD, confirm: str | None = None):
    """Helper to register a user through the real CSRF-protected /register route."""
    if confirm is None:
        confirm = password
    page = client.get("/register")
    token = extract_csrf_token(page.data)
    return client.post(
        "/register",
        data={
            "csrf_token": token,
            "email": email,
            "password": password,
            "confirm_password": confirm,
        },
        follow_redirects=False,
    )


def login_user(client, email: str, password: str = STRONG_PASSWORD):
    """Helper to log in through the real CSRF-protected /login route."""
    page = client.get("/login")
    token = extract_csrf_token(page.data)
    return client.post(
        "/login",
        data={
            "csrf_token": token,
            "email": email,
            "password": password,
        },
        follow_redirects=False,
    )
