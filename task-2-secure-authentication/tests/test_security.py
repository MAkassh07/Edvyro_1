"""Automated tests for CSRF protection, hash non-exposure, cookie flags, and malformed input."""

import logging
import secrets

import pytest
from flask import abort

from app.security import log_security_event
from app import create_app
from app.config import ProductionConfig
from tests.conftest import STRONG_PASSWORD, login_user, register_user


def test_csrf_protection_blocks_missing_token(client):
    """17. State-changing POST requests without a valid CSRF token are rejected."""
    resp_register = client.post(
        "/register",
        data={
            "email": "nocsrf@example.com",
            "password": STRONG_PASSWORD,
            "confirm_password": STRONG_PASSWORD,
        },
    )
    assert resp_register.status_code == 400

    resp_login = client.post(
        "/login",
        data={"email": "nocsrf@example.com", "password": STRONG_PASSWORD},
    )
    assert resp_login.status_code == 400


def test_password_hashes_not_exposed_in_responses(client):
    """18. Password hashes never appear in dashboard or authentication HTML responses."""
    register_user(client, "safeview@example.com", STRONG_PASSWORD)
    login_resp = login_user(client, "safeview@example.com", STRONG_PASSWORD)
    assert b"scrypt:" not in login_resp.data
    assert b"pbkdf2:" not in login_resp.data

    dash_resp = client.get("/dashboard")
    assert dash_resp.status_code == 200
    assert b"scrypt:" not in dash_resp.data
    assert b"pbkdf2:" not in dash_resp.data
    assert b"password_hash" not in dash_resp.data


def test_production_cookie_configuration(tmp_path):
    """19. ProductionConfig enforces HttpOnly, Secure, and SameSite=Lax cookies."""

    class IsolatedProductionConfig(ProductionConfig):
        SECRET_KEY = secrets.token_hex(32)
        DATABASE_PATH = str(tmp_path / "prod_config_test.db")

    prod_app = create_app(IsolatedProductionConfig)
    assert prod_app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert prod_app.config["SESSION_COOKIE_SECURE"] is True
    assert prod_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert prod_app.config["DEBUG"] is False


def test_malformed_input_does_not_crash_app(client):
    """20. Unexpected or SQL-like malformed inputs are handled cleanly without 500 errors."""
    page = client.get("/login")
    # Extract CSRF token safely
    html = page.data.decode("utf-8")
    token = html.split('name="csrf_token" value="')[1].split('"')[0]

    malformed_login = client.post(
        "/login",
        data={"csrf_token": token, "email": "' OR '1'='1 --\x00", "password": "\x00" * 500},
    )
    assert malformed_login.status_code == 401
    assert b"Invalid email or password." in malformed_login.data


def test_security_headers_are_present(client):
    """Defensive HTTP security headers are attached to responses."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


@pytest.mark.parametrize("path", ["/login", "/register"])
def test_authentication_pages_prevent_caching(client, path):
    response = client.get(path)

    assert response.headers["Cache-Control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert response.headers["Pragma"] == "no-cache"


def test_registration_logs_user_id_instead_of_email(client, caplog):
    email = "private-log-check@example.com"
    with caplog.at_level(logging.INFO, logger="secureauth.security"):
        response = register_user(client, email, STRONG_PASSWORD)

    assert response.status_code == 302
    assert "event=REGISTER_SUCCESS" in caplog.text
    assert "user_id=1" in caplog.text
    assert email not in caplog.text


def test_security_log_control_characters_cannot_forge_lines(caplog):
    with caplog.at_level(logging.INFO, logger="secureauth.security"):
        log_security_event(
            "RATE_LIMIT_EXCEEDED",
            "127.0.0.1\r\nFORGED",
            "path=/login\nFAKE_EVENT=1",
        )

    lines = caplog.text.splitlines()
    assert len(lines) == 1
    assert "127.0.0.1 FORGED" in lines[0]
    assert "path=/login FAKE_EVENT=1" in lines[0]


def test_http_error_handlers_log_security_events(app, client, caplog):
    def raise_test_error():
        raise RuntimeError("test failure")

    app.add_url_rule(
        "/__test_forbidden",
        view_func=lambda: abort(403),
    )
    app.add_url_rule(
        "/__test_internal_error",
        view_func=raise_test_error,
    )
    app.config["MAX_CONTENT_LENGTH"] = 64
    app.config["PROPAGATE_EXCEPTIONS"] = False

    with caplog.at_level(logging.INFO, logger="secureauth.security"):
        forbidden = client.get("/__test_forbidden")
        oversized = client.post("/login", data={"payload": "x" * 128})
        internal_error = client.get("/__test_internal_error")

    assert forbidden.status_code == 403
    assert oversized.status_code == 413
    assert internal_error.status_code == 500
    assert "event=FORBIDDEN" in caplog.text
    assert "event=PAYLOAD_TOO_LARGE" in caplog.text
    assert "event=INTERNAL_ERROR" in caplog.text
