"""Automated tests for SecureAuth account registration and password storage."""

from app.models import get_user_for_auth
from tests.conftest import STRONG_PASSWORD, register_user


def test_successful_registration(client):
    """1. Valid registration succeeds and redirects to login."""
    response = register_user(client, "Alice@Example.com", STRONG_PASSWORD)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_duplicate_email_rejection(client):
    """2. Duplicate email registration (including case-insensitive) is rejected."""
    first = register_user(client, "user@example.com", STRONG_PASSWORD)
    assert first.status_code == 302

    duplicate = register_user(client, "USER@example.com", STRONG_PASSWORD)
    assert duplicate.status_code == 400
    assert b"Unable to complete registration" in duplicate.data


def test_invalid_email_rejection(client):
    """3. Malformed email addresses are rejected by server-side validation."""
    response = register_user(client, "not-a-valid-email", STRONG_PASSWORD)
    assert response.status_code == 400
    assert b"valid email address" in response.data


def test_weak_password_rejection(client):
    """4. Passwords violating length or complexity policy are rejected."""
    response = register_user(client, "weak@example.com", "short123")
    assert response.status_code == 400
    assert b"at least 12 characters" in response.data


def test_password_confirmation_mismatch(client):
    """5. Mismatched password and confirm_password are rejected."""
    response = register_user(
        client,
        "mismatch@example.com",
        STRONG_PASSWORD,
        confirm="Different!Password#2026",
    )
    assert response.status_code == 400
    assert b"do not match" in response.data


def test_database_stores_password_hash_not_plaintext(app, client):
    """6. SQLite stores a cryptographic password hash (scrypt/pbkdf2), never plaintext."""
    email = "hashed@example.com"
    response = register_user(client, email, STRONG_PASSWORD)
    assert response.status_code == 302

    with app.app_context():
        user = get_user_for_auth(email)
        assert user is not None
        assert user["password_hash"] != STRONG_PASSWORD
        assert STRONG_PASSWORD not in user["password_hash"]
        assert user["password_hash"].startswith(("scrypt:", "pbkdf2:"))
