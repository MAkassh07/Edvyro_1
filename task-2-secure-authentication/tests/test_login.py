"""Automated tests for SecureAuth login and generic anti-enumeration error handling."""

import pytest

from tests.conftest import (
    STRONG_PASSWORD,
    extract_csrf_token,
    login_user,
    register_user,
)


def test_successful_login(client):
    """7. Registered user can log in with valid credentials and reach dashboard."""
    register_user(client, "valid@example.com", STRONG_PASSWORD)
    response = login_user(client, "valid@example.com", STRONG_PASSWORD)
    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_failed_login_incorrect_password(client):
    """8. Login fails with HTTP 401 when password is wrong."""
    register_user(client, "member@example.com", STRONG_PASSWORD)
    response = login_user(client, "member@example.com", "Wrong!Password#9999")
    assert response.status_code == 401
    assert b"Invalid email or password." in response.data


def test_failed_login_nonexistent_email(client):
    """9. Login fails with HTTP 401 for an unregistered email."""
    response = login_user(client, "missing@example.com", STRONG_PASSWORD)
    assert response.status_code == 401
    assert b"Invalid email or password." in response.data


def test_generic_error_message_prevents_enumeration(client):
    """10. Incorrect password and nonexistent email return the exact same generic error message."""
    register_user(client, "existing@example.com", STRONG_PASSWORD)

    wrong_pw_resp = login_user(client, "existing@example.com", "Wrong!Password#9999")
    unknown_email_resp = login_user(client, "nobody@example.com", STRONG_PASSWORD)

    assert wrong_pw_resp.status_code == 401
    assert unknown_email_resp.status_code == 401
    assert b"Invalid email or password." in wrong_pw_resp.data
    assert b"Invalid email or password." in unknown_email_resp.data
    assert b"does not exist" not in unknown_email_resp.data.lower()
    assert b"not found" not in unknown_email_resp.data.lower()


def test_oversized_password_is_rejected_before_database_or_hashing(
    client, monkeypatch
):
    import app.auth as auth_module

    def unexpected_call(*_args, **_kwargs):
        pytest.fail("Oversized login input reached database lookup or password hashing.")

    monkeypatch.setattr(auth_module, "get_user_for_auth", unexpected_call)
    monkeypatch.setattr(auth_module, "verify_password", unexpected_call)
    page = client.get("/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": extract_csrf_token(page.data),
            "email": "valid@example.com",
            "password": "A" * 129,
        },
    )

    assert response.status_code == 401
    assert b"Invalid email or password." in response.data


def test_oversized_email_is_not_reflected(client):
    email = f"{'a' * 250}@example.com"
    response = login_user(client, email, STRONG_PASSWORD)

    assert response.status_code == 401
    assert email.encode() not in response.data
    assert b"Invalid email or password." in response.data


def test_malformed_login_email_uses_generic_error(client):
    response = login_user(client, "not-an-email", STRONG_PASSWORD)

    assert response.status_code == 401
    assert b"Invalid email or password." in response.data
