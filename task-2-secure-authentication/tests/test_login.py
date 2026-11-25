"""Automated tests for SecureAuth login and generic anti-enumeration error handling."""

from tests.conftest import STRONG_PASSWORD, login_user, register_user


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
