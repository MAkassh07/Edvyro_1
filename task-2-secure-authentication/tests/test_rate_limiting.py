"""Automated tests for Flask-Limiter brute-force rate limiting."""

from tests.conftest import STRONG_PASSWORD, login_user, register_user


def test_login_rate_limiting_returns_429(client):
    """11. Repeated failed login attempts trigger HTTP 429 Too Many Requests."""
    register_user(client, "target@example.com", STRONG_PASSWORD)

    # Configured login limit is 5 attempts per minute per IP
    for _ in range(5):
        resp = login_user(client, "target@example.com", "Wrong!Password#1111")
        assert resp.status_code == 401

    sixth_attempt = login_user(client, "target@example.com", "Wrong!Password#1111")
    assert sixth_attempt.status_code == 429
    assert b"Too many attempts" in sixth_attempt.data


def test_registration_rate_limiting_returns_429(client):
    """Repeated registration POST attempts trigger HTTP 429 after 5 requests per hour."""
    for idx in range(5):
        resp = register_user(client, f"spam{idx}@example.com", STRONG_PASSWORD)
        assert resp.status_code in (302, 400)

    sixth_attempt = register_user(client, "spam5@example.com", STRONG_PASSWORD)
    assert sixth_attempt.status_code == 429
