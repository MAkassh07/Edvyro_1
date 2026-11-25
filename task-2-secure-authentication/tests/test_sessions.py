"""Automated tests for session lifecycle, access control, logout, and expiration."""

import time
from tests.conftest import STRONG_PASSWORD, extract_csrf_token, login_user, register_user


def test_dashboard_inaccessible_without_authentication(client):
    """12. Unauthenticated requests to /dashboard redirect to /login."""
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_dashboard_accessible_after_login(client):
    """13. Authenticated users can access /dashboard and see only their email."""
    register_user(client, "dashuser@example.com", STRONG_PASSWORD)
    register_user(client, "otheruser@example.com", STRONG_PASSWORD)

    login_user(client, "dashuser@example.com", STRONG_PASSWORD)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert b"dashuser@example.com" in dashboard.data
    assert b"otheruser@example.com" not in dashboard.data


def test_logout_clears_authentication_session(client):
    """14. Logging out via POST /logout clears session keys and redirects."""
    register_user(client, "logout@example.com", STRONG_PASSWORD)
    login_user(client, "logout@example.com", STRONG_PASSWORD)

    dash = client.get("/dashboard")
    token = extract_csrf_token(dash.data)
    logout_resp = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)

    assert logout_resp.status_code == 302
    assert "/login" in logout_resp.headers["Location"]

    with client.session_transaction() as sess:
        assert "user_id" not in sess
        assert "last_active_at" not in sess


def test_dashboard_inaccessible_after_logout(client):
    """15. Dashboard denies access after logout."""
    register_user(client, "afterlogout@example.com", STRONG_PASSWORD)
    login_user(client, "afterlogout@example.com", STRONG_PASSWORD)

    dash = client.get("/dashboard")
    token = extract_csrf_token(dash.data)
    client.post("/logout", data={"csrf_token": token}, follow_redirects=False)

    post_logout_dash = client.get("/dashboard", follow_redirects=False)
    assert post_logout_dash.status_code == 302
    assert "/login" in post_logout_dash.headers["Location"]


def test_session_expiration_prevents_access(client):
    """16. Expired inactivity sessions are cleared and blocked from /dashboard."""
    register_user(client, "expired@example.com", STRONG_PASSWORD)
    login_user(client, "expired@example.com", STRONG_PASSWORD)

    # Simulate 20 minutes of inactivity (exceeding the 15-minute / 900s timeout)
    with client.session_transaction() as sess:
        sess["last_active_at"] = time.time() - 1200

    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    followed = client.get("/dashboard", follow_redirects=True)
    assert b"session expired" in followed.data.lower()
