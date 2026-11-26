"""Automated tests for session lifecycle, access control, logout, and expiration."""

import time
import hashlib
import sqlite3
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


def test_pre_logout_cookie_replay_is_rejected_and_session_is_revoked(
    app, client
):
    register_user(client, "replay-session@example.com", STRONG_PASSWORD)
    login_user(client, "replay-session@example.com", STRONG_PASSWORD)
    dashboard = client.get("/dashboard")
    cookie = client.get_cookie("secureauth_session")
    assert cookie is not None

    with client.session_transaction() as session:
        nonce = session["session_nonce"]
        user_id = session["user_id"]
    expected_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()

    with app.app_context():
        db_path = app.config["DATABASE_PATH"]
    connection = sqlite3.connect(db_path)
    record = connection.execute(
        "SELECT session_id_hash, user_id, revoked_at FROM authenticated_sessions"
    ).fetchone()
    connection.close()
    assert record == (expected_hash, user_id, None)

    token = extract_csrf_token(dashboard.data)
    logout_response = client.post(
        "/logout", data={"csrf_token": token}, follow_redirects=False
    )
    assert logout_response.status_code == 302

    connection = sqlite3.connect(db_path)
    revoked_at = connection.execute(
        "SELECT revoked_at FROM authenticated_sessions WHERE session_id_hash = ?",
        (expected_hash,),
    ).fetchone()[0]
    connection.close()
    assert revoked_at is not None

    replay_client = app.test_client()
    replay_client.set_cookie("secureauth_session", cookie.value, domain="localhost")
    replay_response = replay_client.get("/dashboard", follow_redirects=False)
    assert replay_response.status_code == 302
    assert "/login" in replay_response.headers["Location"]


def test_reauthentication_creates_a_new_independent_session(client):
    register_user(client, "new-session@example.com", STRONG_PASSWORD)
    login_user(client, "new-session@example.com", STRONG_PASSWORD)
    with client.session_transaction() as session:
        old_nonce = session["session_nonce"]

    dashboard = client.get("/dashboard")
    logout_token = extract_csrf_token(dashboard.data)
    client.post("/logout", data={"csrf_token": logout_token})

    login_response = login_user(client, "new-session@example.com", STRONG_PASSWORD)
    assert login_response.status_code == 302
    with client.session_transaction() as session:
        new_nonce = session["session_nonce"]
    assert new_nonce != old_nonce
    assert client.get("/dashboard").status_code == 200
