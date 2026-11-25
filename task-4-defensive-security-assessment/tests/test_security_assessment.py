"""Automated defensive assessment verification tests for Task 4."""

import io
import logging
import sys
from pathlib import Path

TASK4_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = TASK4_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import security_assessment as sa  # noqa: E402


def test_dotenv_configuration_loading_passes():
    """FND-01: .env overrides FLASK_SECRET_KEY, SESSION_COOKIE_SECURE, and SESSION_LIFETIME_MINUTES."""
    res = sa.check_dotenv_import_ordering()
    assert res.passed, res.evidence


def test_core_baseline_security_controls_pass():
    """Core controls (cookie flags, headers, scrypt hashing, generic login error, CSRF) remain intact."""
    results = sa.check_baseline_security_controls()
    for item in results:
        assert item.passed, f"{item.check_id}: {item.evidence}"


def test_pre_logout_cookie_replay_is_blocked():
    """FND-02: Replaying a captured pre-logout session cookie after POST /logout is denied."""
    res = sa.check_session_replay_after_logout()
    assert res.passed, res.evidence


def test_oversized_login_payloads_rejected_before_hashing():
    """FND-04: Login rejects >128-char passwords before scrypt and avoids >254-char email reflection."""
    res = sa.check_oversized_login_input_handling()
    assert res.passed, res.evidence


def test_security_logs_omit_pii_and_neutralize_crlf():
    """FND-05: Security audit logs emit user_id instead of email PII and strip CRLF newlines."""
    res = sa.check_logging_pii_and_injection()
    assert res.passed, res.evidence


def test_auth_pages_prevent_caching():
    """FND-06: Sensitive authentication forms (/login, /register) send Cache-Control: no-store."""
    res = sa.check_auth_pages_cache_control()
    assert res.passed, res.evidence


def test_csrf_rejection_and_invalid_session_are_logged(tmp_path):
    """FND-05: Missing CSRF token and forged/tampered session claims emit structured security logs."""
    app = sa._create_isolated_app(str(tmp_path))
    client = app.test_client()

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    sec_logger = logging.getLogger("secureauth.security")
    sec_logger.addHandler(handler)
    sec_logger.setLevel(logging.INFO)
    try:
        resp = client.post("/login", data={"email": "test@example.com", "password": sa.TEST_PW})
        assert resp.status_code == 400

        with client.session_transaction() as sess:
            sess["user_id"] = 999999
            sess["last_active_at"] = 9999999999.0
        dash = client.get("/dashboard", follow_redirects=False)
        assert dash.status_code == 302
    finally:
        sec_logger.removeHandler(handler)

    output = stream.getvalue()
    assert "event=BAD_REQUEST" in output or "event=CSRF_REJECTED" in output
    assert "event=SESSION_INVALID" in output
