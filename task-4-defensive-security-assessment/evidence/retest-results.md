# Before-and-After Retesting Comparison — Task 4

**Retest Date (UTC):** 2026-11-25T16:34:40Z  
**Target:** `task-2-secure-authentication/` (SecureAuth)  
**Overall Suite Result:** `22/22` Task 2 tests PASSED · `7/7` Task 4 assessment tests PASSED · `9/9` harness checks PASSED · `0` `pip-audit` advisories · `0` `bandit` warnings

---

## 1. Before-and-After Finding Verification Matrix

| Finding | Original Test Result | Remediation Performed | Retest Procedure | Actual Retest Result | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **FND-01:** `.env` ignored at `Config` import time | `[FAIL] CHK-01`: `secret_matched=False`, `SESSION_COOKIE_SECURE=False`, `SESSION_LIFETIME_MINUTES=15` | Added `build_env_config()` and `_parse_int()` in `app/config.py`; applied in `create_app()` after `load_dotenv()`. | Run `CHK-01` & `test_dotenv_configuration_loading_passes` in clean `.env` subprocess. | `[PASS] CHK-01`: `secret_matched=True`, `SESSION_COOKIE_SECURE=True`, `SESSION_LIFETIME_MINUTES=25` | **Pass (Fixed)** |
| **FND-02:** Pre-logout session cookie replayable until timeout | `[FAIL] CHK-06`: Replay of pre-logout cookie to `GET /dashboard` returned HTTP `200`. | Added `revoked_sessions` table in `app/models.py`; revoked `session_nonce` on logout and checked revocation in `validate_active_session()`. | Run `CHK-06` & `test_pre_logout_cookie_replay_is_blocked` by replaying pre-logout cookie after `POST /logout`. | `[PASS] CHK-06`: Replay returned HTTP `302` redirect to `/login` and logged `SESSION_REVOKED`. | **Pass (Fixed)** |
| **FND-03:** Outdated `Flask`, `Werkzeug`, `python-dotenv`, `pytest` advisories | `pip-audit`: 8 unique advisories across 4 packages (`exit=1`). | Updated `requirements.txt` to `Flask==3.1.3`, `Werkzeug==3.1.9`, `python-dotenv==1.2.2`, `pytest==9.0.3` and upgraded environment. | Re-run `pip-audit -r requirements.txt --no-deps`. | `No known vulnerabilities found` (`exit=0`). | **Pass (Fixed)** |
| **FND-04:** Unbounded `/login` password/email length | `[FAIL] CHK-07`: `verify_password_called=1` (`250.6 ms`), `oversized_email_reflected=True`. | Enforced `MAX_EMAIL_LENGTH` (`254`) and `MAX_PASSWORD_LENGTH` (`128`) in `authenticate_account()` before DB/hashing; suppressed oversized reflection in `routes.py`. | Run `CHK-07` & `test_oversized_login_payloads_rejected_before_hashing` with 50 KB password & 312-char email. | `[PASS] CHK-07`: `status=401`, `verify_password_called=0`, `oversized_email_reflected=False`, `elapsed_ms=5.1`. | **Pass (Fixed)** |
| **FND-05:** Email PII in registration log & CRLF log injection | `[FAIL] CHK-08`: `pii_leaked=True`, `crlf_injected=True` (`FAKE_EVENT=1` new line). | Logged `user_id` instead of `email` on `REGISTER_SUCCESS`; added `_sanitize_log_value()` in `app/security.py`; added error/invalid-session logging. | Run `CHK-08`, `test_security_logs_omit_pii_and_neutralize_crlf`, and `test_csrf_rejection_and_invalid_session_are_logged`. | `[PASS] CHK-08`: `pii_leaked=False`, `crlf_injected=False`, `BAD_REQUEST` & `SESSION_INVALID` logged cleanly. | **Pass (Fixed)** |
| **FND-06:** `/login` & `/register` omit `Cache-Control: no-store` | `[FAIL] CHK-09`: `Cache-Control=''` on `/login` and `/register`. | Added `_no_store_response()` helper in `app/routes.py` applying `no-store` headers across `/login`, `/register`, and `/dashboard`. | Run `CHK-09` & `test_auth_pages_prevent_caching`. | `[PASS] CHK-09`: Both routes return `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`. | **Pass (Fixed)** |
| **FND-07:** `Bandit B105` on `TestingConfig.SECRET_KEY` | `bandit`: 1 Low warning on `app/config.py:61` (`exit=1`). | Replaced literal string with `secrets.token_hex(32)` in `TestingConfig`. | Re-run `bandit -r app run.py`. | `No issues identified` across 648 lines (`exit=0`). | **Pass (Resolved)** |

---

## 2. Functional Regression Check

Re-running Task 2's full 22-test suite (`tests/test_registration.py`, `tests/test_login.py`, `tests/test_rate_limiting.py`, `tests/test_sessions.py`, `tests/test_security.py`) after all remediations yielded **22 passed in 10.19s** with **0 failures** and **0 errors**, confirming existing registration, login, rate-limiting, session-expiration, and logout behaviors remain fully intact.
