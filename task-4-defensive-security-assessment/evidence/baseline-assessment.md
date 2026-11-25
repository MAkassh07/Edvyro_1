# Baseline Security Assessment — SecureAuth (`task-2-secure-authentication/`)

**Assessment Date (UTC):** 2026-11-25  
**Target:** `task-2-secure-authentication/` (pre-remediation baseline)  
**Assessment Type:** Authorized white-box source review + isolated `pytest` / Flask test client verification + `pip-audit` + `bandit`

---

## 1. Executive Summary of Baseline Posture

Prior to remediation, SecureAuth already implements strong foundational controls: salted `scrypt` password hashing, parameterized `sqlite3` queries, `CSRFProtect`, `Flask-Limiter` (`5/minute` login, `5/hour` registration), generic login errors (`"Invalid email or password."`), dummy-hash timing equalization, `HttpOnly` + `SameSite=Lax` cookies, and defensive HTTP headers (`CSP`, `nosniff`, `X-Frame-Options: DENY`). All **22/22** existing Task 2 `pytest` tests passed at baseline.

However, targeted assessment checks (`src/security_assessment.py --mode baseline` — **4/9 passed, 5 failed**), `pip-audit`, and `bandit` identified **6 actionable findings** (**3 Medium**, **3 Low**) and **1 Informational** item that were not covered by the original 22 tests.

---

## 2. Domain-by-Domain Baseline Inspection

### A. Configuration Security
- **Observed Passing Controls:**
  - `DEBUG` defaults to `False` in `Config` (`app/config.py:18`) and is locked to `False` in `ProductionConfig` (`app/config.py:48`).
  - `run.py` binds to `127.0.0.1:5000` with `debug=False` by default (`run.py:9-11`).
  - `SESSION_COOKIE_HTTPONLY = True` and `SESSION_COOKIE_SAMESITE = "Lax"` are enforced (`app/config.py:26-27`).
  - Custom error handlers for `400`, `403`, `404`, `413`, `429`, and `500` suppress Python tracebacks (`app/__init__.py:61-126`).
- **Confirmed Gaps:**
  - **FND-01 (Medium):** `app/__init__.py:9` imports `Config` before `create_app()` calls `load_dotenv()` (`app/__init__.py:18`). Because `Config` reads `os.environ` at class-definition time (`app/config.py:17-41`), values in `.env` (`FLASK_SECRET_KEY`, `SESSION_COOKIE_SECURE`, `SESSION_LIFETIME_MINUTES`) are silently ignored on startup (`CHK-01` failed: `secret_matched=False`, `SESSION_COOKIE_SECURE=False`). Additionally, empty `SESSION_LIFETIME_MINUTES=""` causes an unhandled `ValueError` at import time.
  - **FND-06 (Low):** `/login` and `/register` omit `Cache-Control: no-store` headers (`CHK-09` failed), unlike `/dashboard`.

### B. Authentication Security
- **Observed Passing Controls:**
  - Passwords hashed with Werkzeug `scrypt` (constant-time `check_password_hash`), with dummy-hash equalization on unknown emails (`app/security.py:25-47`, `app/auth.py:67-70`).
  - Identical HTTP `401` `"Invalid email or password."` response for bad passwords and unknown emails (`CHK-04` passed).
  - `Flask-Limiter` enforces `5/minute` on `POST /login` and `5/hour` on `POST /register` using `request.remote_addr` (`app/routes.py:34,64`), preventing `X-Forwarded-For` header spoofing in standalone mode.
  - `CSRFProtect` rejects POST requests missing `csrf_token` with HTTP `400` (`CHK-05` passed).
  - `create_authenticated_session()` calls `session.clear()` before populating claims, mitigating session fixation (`app/security.py:99`).
- **Confirmed Gaps:**
  - **FND-02 (Medium):** Because Flask sessions use self-contained signed cookies without server-side revocation state, replaying a pre-logout `secureauth_session` cookie after `POST /logout` still grants HTTP `200` access to `/dashboard` until the 15-minute `last_active_at` window expires (`CHK-06` failed).

### C. Input Validation
- **Observed Passing Controls:**
  - `/register` enforces server-side email normalization, `<= 254` length, null/CRLF rejection, format regex, password complexity (`12–128` chars, upper/lower/digit/special), and confirmation matching (`app/security.py:57-94`).
  - All SQLite queries in `app/models.py` use parameterized `?` placeholders; Jinja2 HTML templates autoescape all variables without `|safe`.
  - `MAX_CONTENT_LENGTH` caps total HTTP request bodies at `1 MB` (`app/config.py:37`).
- **Confirmed Gaps:**
  - **FND-04 (Low):** `authenticate_account()` (`app/auth.py:56-75`) does not enforce `MAX_PASSWORD_LENGTH` (`128`) or `MAX_EMAIL_LENGTH` (`254`) before invoking `verify_password()` (`scrypt`) and reflecting `submitted_email` into `login.html` (`CHK-07` failed: 50,000-char password ran `scrypt` for `250.6 ms` and 312-char email was reflected in HTML).

### D. Dependency Security
- **Observed Evidence (`evidence/dependency-audit.txt`):**
  - **FND-03 (Medium):** `pip-audit` against pinned `requirements.txt` identified known security advisories in `Flask==3.1.0` (fixed in `3.1.3`), `Werkzeug==3.1.3` (fixed in `3.1.9`), `python-dotenv==1.0.1` (fixed in `1.2.2`), and `pytest==8.3.5` (dev/test dependency, fixed in `9.0.3`). No advisories were flagged for `Flask-Limiter==3.10.1` or `Flask-WTF==1.2.2`.
  - **FND-07 (Informational):** `bandit` scanned 528 lines of code and reported 0 High/Medium issues and 1 Low/Medium-confidence `B105` notice on `TestingConfig.SECRET_KEY` (`app/config.py:61`).

### E. Logging and Error Handling
- **Observed Passing Controls:**
  - Plaintext passwords, password hashes, and `session_nonce` values are never logged or rendered (`test_password_hashes_not_exposed_in_responses` passed).
- **Confirmed Gaps:**
  - **FND-05 (Low):** `REGISTER_SUCCESS` logs raw `email=<addr>` PII (`app/auth.py:52`) instead of `user_id`, `log_security_event()` does not strip `\r`/`\n` control characters (allowing forged multi-line log entries in `CHK-08`), and `400`/`403`/`413`/`500` or invalid-session events are not logged.
