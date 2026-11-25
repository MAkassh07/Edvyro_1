# Findings Register — Defensive Security Assessment (`task-2-secure-authentication/`)

**Assessment Date:** 2026-11-25  
**Target:** SecureAuth (`task-2-secure-authentication/`)  
**Scope:** Local source-code review, isolated Flask test-client checks, `pytest`, `pip-audit`, and `bandit`

---

## 1. Confirmed Findings & Observations Summary

| ID | Title | Affected Component | Severity | Status (Baseline → Post-Fix) |
| :--- | :--- | :--- | :---: | :--- |
| **FND-01** | `.env` Environment Variables Ignored by `Config` Due to Import Ordering | `app/__init__.py`, `app/config.py` | **Medium** | Confirmed → **Fixed (Verified)** |
| **FND-02** | Pre-Logout Session Cookie Remains Valid Until Expiry (No Server Revocation) | `app/routes.py`, `app/security.py`, `app/models.py` | **Medium** | Confirmed → **Fixed (Verified)** |
| **FND-03** | Outdated Dependencies with Known Advisories (`Flask`, `Werkzeug`, `python-dotenv`, `pytest`) | `requirements.txt` | **Medium** | Confirmed → **Fixed (Verified)** |
| **FND-04** | Unbounded Login Password & Email Length Permits `scrypt` CPU Abuse & HTML Reflection | `app/auth.py`, `app/routes.py` | **Low** | Confirmed → **Fixed (Verified)** |
| **FND-05** | Security Audit Logs Leak Registration Email PII & Lack CRLF Sanitization / Error Coverage | `app/auth.py`, `app/security.py`, `app/__init__.py` | **Low** | Confirmed → **Fixed (Verified)** |
| **FND-06** | Authentication Pages (`/login`, `/register`) Omit `Cache-Control: no-store` | `app/routes.py` | **Low** | Confirmed → **Fixed (Verified)** |
| **FND-07** | `Bandit B105` Warning on `TestingConfig.SECRET_KEY` & Single-Process `memory://` Limiter | `app/config.py` | **Informational** | Observed → **Resolved (B105) / Accepted (`memory://`)** |

---

## 2. Detailed Finding Entries

### FND-01 — `.env` Environment Variables Ignored by `Config` Due to Import Ordering
- **Affected Component:** `app/__init__.py` (lines 9, 18), `app/config.py` (lines 17–41)
- **Severity:** **Medium**
- **Status:** Confirmed (Baseline `CHK-01`: FAIL)
- **Evidence:** `app/__init__.py` executes `from app.config import Config` at module import time before `create_app()` invokes `load_dotenv()`. `Config` binds `SECRET_KEY`, `FLASK_ENV`, `SESSION_COOKIE_SECURE`, `SESSION_LIFETIME_MINUTES`, and `DATABASE_PATH` when the module first imports. Additionally, setting `SESSION_LIFETIME_MINUTES=""` in `.env` triggers an unhandled `ValueError` during `int(...)` parsing.
- **Reproduction Steps:**
  1. Create a `.env` file containing `FLASK_SECRET_KEY=<32+ char test value>`, `SESSION_COOKIE_SECURE=true`, and `SESSION_LIFETIME_MINUTES=25`.
  2. Start Python in that working directory without pre-exporting those variables in the shell and run `from app import create_app; app = create_app()`.
  3. Inspect `app.config["SECRET_KEY"]`, `app.config["SESSION_COOKIE_SECURE"]`, and `app.config["SESSION_LIFETIME_MINUTES"]`.
  4. **Observed Baseline Result:** `secret_matched=False`, `SESSION_COOKIE_SECURE=False`, `SESSION_LIFETIME_MINUTES=15`.
- **Security Impact:** Production deployments relying on `.env` silently boot with a random ephemeral `SECRET_KEY` (breaking session/CSRF continuity across workers/restarts), fail to enable `SESSION_COOKIE_SECURE` and `Strict-Transport-Security`, and ignore custom session timeouts.
- **Recommended Remediation:** Load `.env` before reading configuration values inside `create_app()` (or load `Config` values dynamically inside `create_app()` via helper methods) and guard `SESSION_LIFETIME_MINUTES` integer parsing against empty/non-numeric values.

---

### FND-02 — Pre-Logout Session Cookie Remains Valid Until Expiry (No Server Revocation)
- **Affected Component:** `app/routes.py` (`logout`), `app/security.py` (`create_authenticated_session`, `validate_active_session`), `app/models.py`
- **Severity:** **Medium**
- **Status:** Confirmed (Baseline `CHK-06`: FAIL)
- **Evidence:** `POST /logout` calls `session.clear()`, which sends an expired cookie to the browser, but the server retains no revocation record for `session_nonce`.
- **Reproduction Steps:**
  1. Register and sign in as a synthetic user (`replay_test@example.com`).
  2. Capture the `secureauth_session` cookie value before logging out.
  3. Submit `POST /logout` with a valid `csrf_token`.
  4. Replay the captured pre-logout `secureauth_session` cookie in a new HTTP client request to `GET /dashboard`.
  5. **Observed Baseline Result:** `GET /dashboard` returned **HTTP 200** with the user's dashboard instead of redirecting to `/login`.
- **Security Impact:** If a session cookie is exposed on a shared terminal or intercepted before the user clicks Sign Out, the session remains usable for up to 15 minutes (`SESSION_TIMEOUT_SECONDS`) despite explicit logout.
- **Recommended Remediation:** Record each revoked `session_nonce` (and its expiry timestamp) in a `revoked_sessions` SQLite table upon `POST /logout`, prune expired entries automatically, and reject any session whose `session_nonce` is missing or revoked inside `validate_active_session()`.

---

### FND-03 — Outdated Dependencies with Known Advisories (`Flask`, `Werkzeug`, `python-dotenv`, `pytest`)
- **Affected Component:** `task-2-secure-authentication/requirements.txt`
- **Severity:** **Medium**
- **Status:** Confirmed (`pip-audit`: 8 unique advisories across 4 packages)
- **Evidence:** Running `pip-audit -r requirements.txt --no-deps` identified:
  - `Flask==3.1.0`: `CVE-2025-47278` (`PYSEC-2026-1377`, fixed in `3.1.1`) and `CVE-2026-27205` (`PYSEC-2026-2151`, missing `Vary: Cookie` on session access, fixed in `3.1.3`).
  - `Werkzeug==3.1.3`: `CVE-2025-66221`, `CVE-2026-21860`, `CVE-2026-27199`, `CVE-2026-102598` (`safe_join` Windows NTFS device-name handling, fixed in `3.1.9`).
  - `python-dotenv==1.0.1`: `CVE-2026-28684` (`set_key`/`unset_key` symlink handling, fixed in `1.2.2` — not invoked by SecureAuth).
  - `pytest==8.3.5`: `CVE-2025-71176` (`PYSEC-2026-1845`, fixed in `9.0.3` — test runner only).
- **Security Impact:** `CVE-2026-27205` weakens cache isolation for session-bearing Flask responses, and the `Werkzeug` `safe_join` advisories affect static file serving on Windows NTFS hosts.
- **Recommended Remediation:** Upgrade pinned versions in `requirements.txt` to `Flask==3.1.3`, `Werkzeug==3.1.9`, `python-dotenv==1.2.2`, and `pytest==9.0.3` (or verify compatible patched versions on PyPI) and re-run `pip-audit` + `pytest`.

---

### FND-04 — Unbounded Login Password & Email Length Permits `scrypt` CPU Abuse & HTML Reflection
- **Affected Component:** `app/auth.py` (`authenticate_account`), `app/routes.py` (`login`)
- **Severity:** **Low**
- **Status:** Confirmed (Baseline `CHK-07`: FAIL)
- **Evidence:** `authenticate_account()` checks `if not email or not raw_password` but never checks `MAX_EMAIL_LENGTH` (`254`) or `MAX_PASSWORD_LENGTH` (`128`) before calling `get_user_for_auth(email)` and `verify_password()` (`scrypt`). Meanwhile, `routes.py:84` reflects arbitrary-length `submitted_email` into `login.html`.
- **Reproduction Steps:**
  1. Fetch `/login` CSRF token and submit `POST /login` with a 312-character email and a 50,000-character password.
  2. **Observed Baseline Result:** `verify_password` executed on the 50 KB password (`verify_password_called=1`, `250.6 ms`) and the 312-character email was reflected inside `login.html` (`oversized_email_reflected=True`).
- **Security Impact:** Allows unnecessary per-request `scrypt` CPU amplification within the 1 MB request cap and oversized input reflection in HTML responses.
- **Recommended Remediation:** Reject `len(email) > MAX_EMAIL_LENGTH` or `len(raw_password) > MAX_PASSWORD_LENGTH` immediately in `authenticate_account()` with `GENERIC_LOGIN_ERROR` prior to database lookup or `verify_password()`, and truncate/omit oversized invalid emails from template reflection.

---

### FND-05 — Security Audit Logs Leak Registration Email PII & Lack CRLF Sanitization / Error Coverage
- **Affected Component:** `app/auth.py` (line 52), `app/security.py` (lines 144–147), `app/__init__.py` (lines 61–126)
- **Severity:** **Low**
- **Status:** Confirmed (Baseline `CHK-08`: FAIL)
- **Evidence:**
  - `register_account()` logs `f"email={normalized_email}"` on `REGISTER_SUCCESS`, whereas `LOGIN_SUCCESS`/`LOGOUT` log `user_id=<id>`.
  - `log_security_event()` passes unescaped `ip_address` and `detail` (including `request.path` on `429`) directly to `security_logger.info(...)`.
  - Error handlers `400`, `403`, `413`, `500`, and `validate_active_session()` (`reason == "invalid"`) emit no security audit log.
- **Reproduction Steps:**
  1. Register `pii_probe@example.com` and inspect `secureauth.security` log output.
  2. Call `log_security_event("RATE_LIMIT_EXCEEDED", "127.0.0.1\r\nFAKE", "/login\nFAKE_EVENT=1")`.
  3. **Observed Baseline Result:** `detail=email=pii_probe@example.com` logged (`pii_leaked=True`) and `FAKE_EVENT=1` appeared on its own forged line (`crlf_injected=True`).
- **Security Impact:** Plaintext email PII accumulates in operational logs and multi-line log injection can confuse SIEM/log parsers.
- **Recommended Remediation:** Log `user_id={user_id}` on `REGISTER_SUCCESS`, sanitize `\r`, `\n`, `\t`, and non-printable control characters in `log_security_event()`, and log `BAD_REQUEST`, `FORBIDDEN`, `PAYLOAD_TOO_LARGE`, `INTERNAL_ERROR`, and `SESSION_INVALID` events safely.

---

### FND-06 — Authentication Pages (`/login`, `/register`) Omit `Cache-Control: no-store`
- **Affected Component:** `app/routes.py` (`register`, `login`)
- **Severity:** **Low**
- **Status:** Confirmed (Baseline `CHK-09`: FAIL)
- **Evidence:** `/dashboard` sets `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`, whereas `GET`/`POST` responses on `/login` and `/register` return an empty `Cache-Control` header (`''`).
- **Security Impact:** Shared browsers or intermediate caches could retain authentication pages containing per-session CSRF tokens or recently typed email addresses.
- **Recommended Remediation:** Attach `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` on `/login` and `/register` responses.

---

### FND-07 — `Bandit B105` Static Warning & In-Memory Rate-Limiter Scope
- **Affected Component:** `app/config.py` (lines 40, 61)
- **Severity:** **Informational**
- **Status:** Observed (`bandit` exit 1: 1 Low/Medium-confidence finding)
- **Evidence:** `bandit` flagged `TestingConfig.SECRET_KEY = "test-only-ephemeral-signing-key-not-for-production"` (`B105`). No actual production secret is hardcoded. Separately, `RATELIMIT_STORAGE_URI=memory://` resets on process restart (documented single-process local limitation).
- **Recommended Remediation:** Generate `TestingConfig.SECRET_KEY` dynamically with `secrets.token_hex(32)` (or annotate cleanly) so `bandit` reports 0 warnings, while retaining Redis guidance for multi-worker production.

---

## 3. Verified Passing Security Controls (Baseline)

| Control | Evidence |
| :--- | :--- |
| **Password Hashing (`scrypt`)** | `app/security.py:25-39`; SQLite stores salted `scrypt:` hashes (`CHK-04`: PASS). |
| **SQL Injection Resistance** | Parameterized `?` placeholders across all queries in `app/models.py`; malformed SQL payloads handled safely (`test_malformed_input_does_not_crash_app`: PASS). |
| **CSRF Enforcement** | `Flask-WTF CSRFProtect` active globally; POST without `csrf_token` returns HTTP `400` (`CHK-05`: PASS). |
| **Brute-Force Rate Limiting** | `5/minute` on `POST /login` and `5/hour` on `POST /register` via `request.remote_addr`, returning `429` (`test_rate_limiting.py`: PASS). |
| **Anti-Enumeration Login Errors** | Unknown emails execute `get_dummy_hash()` check and return identical `"Invalid email or password."` (`401`) (`CHK-04`: PASS). |
| **Cookie Attributes & Security Headers** | `HttpOnly=True`, `SameSite=Lax`, `ProductionConfig.SESSION_COOKIE_SECURE=True`, `CSP`, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` (`CHK-02`, `CHK-03`: PASS). |
| **Template XSS Protection** | Jinja2 autoescaping enabled on all `.html` templates; zero `|safe` or raw `Markup()` calls. |
