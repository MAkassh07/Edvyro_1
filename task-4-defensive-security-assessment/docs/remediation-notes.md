# Remediation Notes — SecureAuth (`task-2-secure-authentication/`)

**Remediation Date:** 2026-11-25  
**Target:** `task-2-secure-authentication/`  
**Constraint:** Preserve all routes (`/`, `/register`, `/login`, `/dashboard`, `/logout`), existing UI, SQLite schema compatibility, and all 22 Task 2 functional/security tests.

---

## 1. Summary of Changes Applied

| Finding ID | Modified File(s) | Change Summary |
| :--- | :--- | :--- |
| **FND-01** | `app/config.py`, `app/__init__.py` | Added `_parse_int()` and `build_env_config()` so `create_app()` applies `.env` settings **after** `load_dotenv()` runs; guarded invalid/empty `SESSION_LIFETIME_MINUTES`. |
| **FND-02** | `app/models.py`, `app/security.py`, `app/auth.py` | Added SQLite `revoked_sessions` table (`nonce`, `expires_at`), persisted revoked nonces on `clear_authenticated_session()` (with automatic expired-row cleanup), and enforced nonce presence + revocation checks in `validate_active_session()`. |
| **FND-03** | `requirements.txt` | Upgraded `Flask` (`3.1.0` → `3.1.3`), `Werkzeug` (`3.1.3` → `3.1.9`), `python-dotenv` (`1.0.1` → `1.2.2`), and `pytest` (`8.3.5` → `9.0.3`). |
| **FND-04** | `app/auth.py`, `app/routes.py` | Enforced `MAX_EMAIL_LENGTH` (`254`), `MAX_PASSWORD_LENGTH` (`128`), and null-byte rejection in `authenticate_account()` prior to DB lookup or `scrypt` hashing; suppressed oversized invalid email reflection in HTML templates. |
| **FND-05** | `app/security.py`, `app/auth.py`, `app/__init__.py` | Added `_sanitize_log_value()` to strip CR/LF/control characters in `log_security_event()`, replaced `email=` PII on `REGISTER_SUCCESS` with `user_id=`, and added structured logging on `400`, `403`, `413`, `500`, `SESSION_REVOKED`, and `SESSION_INVALID`. |
| **FND-06** | `app/routes.py` | Added `_no_store_response()` helper attaching `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` to `/register`, `/login`, and `/dashboard`. |
| **FND-07** | `app/config.py` | Replaced static literal `TestingConfig.SECRET_KEY` with dynamic `secrets.token_hex(32)` to remove `Bandit B105` scanner noise while keeping tests isolated. |

---

## 2. Detailed Implementation Rationale

### FND-01: `.env` Load Ordering & Safe Integer Parsing
- **Before:** `from app.config import Config` evaluated `os.environ` before `create_app()` called `load_dotenv()`.
- **After:** `create_app(test_config=None)` calls `load_dotenv()` first and, when `test_config is None`, merges `build_env_config()`. Explicit `test_config` overrides (such as `ProductionConfig` or `TestingConfig` in `pytest`) remain unaffected.

### FND-02: Server-Side Session Revocation Without Changing Architecture
- **Before:** Calling `POST /logout` cleared only the client browser's cookie; any pre-logout copy of `secureauth_session` remained valid for up to 15 minutes.
- **After:** `init_db()` creates `revoked_sessions (nonce TEXT PRIMARY KEY, expires_at REAL NOT NULL)` in the existing SQLite database. `clear_authenticated_session()` stores the logged-out `session_nonce` until its natural max lifetime and purges expired rows. `validate_active_session()` rejects missing or revoked `session_nonce` claims and logs `SESSION_REVOKED` / `SESSION_INVALID`.

### FND-04: Pre-Hash Bounds Enforcement on `/login`
- **Before:** Passwords up to `1 MB` reached Werkzeug's `scrypt` verifier, and emails > 254 characters were reflected into `login.html`.
- **After:** `authenticate_account()` rejects out-of-bounds lengths before querying SQLite or running `verify_password()`, dropping oversized login processing time from `250.6 ms` to `5.1 ms` in local tests (`verify_password_called=0`).

### FND-05: PII Minimization & Log-Injection Sanitization
- **Before:** `REGISTER_SUCCESS` logged `email=<address>`, and `log_security_event()` did not sanitize `\r`/`\n` characters.
- **After:** Registration logs record `user_id=<id>` only, and `_sanitize_log_value()` replaces control characters (`\x00-\x1f`, `\x7f`) with spaces and bounds field lengths cleanly.
