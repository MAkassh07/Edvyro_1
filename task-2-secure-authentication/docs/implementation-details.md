# Implementation Details — SecureAuth

This document describes how SecureAuth implements its Flask and SQLite authentication controls.

## 1. Architecture

| File | Responsibility |
|---|---|
| `app/__init__.py` | Application factory, dotenv loading, runtime configuration, HTTP security headers, and safe error handlers. |
| `app/config.py` | Environment parsing and development, production, and testing configurations. |
| `app/extensions.py` | Shared CSRF protection and rate-limiter instances. |
| `app/models.py` | SQLite schema, request-scoped connections, parameterized user queries, and server-side authenticated-session records. |
| `app/security.py` | Password hashing and verification, session lifecycle checks, input validation helpers, and sanitized security-event logging. |
| `app/auth.py` | Registration/login logic, credential bounds, generic authentication failures, and the login-required decorator. |
| `app/routes.py` | Home, registration, login, dashboard, and logout routes; rate limiting and no-store response headers. |

## 2. Runtime Configuration

`create_app()` loads `.env` before it reads the runtime environment. `build_env_config()` validates booleans and numeric session lifetime values rather than silently accepting malformed settings. The session lifetime must be from 1 to 1440 minutes.

Production mode rejects enabled debug mode, insecure session cookies, a signing key shorter than 32 characters, and a missing signing key. The default application factory reads `FLASK_SECRET_KEY`; explicitly supplied production configuration must also provide a key. Test configuration creates a random signing key.

## 3. Database Schema

The application initializes its tables on startup:

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authenticated_sessions (
    session_id_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked_at REAL
);
```

User queries use SQLite placeholders. Public profile lookup selects only safe metadata and never returns `password_hash`. The session table stores the SHA-256 hash of a random nonce, not the client-side nonce itself.

## 4. Session Lifecycle

1. **Login:** Existing session state is revoked/cleared. The application generates a random nonce, stores its hash with the user ID, issue time, and absolute expiry, then places the nonce and session claims in Flask's signed cookie.
2. **Protected request:** Session claims are checked for valid types and timestamps, idle timeout, and absolute expiry. The nonce hash must match an active database record for the same user. The user record is then loaded and the idle activity time updated.
3. **Logout or invalidation:** The matching database row is marked revoked before the client session is cleared. Copied pre-logout cookies are rejected on subsequent requests.
4. **Cleanup:** Expired session records are removed during database initialization and session operations.

The absolute session lifetime is 48 times the configured inactivity timeout. The cookie remains signed, not encrypted; do not place secrets in its claims.

## 5. Authentication and Input Controls

- Passwords use Werkzeug's salted `scrypt` hashing where supported, with the configured PBKDF2 fallback.
- Registration and login validate input on the server. Login checks type, maximum email/password length, and null bytes before database lookup or password verification.
- Unknown accounts still trigger dummy-hash verification and return the same generic login failure as incorrect passwords.
- SQLite queries are parameterized; rendered templates use Jinja autoescaping.
- Flask-WTF enforces CSRF on state-changing forms. Flask-Limiter bounds login and registration attempts.

## 6. Logging and Response Headers

Security-event fields are length-bounded and ASCII control characters are collapsed to spaces. Registration success records a user ID rather than an email. Error handlers and invalid-session paths emit structured events without logging passwords or session tokens.

All responses receive the configured content-security, content-type, framing, and referrer-policy headers. HTTPS production mode adds HSTS. Login, registration, and dashboard responses include `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache`.

## 7. Deployment Notes

The local `memory://` limiter is process-local and is suitable only for development or a single process. Configure a shared backend such as Redis before using multiple workers. Production deployments must terminate TLS and set a strong `FLASK_SECRET_KEY` and secure cookies.
