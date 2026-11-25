# Implementation Details — SecureAuth

This document describes how SecureAuth implements the defensive controls planned in Task 1 across its modular Python Flask codebase.

---

## 1. Architecture & Module Responsibilities

| File | Responsibility |
| :--- | :--- |
| `app/__init__.py` | Application factory (`create_app`), environment checks, security headers (`CSP`, `nosniff`, `X-Frame-Options`, `HSTS`), and safe error handlers (`400`, `403`, `404`, `413`, `429`, `500`). |
| `app/config.py` | Environment-driven `Config`, `ProductionConfig`, and `TestingConfig` classes managing `SECRET_KEY`, cookie attributes, `MAX_CONTENT_LENGTH`, and timeout windows. |
| `app/extensions.py` | Shared instances of `CSRFProtect` and `Limiter` initialized cleanly without circular imports. |
| `app/models.py` | Request-scoped SQLite connection lifecycle and parameterized queries for user creation, authentication lookup, and safe public profile lookup (excluding `password_hash`). |
| `app/security.py` | Werkzeug `scrypt` password hashing, server-side email/password validation, session creation/rotation/expiration checks, and redacted security event logging. |
| `app/auth.py` | `register_account`, `authenticate_account` (with dummy-hash timing equalization and generic error messages), and the `@login_required` route decorator. |
| `app/routes.py` | Blueprint endpoints (`/` home, `/register`, `/login`, `/dashboard`, `/logout`) with `POST`-only rate limiting and `Cache-Control: no-store` on protected views. |

---

## 2. Database Schema (`SQLite`)

Initialized automatically on startup via `app/models.py`:

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
```

- **`email`**: Normalized (`strip().lower()`) before lookup and insertion, enforced unique by SQLite.
- **`password_hash`**: Stores the full Werkzeug salted hash string (`scrypt:...`).
- **Query isolation**: `get_public_user_by_id()` selects only `(id, email, created_at)`, ensuring `password_hash` is never passed to dashboard templates.

---

## 3. Session Lifecycle Mechanics

1. **Login**: `create_authenticated_session()` calls `session.clear()`, sets `session.permanent = True`, and writes `user_id`, `user_email`, `session_nonce`, `issued_at`, and `last_active_at`.
2. **Protected Request (`/dashboard`)**: `@login_required` calls `validate_active_session()`, which verifies `user_id`, confirms `(now - last_active_at) <= SESSION_TIMEOUT_SECONDS` (900 seconds by default), checks the user record exists in SQLite, and slides `last_active_at` forward.
3. **Expiration**: If inactive beyond the timeout, `session.clear()` runs and the user is redirected to `/login` with an expiration message.
4. **Logout**: `POST /logout` requires a valid CSRF token, logs the `LOGOUT` event, calls `session.clear()`, and redirects to `/login`.

---

## 4. Security Headers Applied (`@app.after_request`)

- `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (enabled automatically when `SESSION_COOKIE_SECURE=True`)
- `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` on `/dashboard`
