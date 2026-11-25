# Secure Authentication Lab — SecureAuth

**Track:** Cyber Security · **Task:** TASK-2 · **Level:** Beginner-Friendly<br>
**Portfolio Repository:** [https://github.com/MAkassh07/Edvyro_1](https://github.com/MAkassh07/Edvyro_1)

---

## 1. Project Overview

**SecureAuth** is a functional Python Flask and SQLite authentication web application built as Task 2 of the Cyber Security internship portfolio. Extending the threats and hardening controls identified in **Task 1 (Threat Model and Secure Configuration)**, this project implements secure credential storage, server-side validation, rate limiting, CSRF defense, generic error handling, hardened cookie sessions, and automated `pytest` security tests.

---

## 2. Objectives

- Store user passwords exclusively using salted, memory-hard cryptographic hashing (`scrypt`).
- Validate and normalize all inputs on the server using parameterized SQLite queries.
- Prevent brute-force guessing with `Flask-Limiter` rate limits (`429 Too Many Requests`).
- Prevent account enumeration using generic login errors and constant-time dummy verification.
- Secure cookie sessions with `HttpOnly`, `SameSite=Lax`, configurable `Secure`, session rotation, and 15-minute inactivity expiration.
- Protect all state-changing forms against CSRF using `Flask-WTF`.
- Verify every security control with deterministic automated `pytest` tests.

---

## 3. Features

- **Home Page (`/`):** Project introduction, security overview, and sign-in/registration navigation.
- **Registration (`/register`):** Email + password + confirm password form, live UX policy hints, duplicate account prevention, server-side policy enforcement, and `scrypt` hashing.
- **Login (`/login`):** Rate-limited authentication (`5/minute`), generic error handling (`"Invalid email or password."`), and session regeneration.
- **Protected Dashboard (`/dashboard`):** Accessible only with a valid active session; displays solely the signed-in user's email, ID, creation timestamp, and session protections (`Cache-Control: no-store`).
- **Logout (`POST /logout`):** CSRF-protected session termination clearing all session cookies/claims and redirecting to `/login`.

---

## 4. Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Backend** | Python 3, Flask 3.1 |
| **Security & Sessions** | Werkzeug (`scrypt`), Flask-Limiter, Flask-WTF (`CSRFProtect`), Flask signed cookie sessions |
| **Database** | SQLite (parameterized `sqlite3` queries) |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript (password visibility toggle & form state) |
| **Testing** | `pytest`, Flask test client |

---

## 5. Architecture Overview

```text
Browser (HTML5/CSS3/JS + CSRF Token + Signed Session Cookie)
   │
   ▼ HTTP / HTTPS
Flask Application Factory (app/__init__.py)
   ├── Security Headers (CSP, X-Frame-Options, nosniff, HSTS)
   ├── Flask-WTF CSRFProtect & Flask-Limiter
   ├── Blueprint Routes (app/routes.py)
   ├── Auth Logic & @login_required (app/auth.py)
   ├── Hashing, Validation & Session Expiry (app/security.py)
   └── Parameterized SQLite Queries (app/models.py ──► instance/secureauth.db)
```

---

## 6. Authentication Workflow

1. **Registration:** User submits `email`, `password`, and `confirm_password` with a valid `csrf_token`. The server normalizes the email, enforces the 12–128 character complexity policy, verifies uniqueness, hashes the password via Werkzeug `scrypt`, and stores `(email, password_hash, created_at)` in SQLite.
2. **Login:** User submits credentials to `POST /login` (throttled at 5 attempts/minute/IP). If the account is missing or the password fails, the server returns HTTP `401` with `"Invalid email or password."`. On success, `session.clear()` replaces any prior session state and creates a fresh 15-minute permanent session.
3. **Dashboard Access:** `@login_required` verifies the active session and inactivity timestamp (`last_active_at`), redirecting unauthenticated or expired sessions back to `/login`.
4. **Logout:** `POST /logout` validates the CSRF token, logs the event, clears the session, and redirects to `/login`.

---

## 7. Password Security Implementation

- Passwords are hashed using `werkzeug.security.generate_password_hash(password, method="scrypt")` (with `pbkdf2:sha256:600000` fallback if OpenSSL lacks `scrypt`).
- Plaintext passwords are never stored, returned in responses, or logged.
- Policy enforced server-side: **12–128 characters**, uppercase, lowercase, digit, and special character.
- Detailed rationale on why hashing is required instead of encryption or plaintext is documented in [`docs/authentication-security-note.md`](docs/authentication-security-note.md).

---

## 8. Input Validation

- **Email:** Trimmed, lowercased, checked for `<= 254` chars, format regex, and rejection of control characters.
- **Password:** Checked for string type, absence of null bytes, 12–128 length, complexity rules, and equality with `confirm_password`.
- **SQL Safety:** Every database read/write uses `?` placeholders in `sqlite3` (`app/models.py`).
- **Payload Cap:** `MAX_CONTENT_LENGTH` is capped at 1 MB (`413` safe handler).

---

## 9. Rate Limiting

Configured via `Flask-Limiter` on `POST` authentication routes:

- **`POST /login`:** `5 per minute` per IP address.
- **`POST /register`:** `5 per hour` per IP address.
- Exceeding limits returns **HTTP 429** with `"Too many attempts. Please wait a moment before trying again."`
- Uses `memory://` in local development; configure `RATELIMIT_STORAGE_URI=redis://...` in multi-worker production.

---

## 10. Secure Sessions

- `SESSION_COOKIE_HTTPONLY = True` (blocks `document.cookie` JS access)
- `SESSION_COOKIE_SAMESITE = 'Lax'` (defends against cross-site `POST` requests)
- `SESSION_COOKIE_SECURE` controlled via environment variable (`false` for local `http://127.0.0.1`, `true` for HTTPS production)
- 15-minute inactivity expiration enforced both at cookie level (`PERMANENT_SESSION_LIFETIME`) and server timestamp level (`last_active_at`).

---

## 11. Generic Authentication Errors

Both invalid passwords and non-existent emails return HTTP `401` with **`"Invalid email or password."`**. Unknown-account lookups also execute a dummy hash check (`get_dummy_hash()`) to equalize response timing and prevent account enumeration.

---

## 12. Database Structure & Initialization

SQLite table `users` in `instance/secureauth.db`:

| Column | Type | Constraints |
| :--- | :--- | :--- |
| `id` | `INTEGER` | `PRIMARY KEY AUTOINCREMENT` |
| `email` | `TEXT` | `NOT NULL UNIQUE` |
| `password_hash` | `TEXT` | `NOT NULL` |
| `created_at` | `TEXT` | `NOT NULL` (UTC ISO-8601) |

The schema initializes automatically when `create_app()` runs (`app/models.py:init_db()`). You can also initialize it explicitly without starting the server:

```powershell
python -c "from app import create_app; create_app()"
```

---

## 13. Setup & Installation Guide (Windows PowerShell)

Follow these steps inside `task-2-secure-authentication/`:

```powershell
# 1. Create a virtual environment
python -m venv venv

# 2. Activate the virtual environment (Windows PowerShell)
venv\Scripts\Activate.ps1

# 3. Install pinned dependencies
pip install -r requirements.txt

# 4. Create your local .env file from the template
Copy-Item .env.example .env
```

Generate a random secret key and paste it into `.env` as `FLASK_SECRET_KEY=...`:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

*(macOS / Linux equivalents: `python3 -m venv venv`, `source venv/bin/activate`, `cp .env.example .env`.)*

---

## 14. Running the Application

```powershell
python run.py
```

Open **`http://127.0.0.1:5000`** in your browser.

---

## 15. Running Automated Security Tests

Execute the full `pytest` suite (`22` deterministic tests covering registration, login, rate limiting, sessions, CSRF, cookie config, and malformed input):

```powershell
pytest -v
```

---

## 16. Screenshots / UI Overview

*(Add local screenshots after running `python run.py` in your environment)*

- `[Screenshot Placeholder: Home Page — /]`
- `[Screenshot Placeholder: Registration Page with Password Policy — /register]`
- `[Screenshot Placeholder: Login Page with Generic Error — /login]`
- `[Screenshot Placeholder: Protected User Dashboard — /dashboard]`

---

## 17. Security Testing Results

All test descriptions and expected outcomes are cataloged in [`docs/testing-report.md`](docs/testing-report.md), and execution output capture instructions live in [`evidence/test-results.md`](evidence/test-results.md). Tests are marked pending until run locally via `pytest -v`.

---

## 18. Project Limitations

- Uses in-memory `Flask-Limiter` storage by default (single-process dev only; production requires Redis).
- Uses single-factor email/password authentication (no MFA or email verification in Task 2 scope).
- Uses Flask client-side signed cookies rather than a server-side session revocation store.
- Local development runs over HTTP (`SESSION_COOKIE_SECURE=false`); production requires HTTPS behind a reverse proxy with `SESSION_COOKIE_SECURE=true`.

---

## 19. References

- **OWASP Authentication Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **OWASP Password Storage Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **OWASP Session Management Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- **OWASP Input Validation Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- **OWASP CSRF Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- **Flask Official Documentation (Security):** https://flask.palletsprojects.com/en/stable/security/
- **Werkzeug Official Documentation (Password Hashing):** https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security
- **Flask-Limiter Official Documentation:** https://flask-limiter.readthedocs.io/en/stable/
