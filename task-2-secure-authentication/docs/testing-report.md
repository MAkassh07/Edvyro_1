# Security Testing Report — SecureAuth

> **Execution Notice:** No test cases below are marked as `Pass` prior to local execution. In the build container where these files were generated, `pip` and third-party Python packages (`Flask`, `pytest`, etc.) were not installed, so runtime `pytest` execution must be run in your local virtual environment (`pytest -v`) and recorded in `evidence/test-results.md`.

---

## 1. Test Execution Command

```powershell
# Windows PowerShell (inside task-2-secure-authentication/)
.\venv\Scripts\Activate.ps1
pytest -v
```

```bash
# macOS / Linux
source venv/bin/activate
pytest -v
```

---

## 2. Automated Test Cases Matrix

| # | Test File & Function | Security Control Verified | Expected Outcome | Actual Outcome | Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **01** | `test_registration.py::test_successful_registration` | Account registration flow | Valid email + compliant password redirects (`302`) to `/login`. | *Pending local execution* | `Not run` |
| **02** | `test_registration.py::test_duplicate_email_rejection` | Duplicate account prevention | Re-registering existing email (even different case) returns `400` safely. | *Pending local execution* | `Not run` |
| **03** | `test_registration.py::test_invalid_email_rejection` | Server-side email validation | Malformed email returns `400` with validation error. | *Pending local execution* | `Not run` |
| **04** | `test_registration.py::test_weak_password_rejection` | Server-side password policy | Password under 12 chars or missing complexity returns `400`. | *Pending local execution* | `Not run` |
| **05** | `test_registration.py::test_password_confirmation_mismatch` | Password confirmation check | Mismatched confirmation password returns `400`. | *Pending local execution* | `Not run` |
| **06** | `test_registration.py::test_database_stores_password_hash_not_plaintext` | Cryptographic password storage | SQLite `password_hash` starts with `scrypt:` (or `pbkdf2:`) and never stores plaintext. | *Pending local execution* | `Not run` |
| **07** | `test_login.py::test_successful_login` | Credential authentication | Registered user redirects (`302`) to `/dashboard`. | *Pending local execution* | `Not run` |
| **08** | `test_login.py::test_failed_login_incorrect_password` | Failed auth rejection | Wrong password returns `401` with generic error message. | *Pending local execution* | `Not run` |
| **09** | `test_login.py::test_failed_login_nonexistent_email` | Unknown account rejection | Unregistered email returns `401` with generic error message. | *Pending local execution* | `Not run` |
| **10** | `test_login.py::test_generic_error_message_prevents_enumeration` | Anti-enumeration error handling | Both wrong password and unknown email return identical `"Invalid email or password."` text. | *Pending local execution* | `Not run` |
| **11** | `test_rate_limiting.py::test_login_rate_limiting_returns_429` | Brute-force throttling (`Flask-Limiter`) | 6th login attempt within 1 minute returns HTTP `429 Too Many Requests`. | *Pending local execution* | `Not run` |
| **12** | `test_rate_limiting.py::test_registration_rate_limiting_returns_429` | Registration spam throttling | 6th registration POST within 1 hour returns HTTP `429`. | *Pending local execution* | `Not run` |
| **13** | `test_sessions.py::test_dashboard_inaccessible_without_authentication` | Route access control | Unauthenticated `GET /dashboard` redirects (`302`) to `/login`. | *Pending local execution* | `Not run` |
| **14** | `test_sessions.py::test_dashboard_accessible_after_login` | Authenticated isolation | Authenticated user sees only their own email on `/dashboard`. | *Pending local execution* | `Not run` |
| **15** | `test_sessions.py::test_logout_clears_authentication_session` | Session termination | `POST /logout` clears `user_id` and `last_active_at` from session. | *Pending local execution* | `Not run` |
| **16** | `test_sessions.py::test_dashboard_inaccessible_after_logout` | Post-logout access denial | `GET /dashboard` after logout redirects (`302`) to `/login`. | *Pending local execution* | `Not run` |
| **17** | `test_sessions.py::test_session_expiration_prevents_access` | Inactivity timeout enforcement | Session idle past 15 minutes is cleared and redirected to `/login`. | *Pending local execution* | `Not run` |
| **18** | `test_security.py::test_csrf_protection_blocks_missing_token` | CSRF protection | `POST /register` or `/login` without valid `csrf_token` returns `400`. | *Pending local execution* | `Not run` |
| **19** | `test_security.py::test_password_hashes_not_exposed_in_responses` | Secret/hash non-disclosure | No `scrypt:`, `pbkdf2:`, or `password_hash` strings appear in HTML responses. | *Pending local execution* | `Not run` |
| **20** | `test_security.py::test_production_cookie_configuration` | Production cookie flags | `ProductionConfig` sets `HttpOnly=True`, `Secure=True`, `SameSite='Lax'`, `DEBUG=False`. | *Pending local execution* | `Not run` |
| **21** | `test_security.py::test_malformed_input_does_not_crash_app` | Safe malformed input handling | SQL-like and null-byte payloads return `401` safely without `500` crash. | *Pending local execution* | `Not run` |
| **22** | `test_security.py::test_security_headers_are_present` | HTTP defense headers | Responses include `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`. | *Pending local execution* | `Not run` |
