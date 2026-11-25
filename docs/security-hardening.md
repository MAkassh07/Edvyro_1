# Prioritized Security Hardening Plan — SecureVault

This hardening plan translates the findings from the [Threat Model & STRIDE Analysis](threat-model.md) and [Risk Register](risk-register.md) into concrete, phased defensive controls for SecureVault (HTML/CSS/JS + Python Flask + SQLite + External Email Service).

Every recommendation details:
1. **What needs to be changed**
2. **Why it matters**
3. **How to implement it**
4. **How to verify it**

---

## Phase 1 — Critical Fixes (Immediate Priority)

Phase 1 eliminates Critical and High-risk architectural exposures that could lead to full database compromise, unauthorized note access, or account takeover.

### 1.1 Strong Password Hashing (Argon2id / bcrypt)
*Mitigates: `RISK-04` (Spoofing / Information Disclosure)*

1. **What needs to be changed:** Replace any plaintext, MD5, SHA-1, or unsalted SHA-256 password storage with a modern memory-hard adaptive hashing algorithm (`Argon2id` preferred, or `bcrypt`).
2. **Why it matters:** If the SQLite file (`securevault.db`) is ever exposed via a backup leak or host compromise, fast hashes can be cracked at billions of guesses per second on consumer GPUs. Argon2id forces high memory and CPU cost per guess, making offline brute-forcing impractical.
3. **How to implement it:**
   ```python
   from argon2 import PasswordHasher
   from argon2.exceptions import VerifyMismatchError

   ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

   # Registration / Password Change
   password_hash = ph.hash(submitted_password)

   # Login Verification
   try:
       ph.verify(stored_hash, submitted_password)
   except VerifyMismatchError:
       return {"error": "Invalid credentials"}, 401
   ```
4. **How to verify it:** Register a test account and inspect the `users` table in SQLite; confirm the `password_hash` column starts with `$argon2id$` (or `$2b$` for bcrypt) and never stores the plaintext password.

### 1.2 Server-Side Input Validation
*Mitigates: `RISK-01`, `RISK-10`, `RISK-12` (Tampering / DoS)*

1. **What needs to be changed:** Enforce strict schema, type, length, and format validation inside Flask route handlers for all registration, login, note, and profile inputs.
2. **Why it matters:** Frontend JavaScript validation crosses Trust Boundary 1 (User Device) and can be bypassed in seconds with `curl` or a proxy. Server-side validation is the authoritative defense against malformed data, oversized payloads, and unexpected types.
3. **How to implement it:**
   - Enforce email format checks, minimum password length (e.g., $\ge 12$ characters per NIST SP 800-63B), note title max length (e.g., 150 chars), and note body max length (e.g., 20,000 chars).
   - Set `app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024` (1 MB) in Flask to reject oversized requests at the framework layer.
4. **How to verify it:** Send POST requests directly via `curl` containing empty fields, invalid emails, and payloads exceeding field length limits; verify HTTP `400 Bad Request` or `413 Payload Too Large` is returned.

### 1.3 Parameterized SQL Queries
*Mitigates: `RISK-01` (Tampering / Information Disclosure)*

1. **What needs to be changed:** Eliminate all string concatenation (`+`), `%`-formatting, and Python f-strings inside SQLite queries; use parameterized placeholders (`?`) exclusively.
2. **Why it matters:** String interpolation merges untrusted user data with SQL syntax, enabling attackers to bypass authentication or dump the entire SQLite database. Parameterization separates SQL code from user-supplied data at the database driver level.
3. **How to implement it:**
   ```python
   # Secure parameterized query
   cursor.execute(
       "SELECT id, email, password_hash, role FROM users WHERE email = ?",
       (normalized_email,)
   )
   ```
4. **How to verify it:** Audit all `cursor.execute` calls in the codebase for f-strings or string formatting, and submit SQL metacharacters (`' OR '1'='1 --`) to login and note search forms to confirm they are treated strictly as literal text.

### 1.4 Secure Session Cookies
*Mitigates: `RISK-05` (Spoofing / Information Disclosure)*

1. **What needs to be changed:** Configure Flask session cookies with `HttpOnly`, `Secure`, `SameSite`, and a strong, externally loaded cryptographic `SECRET_KEY`, plus regenerate sessions upon login.
2. **Why it matters:** Without `HttpOnly`, client-side scripts (XSS) can read session cookies via `document.cookie`. Without `Secure`, cookies leak over unencrypted HTTP. Without `SameSite`, browsers attach cookies to cross-site CSRF requests.
3. **How to implement it:**
   ```python
   import os

   app.config.update(
       SECRET_KEY=os.environ["FLASK_SECRET_KEY"],  # Minimum 32 random bytes
       SESSION_COOKIE_HTTPONLY=True,
       SESSION_COOKIE_SECURE=True,
       SESSION_COOKIE_SAMESITE="Lax",
       SESSION_COOKIE_NAME="__Host-session",
   )

   # On successful login:
   session.clear()
   session["user_id"] = user["id"]
   session["role"] = user["role"]
   ```
4. **How to verify it:** Inspect the `Set-Cookie` response header after login in browser DevTools or `curl -i` and confirm `HttpOnly`, `Secure`, and `SameSite=Lax` attributes are present; confirm `document.cookie` in the browser console does not expose the session cookie.

### 1.5 Authentication and Authorization Checks (IDOR & Role Validation)
*Mitigates: `RISK-02`, `RISK-03` (Tampering / Elevation of Privilege)*

1. **What needs to be changed:** Require active session authentication on all non-public routes, enforce object ownership (`user_id`) on all note queries, allowlist mutable profile fields, and apply server-side role decorators on admin endpoints.
2. **Why it matters:** Authenticating a user only proves *who* they are; authorization proves *what* they are allowed to access. Missing ownership or role checks enable horizontal privilege escalation (reading/editing others' notes) and vertical privilege escalation (becoming an Administrator).
3. **How to implement it:**
   ```python
   # Object-level ownership check
   note = db.execute(
       "SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?",
       (note_id, session["user_id"])
   ).fetchone()
   if note is None:
       abort(404)

   # Explicit allowlist on profile update (never accept 'role')
   allowed_name = validate_display_name(request.form.get("display_name", ""))
   db.execute("UPDATE users SET display_name = ? WHERE id = ?", (allowed_name, session["user_id"]))
   ```
4. **How to verify it:** Authenticate as User A and attempt to fetch, update, or delete a note owned by User B (expect `403`/`404`). Submit `role=admin` in User A's profile update request and verify User A's role remains unchanged in SQLite.

### 1.6 Login and Reset Rate Limiting
*Mitigates: `RISK-07` (Spoofing / Denial of Service)*

1. **What needs to be changed:** Add IP-based and account-based request throttling to `/login`, `/register`, and `/forgot-password`.
2. **Why it matters:** Unthrottled authentication endpoints allow automated password guessing, credential stuffing, and email service quota exhaustion.
3. **How to implement it:**
   ```python
   from flask_limiter import Limiter
   from flask_limiter.util import get_remote_address

   limiter = Limiter(get_remote_address, app=app)

   @app.route("/login", methods=["POST"])
   @limiter.limit("5 per minute; 20 per hour")
   def login():
       ...
   ```
4. **How to verify it:** Issue rapid sequential requests to `/login` and `/forgot-password` exceeding the configured threshold and verify the server returns HTTP `429 Too Many Requests`.

### 1.7 Password Reset Token Security
*Mitigates: `RISK-06` (Elevation of Privilege / Spoofing)*

1. **What needs to be changed:** Generate cryptographically random reset tokens, store only their SHA-256 hash in SQLite, enforce a short expiration (15 minutes), invalidate tokens after single use, and return generic confirmation messages.
2. **Why it matters:** Predictable, non-expiring, or reusable tokens allow attackers to take over accounts via token guessing or link replay. Generic responses prevent account email enumeration.
3. **How to implement it:**
   ```python
   import hashlib, secrets
   from datetime import datetime, timedelta, timezone

   raw_token = secrets.token_urlsafe(32)
   token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
   expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

   # Store token_hash + expires_at + used=0 in password_resets table
   # Send raw_token via Email Service; on submission, verify hash, expiry, and used=0, then mark used=1 atomically.
   ```
4. **How to verify it:** Verify reset tokens have at least 256 bits of entropy, confirm an expired token ($>15$ minutes) is rejected, confirm submitting a valid token a second time fails, and verify `/forgot-password` returns the exact same response for registered and unregistered emails.

---

## Phase 2 — Important Improvements

Phase 2 strengthens defense-in-depth across the User Device, Public Internet, Application Server, and Database trust boundaries.

### 2.1 CSRF Protection
*Mitigates: `RISK-08` (Tampering)*

1. **What needs to be changed:** Require anti-CSRF tokens on all state-changing routes (`POST`, `PUT`, `PATCH`, `DELETE`).
2. **Why it matters:** Even with `SameSite=Lax`, explicit CSRF tokens guarantee that state-changing actions (note deletion, profile email updates, logout) originate intentionally from SecureVault's own UI rather than a malicious third-party page.
3. **How to implement it:** Enable `CSRFProtect(app)` from `Flask-WTF` and embed `{{ csrf_token() }}` in HTML forms or send `X-CSRFToken` headers from JavaScript `fetch()` calls.
4. **How to verify it:** Submit a state-changing `POST` request with a valid session cookie but missing or altered CSRF token; confirm Flask rejects the request with HTTP `400` or `403`.

### 2.2 Content Security Policy (CSP)
*Mitigates: `RISK-10` (Information Disclosure / Tampering)*

1. **What needs to be changed:** Add a restrictive `Content-Security-Policy` HTTP response header disabling inline scripts and unauthorized external origins.
2. **Why it matters:** CSP acts as a critical safety net against Cross-Site Scripting (XSS) by instructing the browser to block unauthorized inline `<script>` execution or data exfiltration to attacker-controlled domains.
3. **How to implement it:** Configure Flask `@app.after_request` (or `Flask-Talisman`) with:
   `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';`
4. **How to verify it:** Inspect HTTP response headers from any Flask route and verify the `Content-Security-Policy` header is present without `'unsafe-inline'` or `'unsafe-eval'` in `script-src`.

### 2.3 HTTPS Enforcement
*Mitigates: `RISK-05` (Spoofing / Information Disclosure)*

1. **What needs to be changed:** Serve SecureVault exclusively over HTTPS via a reverse proxy (Nginx/Caddy/Cloud Load Balancer), redirect HTTP to HTTPS, and enable HSTS.
2. **Why it matters:** Traffic crossing the Public Internet Trust Boundary (credentials, personal notes, session cookies) is trivially readable and modifiable in plaintext HTTP on shared networks.
3. **How to implement it:** Terminate TLS 1.2/1.3 at the reverse proxy, configure `301` HTTP-to-HTTPS redirects, configure Flask `ProxyFix`, and set `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
4. **How to verify it:** Request the HTTP URL and verify automatic redirection to `https://`; inspect HTTPS headers for `Strict-Transport-Security`.

### 2.4 Security Headers
*Mitigates: `RISK-10` (Information Disclosure / Tampering)*

1. **What needs to be changed:** Configure standard defensive HTTP response headers on every response.
2. **Why it matters:** Prevents clickjacking (`X-Frame-Options`), MIME-type sniffing (`X-Content-Type-Options`), and unintended referrer leakage (`Referrer-Policy`).
3. **How to implement it:** Add via `@app.after_request`:
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Cache-Control: no-store` on authenticated API/dashboard responses
4. **How to verify it:** Run `curl -I https://<host>/dashboard` and verify all four headers are present in the HTTP response.

### 2.5 Restricted Database Access
*Mitigates: `RISK-01`, `RISK-04` (Information Disclosure / Tampering)*

1. **What needs to be changed:** Move `securevault.db` outside the web-accessible `static/` directory and restrict OS filesystem permissions to the dedicated service account.
2. **Why it matters:** If SQLite sits inside a served static folder or carries world-readable permissions (`0644`), any user or local process could download the entire database file directly.
3. **How to implement it:** Store the database in `/var/lib/securevault/securevault.db`, set ownership to the `securevault` service user, and run `chmod 700 /var/lib/securevault` and `chmod 600 /var/lib/securevault/securevault.db`.
4. **How to verify it:** Attempt to request `/static/securevault.db` over HTTP (expect `404`), and run `ls -l` on the host to verify `0600` file permissions.

### 2.6 Safe Error Handling
*Mitigates: `RISK-09` (Information Disclosure)*

1. **What needs to be changed:** Disable Flask debug mode (`FLASK_DEBUG=0`) and register custom generic handlers for `400`, `403`, `404`, and `500` errors.
2. **Why it matters:** Flask's interactive debugger (`Werkzeug` debugger) or raw Python tracebacks reveal internal filesystem paths, SQLite table layouts, and environment variables to attackers.
3. **How to implement it:** Register `@app.errorhandler(500)` returning a generic message (`"An unexpected error occurred."`) while logging the detailed exception stack trace exclusively to server-side logs.
4. **How to verify it:** Trigger a simulated server error or invalid endpoint and inspect the HTTP response body to ensure zero stack traces, file paths, or SQL fragments appear.

### 2.7 Logging and Monitoring
*Mitigates: `RISK-11` (Repudiation)*

1. **What needs to be changed:** Add structured security event logging for logins, failed logins, lockouts, password resets, note deletions, and `403` authorization denials.
2. **Why it matters:** Without audit trails, brute-force campaigns and unauthorized access attempts go unnoticed, and post-incident investigation becomes impossible.
3. **How to implement it:** Use Python's `logging` module with UTC ISO-8601 timestamps, event name, user ID (or anonymized email), and source IP, explicitly excluding passwords, cookies, and reset tokens from log strings.
4. **How to verify it:** Execute a failed login and a password reset request; inspect the log file to confirm structured entries exist and contain no secret values.

### 2.8 Least Privilege
*Mitigates: `RISK-03`, `RISK-09` (Elevation of Privilege)*

1. **What needs to be changed:** Run the Flask WSGI server under a dedicated unprivileged OS user (`securevault`) and scope the external Email Service API key strictly to mail-sending permissions.
2. **Why it matters:** Limits blast radius if the application process or third-party email credential is compromised, preventing lateral host takeover or reading unrelated account data in the email provider.
3. **How to verify it:** Inspect the running process owner (`ps -ef | grep gunicorn`) to confirm non-root execution, and review email provider API key scopes.

---

## Phase 3 — Additional Hardening

Phase 3 establishes ongoing operational resilience, session lifecycle hygiene, and incident preparedness.

### 3.1 Dependency Updates & Vulnerability Scanning
*Mitigates: `RISK-12`*

1. **What needs to be changed:** Pin exact package versions in `requirements.txt` and integrate automated CVE checks (`pip-audit`).
2. **Why it matters:** Outdated Flask, Werkzeug, or cryptography packages can expose known vulnerabilities even when application code is secure.
3. **How to implement it:** Generate pinned dependencies (`pip freeze > requirements.txt`) and run `pip-audit -r requirements.txt` on every CI build and monthly maintenance window.
4. **How to verify it:** Execute `pip-audit` and confirm zero unresolved High/Critical CVEs are reported.

### 3.2 Backup and Recovery Strategy
*Mitigates: `RISK-12`*

1. **What needs to be changed:** Schedule automated, encrypted, consistent SQLite backups using SQLite's online backup API (`sqlite3 .backup`) rather than raw file copying.
2. **Why it matters:** Copying an active SQLite file directly can produce corrupted backups; unencrypted backups expose user data if storage is compromised.
3. **How to implement it:** Run a scheduled job executing `sqlite3 /var/lib/securevault/securevault.db ".backup '/var/backups/securevault/db-$(date +%F).sqlite'"`, encrypt backups at rest, and test restores quarterly.
4. **How to verify it:** Restore a backup copy into an isolated test environment and verify record integrity and application startup.

### 3.3 Account Activity Monitoring
*Mitigates: `RISK-11`, `RISK-05`*

1. **What needs to be changed:** Record and surface recent login timestamps and security-sensitive account events (password changes, email updates) and send email alerts when a password is changed or reset.
2. **Why it matters:** Enables legitimate users to spot unauthorized logins or unexpected profile changes quickly.
3. **How to implement it:** Add a `last_login_at` column and send a notification email via the Email Service whenever a password reset completes or account email changes.
4. **How to verify it:** Complete a password reset and confirm an email alert is dispatched to the account's registered address.

### 3.4 Session Expiration (Idle & Absolute Timeouts)
*Mitigates: `RISK-05`*

1. **What needs to be changed:** Enforce both an idle timeout (e.g., 30 minutes of inactivity) and an absolute maximum session lifetime (e.g., 12 hours), plus server-side session invalidation on logout or password change.
2. **Why it matters:** Limits the window of exposure if a user leaves a shared computer logged in or if a session token is leaked.
3. **How to implement it:** Store `issued_at` and `last_active_at` timestamps inside the session alongside a per-user `session_version` integer in SQLite; increment `session_version` on password reset/logout-all to invalidate prior cookies immediately.
4. **How to verify it:** Advance or wait past the idle timeout and confirm subsequent requests redirect to `/login`; change the account password and verify an older session cookie is rejected.

### 3.5 Security Testing Integration
*Mitigates: All Risks*

1. **What needs to be changed:** Add automated unit/integration tests covering authorization boundaries (IDOR), SQL injection payloads, CSRF rejection, and rate-limiting thresholds, plus static analysis (`bandit`).
2. **Why it matters:** Prevents security regressions as new features are added to SecureVault over time.
3. **How to implement it:** Run `pytest` security test suites and `bandit -r app/` on every pull request.
4. **How to verify it:** Inspect CI workflow logs to verify `bandit` and security integration tests pass cleanly.

### 3.6 Incident Response Preparation
*Mitigates: `RISK-11`, `RISK-12`*

1. **What needs to be changed:** Document a concise runbook for rotating `FLASK_SECRET_KEY`, revoking external Email Service API keys, invalidating active sessions, and restoring clean SQLite backups.
2. **Why it matters:** Pre-tested recovery procedures dramatically reduce downtime and containment time during a real security incident.
3. **How to implement it:** Maintain an operational incident runbook with contact owners, secret-rotation commands, and log retention locations.
4. **How to verify it:** Conduct a tabletop walkthrough verifying each rotation step can be executed without undocumented dependencies.
