# Authentication Security Note — SecureAuth

This technical note explains the authentication design decisions implemented in **SecureAuth** in clear, practical terms suitable for a second-year Computer Science student and cybersecurity reviewers.

---

## 1. What Authentication Is

**Authentication** is the process of verifying that a user is genuinely who they claim to be before granting access to private application resources. In SecureAuth, users prove their identity using something they know: their registered email address and password.

Authentication is distinct from **authorization** (deciding what an authenticated user is permitted to access). Once SecureAuth verifies credentials, it creates a server-signed session so the user does not have to re-enter their password on every page load, and every protected route (`/dashboard`) verifies that session before displaying user data.

---

## 2. Why Password Hashing Is Important

If an attacker ever steals a copy of the SQLite database (`secureauth.db`), plaintext passwords would immediately expose every user's account—and because many people reuse passwords, their accounts on other websites too.

**Ordinary encryption (such as AES) is not an appropriate replacement for password hashing** because encryption is reversible: if the database and the encryption key are stored on the same server, an attacker who compromises the server can decrypt every password.

By contrast, **cryptographic password hashing** is a **one-way mathematical transformation** designed specifically for passwords:

- It cannot be reversed back into the original password.
- Modern password-hashing algorithms (`scrypt`, `Argon2id`, `bcrypt`) are intentionally **slow and memory-hard**, making brute-force guessing thousands of times more expensive for attackers.
- Each password receives a unique random **salt**, preventing attackers from using precomputed lookup tables ("rainbow tables") or spotting two users who chose the same password.

---

## 3. How SecureAuth Stores Passwords Safely

SecureAuth delegates password hashing to **Werkzeug** (`generate_password_hash` and `check_password_hash`) using `scrypt` (when supported by OpenSSL/Python, with `pbkdf2:sha256:600000` as a safe fallback):

- When a user registers, `hash_password()` generates a random cryptographic salt and derives an irreversible hash string stored in the `password_hash` column.
- Plaintext passwords are never written to SQLite, never returned in HTML/JSON responses, and never written to application logs.
- During login, `verify_password()` runs `check_password_hash()`, which extracts the salt and parameters from the stored hash and compares hashes in constant time.

---

## 4. How Server-Side Validation Works

Browser HTML attributes (`required`, `type="email"`, `minlength="12"`) and JavaScript hints improve user experience, **but they provide zero real security** because any user or automated script can bypass the browser using `curl`, Python `requests`, or browser DevTools.

SecureAuth therefore validates every field inside `app/security.py` on the server:

- **Email normalization & checks:** Whitespace is trimmed and letters are lowercased (`normalize_email`), empty values, control characters, and lengths above 254 characters are rejected, and format is validated.
- **Password policy:** Enforces 12–128 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character, while rejecting null bytes.
- **Confirmation check:** Verifies `password == confirm_password` on the server.
- **Database safety:** All SQL queries use `?` parameter placeholders in `sqlite3` so user input is never concatenated into SQL strings, preventing SQL injection.

---

## 5. How Rate Limiting Prevents Brute-Force Attempts

Without request throttling, an attacker can write a script that tests thousands of common passwords against `/login` per minute.

SecureAuth uses **Flask-Limiter** on `POST` routes:

- **`/login`:** Limited to **5 attempts per minute per IP address**.
- **`/register`:** Limited to **5 attempts per hour per IP address**.

When an IP exceeds the limit, Flask-Limiter immediately returns **HTTP 429 (Too Many Requests)** and records a `RATE_LIMIT_EXCEEDED` security event without executing password hashing. For local development, limits are stored in memory (`memory://`); in multi-worker production deployments, a shared backend such as Redis (`redis://...`) should be configured so all worker processes share the same counters.

---

## 6. How Secure Cookies Protect Sessions

HTTP is stateless—every request arrives independently. After a user logs in, Flask stores session claims (`user_id`, `user_email`, `session_nonce`, `issued_at`, `last_active_at`) inside a cookie signed with `SECRET_KEY` using HMAC. The server stores only a SHA-256 hash of the nonce in an `authenticated_sessions` SQLite table.

Because the cookie is cryptographically signed, a user cannot modify `user_id` inside their browser without invalidating the signature. Upon login, SecureAuth clears/revokes any existing session before setting the new user's session data, ensuring prior session state is replaced cleanly (mitigating session fixation). On each protected request, the server verifies that the nonce hash exists, belongs to that user, is not revoked, and has not expired.

---

## 7. What `HttpOnly`, `Secure`, and `SameSite` Mean

| Cookie Attribute | Setting in SecureAuth | Security Purpose |
| :--- | :--- | :--- |
| **`HttpOnly`** | `True` (Always) | Prevents client-side JavaScript (`document.cookie`) from reading the session cookie, blocking cookie theft if an XSS bug ever occurred. |
| **`Secure`** | `True` in HTTPS production (`SESSION_COOKIE_SECURE=true`), `False` for local HTTP dev | Instructs the browser to send the cookie **only** over encrypted HTTPS connections so it cannot be sniffed on public Wi-Fi. Disabled only for local `http://127.0.0.1` testing. |
| **`SameSite`** | `'Lax'` | Prevents browsers from sending the session cookie on cross-site background `POST` requests (such as hidden forms on malicious third-party sites), providing defense-in-depth against CSRF. |

---

## 8. Why Session Expiration Matters

If a user signs in on a shared computer or leaves a browser open, an indefinite session stays valid forever. SecureAuth sets two layers of expiration:

1. **Cookie lifetime (`PERMANENT_SESSION_LIFETIME`):** Tells the browser to discard the cookie after the configured inactivity interval (15 minutes by default).
2. **Server-verified inactivity timestamp (`last_active_at`):** `validate_active_session()` checks the elapsed time since the user's last request and forces re-authentication after the configured idle timeout.
3. **Absolute lifetime and revocation:** The session registry applies an absolute expiry (48 times the configured idle timeout). Logout marks the server-side record revoked before clearing the cookie, so replaying a copied pre-logout cookie is rejected immediately.

---

## 9. How Generic Error Messages Prevent Account Enumeration

If `/login` returned `"No account found with that email"` for unknown addresses and `"Wrong password"` for real users, an attacker could probe thousands of emails to build a list of registered SecureAuth users (**account enumeration**).

SecureAuth prevents this in two ways:

1. Both unknown emails and wrong passwords return the exact same HTTP `401` message: **`"Invalid email or password."`**
2. When an email does not exist, `authenticate_account()` still runs `verify_password()` against a precomputed dummy hash so the response time stays consistent with a real password verification.

---

## 10. What CSRF Protection Does

**Cross-Site Request Forgery (CSRF)** occurs when a malicious website tricks a logged-in victim's browser into submitting an unintended request (for example, submitting a hidden form to `/logout` or changing account settings) using the victim's active session cookie.

SecureAuth enables **Flask-WTF `CSRFProtect`**, which embeds a unique, cryptographically signed `csrf_token` inside every HTML `<form>` (`register`, `login`, `logout`). When a `POST` request arrives without a matching token, Flask rejects it with **HTTP 400** before any route logic runs.

---

## 11. Security Limitations That Remain

To keep Task 2 beginner-friendly and focused on core authentication mechanics, several production capabilities are intentionally outside scope:

- **In-memory rate limiting:** Default `memory://` storage resets when the server restarts and does not synchronize across multiple Gunicorn workers (production requires Redis).
- **Single-factor authentication:** No email verification on sign-up, password reset flow, or Multi-Factor Authentication (MFA/TOTP) is implemented yet.
- **Signed client cookie metadata:** Flask's cookie is signed, not encrypted, so its claims are visible to the client. A server-side hash registry enables immediate revocation without storing the raw nonce; do not put secrets in session claims.
- **No TLS termination in Flask dev server:** Local `python run.py` uses HTTP; production deployments must run behind Nginx/Caddy with HTTPS and `SESSION_COOKIE_SECURE=true`.
