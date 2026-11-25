# Security Verification Checklist — SecureVault

> **Verification Policy:** Controls must **never** be marked as `Pass` unless the corresponding verification procedure has actually been executed against a running SecureVault instance or codebase and observed to succeed.

---

## Verification Matrix

| ID | Control Requirement | Verification Procedure | Expected Secure Result | Status |
| :---: | :--- | :--- | :--- | :---: |
| **CHK-01** | Passwords are never stored in plaintext | Register a test user and inspect the users table directly using sqlite3 CLI (SELECT email, password_hash FROM users;). | The password_hash column contains only an irreversible salted cryptographic hash; plaintext never appears in DB or logs. | `Not tested` |
| **CHK-02** | Password hashing uses a secure algorithm (Argon2id / bcrypt) | Inspect the password_hash prefix in SQLite and review the Authentication Module hashing configuration. | Hash begins with $argon2id$ (or $2b$ with cost >= 12), confirming adaptive key stretching. | `Not tested` |
| **CHK-03** | SQL queries use parameterized statements | Audit all cursor.execute(...) calls in Flask backend and submit ' OR '1'='1 -- into login, registration, and note forms. | Zero string-formatted SQL queries exist; SQL metacharacters are treated strictly as literal strings with no DB error or bypass. | `Not tested` |
| **CHK-04** | Invalid login attempts are rate-limited | Send 15 rapid consecutive POST /login requests with invalid credentials from the same IP or targeting the same email. | Requests beyond the threshold (e.g., 5/min) receive HTTP 429 Too Many Requests without executing password verification. | `Not tested` |
| **CHK-05** | Session cookies use HttpOnly | Log in successfully, inspect Set-Cookie headers in HTTP response, and evaluate document.cookie in browser DevTools. | Set-Cookie includes HttpOnly; document.cookie does not expose the session cookie to JavaScript. | `Not tested` |
| **CHK-06** | Session cookies use Secure in HTTPS deployments | Inspect Set-Cookie response headers over an HTTPS deployment and verify cookie transmission rules. | Set-Cookie includes the Secure attribute, restricting browser cookie transmission to encrypted HTTPS connections. | `Not tested` |
| **CHK-07** | SameSite cookie policy is configured | Inspect the Set-Cookie header emitted by the Session Manager during authentication. | Set-Cookie includes SameSite=Lax (or SameSite=Strict), mitigating cross-site cookie attachment. | `Not tested` |
| **CHK-08** | Users cannot access or modify another user's notes | Authenticate as User A and request GET, PUT, and DELETE against a note ID owned by User B. | Server denies access with HTTP 403 Forbidden or 404 Not Found; User B's note remains unmodified in SQLite. | `Not tested` |
| **CHK-09** | Privilege escalation via improper role validation is prevented | Authenticate as a Normal User, submit role=admin in POST /account/update, and request /admin/* endpoints. | Profile update ignores role; database role remains user; /admin/* returns HTTP 403 Forbidden. | `Not tested` |
| **CHK-10** | CSRF protection is enabled for state-changing requests | Capture an authenticated POST request (create/delete note) and replay it with a missing or invalid CSRF token. | Request is rejected with HTTP 400 or 403 and no state modification occurs in SQLite. | `Not tested` |
| **CHK-11** | Sensitive information is not exposed in error messages | Send malformed payloads and trigger a non-existent route and simulated 500 condition while inspecting response bodies. | Responses return generic messages only; zero Python stack traces, file paths, or SQL statements are exposed. | `Not tested` |
| **CHK-12** | Security headers (CSP, HSTS, X-Frame-Options) are configured | Inspect HTTP response headers (curl -I) on /login and /dashboard. | Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, and HSTS (HTTPS) are present. | `Not tested` |
| **CHK-13** | Password reset tokens expire | Request a password reset token, wait past the configured TTL (15 minutes), and attempt to redeem the token. | Server rejects the expired token and requires initiating a new password reset request. | `Not tested` |
| **CHK-14** | Password reset tokens cannot be reused | Complete a valid password reset using a token, then submit the exact same token a second time. | Second attempt is rejected immediately; token record in SQLite is marked consumed or deleted on first use. | `Not tested` |
| **CHK-15** | Unauthorized access attempts and auth events are logged | Trigger failed logins, a 403 access denial, and a password reset; inspect server security logs. | Structured log entries record UTC timestamp, event type, source IP, and target ID without logging passwords or tokens. | `Not tested` |
| **CHK-16** | Dependencies are checked for known vulnerabilities | Run pip-audit -r requirements.txt against the pinned Python environment. | Scan completes cleanly with zero unresolved High or Critical CVEs in Flask or supporting packages. | `Not tested` |

---

## Markdown Checklist Summary

- [ ] **CHK-01:** Passwords are never stored in plaintext *(Status: Not tested)*
- [ ] **CHK-02:** Password hashing uses a secure algorithm (Argon2id / bcrypt) *(Status: Not tested)*
- [ ] **CHK-03:** SQL queries use parameterized statements *(Status: Not tested)*
- [ ] **CHK-04:** Invalid login attempts are rate-limited *(Status: Not tested)*
- [ ] **CHK-05:** Session cookies use HttpOnly *(Status: Not tested)*
- [ ] **CHK-06:** Session cookies use Secure in HTTPS deployments *(Status: Not tested)*
- [ ] **CHK-07:** SameSite cookie policy is configured *(Status: Not tested)*
- [ ] **CHK-08:** Users cannot access or modify another user's notes *(Status: Not tested)*
- [ ] **CHK-09:** Privilege escalation via improper role validation is prevented *(Status: Not tested)*
- [ ] **CHK-10:** CSRF protection is enabled for state-changing requests *(Status: Not tested)*
- [ ] **CHK-11:** Sensitive information is not exposed in error messages *(Status: Not tested)*
- [ ] **CHK-12:** Security headers (CSP, HSTS, X-Frame-Options) are configured *(Status: Not tested)*
- [ ] **CHK-13:** Password reset tokens expire *(Status: Not tested)*
- [ ] **CHK-14:** Password reset tokens cannot be reused *(Status: Not tested)*
- [ ] **CHK-15:** Unauthorized access attempts and auth events are logged *(Status: Not tested)*
- [ ] **CHK-16:** Dependencies are checked for known vulnerabilities *(Status: Not tested)*
