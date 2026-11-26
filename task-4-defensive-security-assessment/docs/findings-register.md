# Findings Register — SecureAuth Defensive Assessment

**Assessment window:** 2026-11-25 to 2026-11-26 (UTC)
**Target:** `task-2-secure-authentication/`
**Scope:** Local source review, isolated Flask test-client checks, pytest, pip-audit, and Bandit

## Status summary

| ID | Finding | Severity | Baseline | Final status |
|---|---|---|---|---|
| FND-01 | Runtime environment configuration was read before dotenv loading | Medium | Confirmed | Fixed and verified |
| FND-02 | Signed session cookies had no server-side revocation | Medium | Confirmed | Fixed and verified |
| FND-03 | Pinned dependencies had known advisories | Medium | Confirmed | Fixed and verified |
| FND-04 | Login accepted unbounded credentials before password verification | Low | Confirmed | Fixed and verified |
| FND-05 | Security logs exposed registration email and accepted control characters | Low | Confirmed | Fixed and verified |
| FND-06 | Authentication pages lacked no-store cache directives | Low | Confirmed | Fixed and verified |
| FND-07 | Bandit flagged a literal test key; local limiter uses process memory | Informational | Observed | Informational; B105 fixed and memory-backend limitation accepted |

Baseline and retest evidence are recorded in `../evidence/baseline-test-results.txt`, `../evidence/dependency-audit.txt`, and `../evidence/retest-test-results.txt`. The independently reproduced baseline in this checkout was 22 Task 2 tests passed, 4/9 harness checks passed, 8 unique dependency advisories, and one Bandit B105 warning. The final retest was 40 Task 2 tests and 8 Task 4 tests passed, 9/9 harness checks, zero pip-audit advisories, and zero Bandit findings.

## Findings

### FND-01 — Environment configuration loaded too early

- **Affected:** `app/__init__.py`, `app/config.py`
- **Baseline evidence:** `CHK-01` failed because configuration values were bound before `load_dotenv()` ran. Empty or malformed boolean/integer environment values could also fail without a clear range check.
- **Remediation:** `create_app()` loads dotenv before building environment configuration. Boolean and integer parsing now fails explicitly on malformed values; session lifetime is bounded to 1–1440 minutes. Production rejects debug mode, insecure cookies, short signing keys, and missing keys. Direct `ProductionConfig` use requires an explicit or environment-provided key.
- **Verification:** `CHK-01` passed; Task 2 configuration tests cover dotenv ordering, invalid settings, production constraints, and per-test secrets.
- **Final status:** **Fixed and verified**.

### FND-02 — Logout did not revoke copied session cookies

- **Affected:** `app/models.py`, `app/security.py`
- **Baseline evidence:** `CHK-06` replayed a pre-logout cookie and received HTTP 200 on `/dashboard`.
- **Remediation:** A SQLite `authenticated_sessions` table stores a SHA-256 hash of a random session nonce, the user ID, issue/expiry times, and revocation time. Validation checks the server-side record, idle timeout, and absolute expiry; logout revokes the record before clearing the cookie. Expired records are pruned.
- **Verification:** `CHK-06` passed with a redirect to login; focused tests cover replay rejection, independent sessions, expiration, and stored-hash behavior.
- **Final status:** **Fixed and verified**.

### FND-03 — Known dependency advisories

- **Affected:** Task 2 and Task 4 `requirements.txt`
- **Baseline evidence:** The pinned baseline manifest produced 15 pip-audit advisory rows representing 8 unique advisory identifiers across Flask, Werkzeug, python-dotenv, and pytest.
- **Remediation:** Both manifests pin Flask 3.1.3, Werkzeug 3.1.9, python-dotenv 1.2.2, and pytest 9.0.3. Other pinned runtime packages remain unchanged.
- **Verification:** pip-audit against the Task 2 manifest and full Task 4 dependency set reported no known vulnerabilities.
- **Final status:** **Fixed and verified**.

### FND-04 — Unbounded login inputs

- **Affected:** `app/auth.py`, `app/routes.py`
- **Baseline evidence:** `CHK-07` passed a 50,000-character password into the password verifier and reflected a 312-character email in the login response. The independent baseline harness measured 110.6 ms; its Task 4 pytest check measured 112.6 ms. These are single-run environment-specific observations, not performance guarantees.
- **Remediation:** Login validates input type, email/password length, and null bytes before database lookup or password verification. Oversized or control-containing submitted emails are not echoed into the response.
- **Verification:** `CHK-07` passed with no password-verifier call and no oversized email reflection. Task 2 tests cover oversized email/password and malformed/null input.
- **Final status:** **Fixed and verified**.

### FND-05 — PII exposure and log injection

- **Affected:** `app/auth.py`, `app/security.py`, `app/__init__.py`
- **Baseline evidence:** Registration logs included the submitted email; CR/LF controls could forge log lines; selected client/server error and invalid-session events lacked structured logs.
- **Remediation:** Registration success logs use the user ID rather than email. Event, address, and detail fields are bounded and control characters are collapsed. Structured events cover bad requests, forbidden requests, oversized payloads, internal errors, and invalid/revoked/expired sessions.
- **Verification:** `CHK-08` passed with no PII leak or forged line. Tests exercise registration-log redaction, control-character sanitization, CSRF rejection, and invalid sessions.
- **Final status:** **Fixed and verified**.

### FND-06 — Authentication response caching

- **Affected:** `app/routes.py`
- **Baseline evidence:** `/login` and `/register` did not set no-store directives.
- **Remediation:** Login, registration, and dashboard responses now set `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache`.
- **Verification:** `CHK-09` and route-specific tests passed for both authentication pages.
- **Final status:** **Fixed and verified**.

### FND-07 — Static-analysis notice and in-memory limiter

- **Affected:** `app/config.py`, `app/extensions.py`
- **Baseline evidence:** Bandit reported one low-severity, medium-confidence B105 warning on a literal test signing key. The `memory://` limiter backend is process-local and resets on restart.
- **Remediation and disposition:** Test signing keys are generated with `secrets.token_hex(32)`, and the B105 warning is gone. The local memory backend remains intentionally configured for this single-process educational app; shared Redis storage is required for multi-worker deployments.
- **Verification:** Bandit reported no findings. The deployment limitation remains documented.
- **Final status:** **Informational**; B105 fixed and verified, process-local limiter limitation accepted.

## Passing controls retained

The assessment also verified salted Werkzeug password hashing, parameterized SQLite queries, CSRF protection, login/registration rate limits, generic login errors with a dummy hash for unknown users, secure cookie attributes, security headers, and Jinja autoescaping. Existing Task 2 behavior remained covered by the final regression suite.
