# Remediation Notes — SecureAuth

**Remediation and verification window:** 2026-11-25 to 2026-11-26
**Target:** `task-2-secure-authentication/`  
**Scope:** Findings FND-01–FND-07; existing routes and UI retained

## Changes implemented

| Finding | Files | Remediation |
|---|---|---|
| FND-01 | `app/config.py`, `app/__init__.py` | Load dotenv before runtime configuration; validate boolean and integer environment values; bound session lifetime; enforce production debug, cookie, and key requirements. |
| FND-02 | `app/models.py`, `app/security.py` | Persist SHA-256 hashes of session nonces in `authenticated_sessions`; validate user, revocation, idle and absolute expiry; revoke the record before clearing the cookie; prune expired rows. |
| FND-03 | Task 2 and Task 4 `requirements.txt` | Upgrade Flask 3.1.0→3.1.3, Werkzeug 3.1.3→3.1.9, python-dotenv 1.0.1→1.2.2, and pytest 8.3.5→9.0.3. |
| FND-04 | `app/auth.py`, `app/routes.py` | Check credential type, length, and null bytes before lookup or password verification; do not reflect oversized or control-containing submitted emails. |
| FND-05 | `app/auth.py`, `app/security.py`, `app/__init__.py` | Log registration success with user ID, bound and sanitize log fields, and emit structured security events for selected error and invalid-session conditions. |
| FND-06 | `app/routes.py` | Apply `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` and `Pragma: no-cache` to login, registration, and dashboard responses. |
| FND-07 | `app/config.py` | Generate test signing keys with `secrets.token_hex(32)`, removing Bandit B105. Retain `memory://` for local single-process use and document the shared-store requirement for multi-worker deployment. |

## Implementation details

### Runtime configuration

The application factory calls `load_dotenv()` before `build_env_config()`. Invalid booleans or session-lifetime values now raise explicit errors. The accepted session lifetime is 1–1440 minutes. Production configuration rejects debug mode, insecure cookies, signing keys shorter than 32 characters, and missing keys.

### Server-side session lifecycle

On login, the application generates a random session nonce, hashes it with SHA-256, and stores the hash with the user ID and absolute expiry. Only the nonce is carried in the signed client cookie. On each protected request, the application validates the client timestamps and the matching database record. Logout marks the server record revoked before clearing the cookie. The configured absolute lifetime is 48 times the idle timeout.

### Input, logging, and cache controls

Login input bounds are enforced before database lookup and password verification. Security logs avoid registration email addresses and replace ASCII control characters with spaces after bounding fields. Error handlers and invalid-session paths emit structured events without logging passwords or session tokens. Authentication and dashboard responses are marked non-cacheable.

## Verification summary

The final run passed 40 Task 2 tests, 8 Task 4 verification tests, and all 9 assessment-harness checks. pip-audit reported no known vulnerabilities for the scanned Task 2 requirements or the full Task 4 dependency set; Bandit reported no findings. The independent baseline and final test logs are in `../evidence/`.

The independent baseline harness observed a 110.6 ms login time with one verifier call. Final retesting established that the verifier is no longer called for oversized input; elapsed time is deliberately not treated as a security threshold or guarantee.
