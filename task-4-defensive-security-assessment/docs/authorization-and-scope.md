# Authorization and Scope — Defensive Security Assessment (Task 4)

**Project:** Defensive Security Assessment Capstone (EdVyro Cyber Security Internship — Task 4)  
**Repository:** Existing local portfolio checkout
**Assessment Date / Testing Window:** 2026-11-25 to 2026-11-26 (controlled localhost baseline, remediation, and verification retesting)

---

## 1. Authorization Statement

This defensive security assessment was authorized by the repository owner against the local educational Flask authentication service (**SecureAuth**) developed in **Task 2** (`task-2-secure-authentication/`). All inspection, automated verification, configuration checking, dependency auditing, remediation, and retesting activities are confined strictly to local workspace source files and ephemeral in-process / `127.0.0.1` localhost test instances using synthetic test accounts.

---

## 2. Target and Environment

| Attribute | Value |
| :--- | :--- |
| **Target Application** | SecureAuth (`task-2-secure-authentication/`) |
| **Baseline Application Stack** | Python 3.14.6, Flask 3.1.0, Werkzeug 3.1.3, Flask-Limiter 3.10.1, Flask-WTF 1.2.2, python-dotenv 1.0.1, pytest 8.3.5, SQLite |
| **Execution Mode** | Localhost (`127.0.0.1:5000`) and Flask `app.test_client()` backed by isolated temporary SQLite databases |
| **Prior Context** | Built from Threat Model & Hardening Plan in `task-1-threat-model/` |

---

## 3. In-Scope Components

The following files, routes, and controls inside `task-2-secure-authentication/` are **in scope**:

1. **Application Factory & Error Handlers:** `app/__init__.py` (security headers, error responses, `load_dotenv()` initialization).
2. **Configuration & Environment Handling:** `app/config.py`, `run.py`, `.env.example`, `.gitignore`.
3. **Extensions & Rate Limiting:** `app/extensions.py` (`CSRFProtect`, `Limiter`).
4. **Data Layer:** `app/models.py` (SQLite connection management, schema initialization, parameterized queries).
5. **Authentication & Security Controls:** `app/auth.py`, `app/security.py` (Werkzeug `scrypt` hashing, email/password validation, session lifecycle, audit logging).
6. **Routes & Templates / Client Assets:** `app/routes.py` (`/`, `/register`, `/login`, `/dashboard`, `/logout`), `app/templates/*.html`, `app/static/js/main.js`, `app/static/css/style.css`.
7. **Dependencies & Existing Tests:** `requirements.txt`, `pytest.ini`, `tests/*.py`.

---

## 4. Out-of-Scope Components

- Any external websites, public IP addresses, cloud hosting platforms, or third-party infrastructure.
- Production databases, real user accounts, or personal data (only synthetic `@example.com` test accounts are permitted).
- Task 1 (`task-1-threat-model/`) and Task 3 (`task-3-security-log-investigation/`) deliverables, which must remain unmodified.
- Network-layer load generation or denial-of-service stress testing.

---

## 5. Tools and Methodology

- **Manual Source-Code Review:** Line-by-line inspection across configuration, authentication, input validation, database queries, templates, and logging.
- **Automated Functional & Security Suite (`pytest`):** Executing the existing 22-test Task 2 suite plus custom non-destructive assessment checks (`src/security_assessment.py` and `tests/test_security_assessment.py`).
- **Static & Dependency Inspection:** `bandit` static security linter (when available in isolated venv), `pip-audit` dependency vulnerability check against `requirements.txt`, and local package metadata verification.
- **Controlled Local HTTP / Test Client Verification:** Low-impact requests simulating normal flows, malformed inputs, missing CSRF tokens, oversized payloads, and session replay/expiration checks.

---

## 6. Evidence-Handling Policy

- **No Secrets or PII:** Never store real credentials, `.env` secrets, or personal emails/passwords in findings, logs, evidence files, or PDFs.
- **Sanitized Outputs:** All test outputs and code references use synthetic accounts (`assessment@example.com`, `retest@example.com`) and temporary SQLite paths.
- **Factuality Guarantee:** Every finding, severity rating, dependency status, and retest result is backed strictly by observed code inspection or captured command output.
