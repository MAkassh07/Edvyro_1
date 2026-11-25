# Assessment Methodology — Defensive Security Assessment

This assessment follows a structured, five-domain defensive review modeled after OWASP ASVS (Application Security Verification Standard) Level 1/2 practices and the Task 1 threat model for authentication services.

---

## 1. Five Assessment Domains (Phase 2)

| Domain | Inspection & Testing Criteria | Primary Files Reviewed |
| :--- | :--- | :--- |
| **A. Configuration Security** | `DEBUG` defaults, `SECRET_KEY` lifecycle, `.env` loading order, `HttpOnly`/`Secure`/`SameSite` flags, session timeout enforcement, custom error handlers | `app/__init__.py`, `app/config.py`, `run.py`, `.env.example` |
| **B. Authentication Security** | Password hashing algorithm (`scrypt`), brute-force rate limiting (`Flask-Limiter`), session fixation & logout revocation, CSRF protection, generic anti-enumeration messages | `app/auth.py`, `app/security.py`, `app/routes.py`, `app/extensions.py` |
| **C. Input Validation** | Empty/type checks, email normalization and length caps, password complexity and upper bounds across both `/register` and `/login`, SQL parameterization, XSS autoescaping | `app/security.py`, `app/auth.py`, `app/models.py`, `app/templates/*.html` |
| **D. Dependency Security** | Pinned package versions in `requirements.txt`, `pip-audit` advisory checks, static analysis via `bandit`, separation of confirmed CVEs from informational warnings | `requirements.txt` |
| **E. Logging & Error Handling** | Audit coverage across auth/security events, PII minimization in logs, newline/CRLF log-injection sanitization, stack trace suppression on `4xx`/`5xx` | `app/security.py`, `app/auth.py`, `app/__init__.py` |

---

## 2. Severity Classification Criteria

Findings are classified conservatively based on exploitability in SecureAuth's local/web threat model and actual observed impact:

- **Critical:** Directly exploitable remote compromise (e.g., authentication bypass, RCE, SQL injection exposing credentials) requiring immediate remediation.
- **High:** Significant weakness enabling account takeover, session hijacking, or systemic bypass of core security controls.
- **Medium:** Confirmed flaw weakening defense-in-depth, configuration reliability, session revocation, or service resilience under realistic conditions.
- **Low:** Minor hardening gap, defense-in-depth improvement, or limited information/logging issue with constrained impact.
- **Informational:** Architectural trade-off, scope boundary, or observation recorded for completeness without an active defect.

---

## 3. Evidence Verification & Retesting Workflow

1. **Baseline Capture:** Run Task 2's existing 22-test `pytest` suite, run `src/security_assessment.py` in baseline mode, and run `pip-audit` + `bandit`. Save raw sanitized outputs in `evidence/`.
2. **Findings Registration:** Log only verified issues supported by exact file/line references and reproducible test outputs (`docs/findings-register.md`). Document effective controls separately as **Passing Security Controls**.
3. **Targeted Remediation:** Implement minimal, clean, backward-compatible fixes in `task-2-secure-authentication/` without changing its overall Flask + SQLite architecture.
4. **Before-and-After Retesting:** Re-run the complete Task 2 `pytest` suite, the Task 4 assessment tests (`tests/test_security_assessment.py`), and `src/security_assessment.py`, recording actual pass/fail outcomes in `evidence/retest-results.md` and `evidence/retest-test-results.txt`.
5. **Report Compilation:** Generate `reports/defensive-security-assessment-report.pdf` directly from verified assessment data via ReportLab.
