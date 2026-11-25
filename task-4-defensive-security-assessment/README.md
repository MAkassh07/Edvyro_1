# Defensive Security Assessment Capstone — Task 4

**Track:** Cyber Security · **Task:** TASK-4 · **Target:** `task-2-secure-authentication/` (SecureAuth)  
**Assessment Date:** 2026-11-25 · **Repository:** [https://github.com/MAkassh07/Edvyro_1](https://github.com/MAkassh07/Edvyro_1)

---

## 1. Project Overview

This capstone project conducts an authorized, non-destructive white-box defensive security assessment of the local Python Flask authentication application (**SecureAuth**) built in Task 2. Following formal scope and rules-of-engagement boundaries, the engagement inspects five core security domains, records baseline evidence, remediates the highest-priority confirmed findings inside Task 2, and verifies every fix via automated before-and-after retesting.

---

## 2. Assessment Scope & Phases

- **Phase 1 — Authorization & Scope:** [`docs/authorization-and-scope.md`](docs/authorization-and-scope.md) · [`docs/rules-of-engagement.md`](docs/rules-of-engagement.md)
- **Phase 2 — Baseline Assessment:** [`docs/assessment-methodology.md`](docs/assessment-methodology.md) · [`evidence/baseline-assessment.md`](evidence/baseline-assessment.md) · [`evidence/baseline-test-results.txt`](evidence/baseline-test-results.txt) · [`evidence/dependency-audit.txt`](evidence/dependency-audit.txt)
- **Phase 3 — Findings Register:** [`docs/findings-register.md`](docs/findings-register.md)
- **Phase 4 — Remediation Notes:** [`docs/remediation-notes.md`](docs/remediation-notes.md)
- **Phase 5 — Retesting Evidence:** [`evidence/retest-results.md`](evidence/retest-results.md) · [`evidence/retest-test-results.txt`](evidence/retest-test-results.txt)
- **Phase 6 — Final PDF Report:** [`reports/defensive-security-assessment-report.pdf`](reports/defensive-security-assessment-report.pdf)

---

## 3. Summary of Verified Findings & Remediations

| ID | Finding | Severity | Post-Remediation Status |
| :--- | :--- | :---: | :--- |
| **FND-01** | `.env` configuration variables ignored at `Config` import time (`app/__init__.py`, `app/config.py`) | **Medium** | **Fixed (Verified)** — `build_env_config()` runs after `load_dotenv()` |
| **FND-02** | Pre-logout `secureauth_session` cookie replayable until timeout (`app/models.py`, `app/security.py`) | **Medium** | **Fixed (Verified)** — SQLite `revoked_sessions` rejects logged-out nonces |
| **FND-03** | Outdated dependencies (`Flask==3.1.0`, `Werkzeug==3.1.3`, `python-dotenv==1.0.1`, `pytest==8.3.5`) | **Medium** | **Fixed (Verified)** — Upgraded & verified `0` `pip-audit` advisories |
| **FND-04** | Unbounded `/login` password/email length causes `scrypt` CPU work & reflection (`app/auth.py`, `app/routes.py`) | **Low** | **Fixed (Verified)** — Pre-hash bounds enforced (`250.6 ms` → `5.1 ms`) |
| **FND-05** | `REGISTER_SUCCESS` logs email PII; missing CRLF sanitization & error logging (`app/security.py`, `app/__init__.py`) | **Low** | **Fixed (Verified)** — Logs `user_id` + `_sanitize_log_value()` |
| **FND-06** | `/login` and `/register` omit `Cache-Control: no-store` (`app/routes.py`) | **Low** | **Fixed (Verified)** — `no-store` headers applied to auth forms |
| **FND-07** | `Bandit B105` test key notice (`app/config.py`) & single-process `memory://` limiter | **Info** | **Resolved (`B105`) / Accepted (`memory://`)** |

---

## 4. Verification Metrics (Before vs. After)

- **Task 2 Functional & Security Suite (`pytest`):** `22/22` passed (baseline) → **`22/22` passed** (post-remediation, no regressions)
- **Task 4 Assessment Harness (`src/security_assessment.py`):** `4/9` passed (baseline) → **`9/9` passed** (retest)
- **Task 4 Verification Suite (`tests/test_security_assessment.py`):** **`7/7` passed**
- **Dependency Audit (`pip-audit`):** `8` unique advisories (baseline) → **`0` known vulnerabilities**
- **Static Scan (`bandit`):** `1` Low `B105` warning (baseline) → **`0` issues identified**

---

## 5. Reproducible Commands (Windows PowerShell)

Run inside `task-4-defensive-security-assessment/`:

```powershell
# 1. Create and activate virtual environment
python -m venv venv
venv\Scripts\Activate.ps1

# 2. Install Task 4 assessment + Task 2 patched dependencies
pip install -r requirements.txt

# 3. Run the automated Task 4 assessment harness
python src/security_assessment.py --mode retest

# 4. Run Task 4 verification tests
pytest -v

# 5. Run Task 2 full test suite to verify zero regressions
pytest -v ..\task-2-secure-authentication\tests -c ..\task-2-secure-authentication\pytest.ini

# 6. Run dependency and static security scans
pip-audit -r ..\task-2-secure-authentication\requirements.txt --no-deps
bandit -r ..\task-2-secure-authentication\app ..\task-2-secure-authentication\run.py

# 7. Regenerate the PDF report
python src/security_assessment.py --generate-pdf
```
