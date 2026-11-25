# Rules of Engagement — Defensive Security Assessment

**Target:** `task-2-secure-authentication/` (Local Flask Application — SecureAuth)  
**Testing Window:** 2026-11-25  
**Mode:** Authorized White-Box Defensive Assessment (Localhost & Isolated Test Fixtures Only)

---

## 1. Permitted Activities

- **Localhost & In-Process Testing Only:** Execute tests against `127.0.0.1` or Flask's isolated `app.test_client()` using temporary SQLite database files (`tmp_path`).
- **Manual Source-Code Inspection:** Inspect all Python modules, Jinja2 templates, static JavaScript/CSS, configuration classes, and dependency manifests inside `task-2-secure-authentication/`.
- **Local Automated Testing:** Run `pytest` suites and deterministic Python defensive verification scripts (`src/security_assessment.py`).
- **Safe Configuration & Dependency Auditing:** Inspect environment variable handling, cookie flags, HTTP response headers, and run read-only dependency audits (`pip-audit`) and static analysis (`bandit`).
- **Controlled Validation & Authentication Checks:** Test boundary conditions (empty fields, oversized inputs, null bytes, missing CSRF tokens, rate-limit thresholds, expired or logged-out session cookies) using synthetic dummy data.

---

## 2. Strictly Prohibited Activities

- **No External Targets:** Do not scan, probe, or connect to external websites, public IP addresses, or third-party systems.
- **No Denial-of-Service (DoS) Flooding:** Do not launch high-volume traffic floods or resource-exhaustion loops against live servers; oversized-input checks use single bounded test-client requests.
- **No Credential Stuffing or Real Data:** Never use leaked credential lists, real passwords, or personal user data.
- **No Destructive Database Operations:** Do not alter or corrupt persistent production databases; use ephemeral temporary SQLite files per test case.
- **No Secret or Exploit Disclosure:** Never commit `.env` files, real signing keys, or weaponized exploit payloads.

---

## 3. Operational Safeguards & Escalation

1. **Preserve Baseline Evidence First:** Complete and record the entire baseline assessment (`evidence/baseline-assessment.md`, `evidence/baseline-test-results.txt`, `evidence/dependency-audit.txt`) before modifying any file in `task-2-secure-authentication/`.
2. **Preserve Repository Integrity:** Keep `task-1-threat-model/`, `task-3-security-log-investigation/`, and root `README.md` completely untouched.
3. **Preserve Application Behavior:** Every remediation in `task-2-secure-authentication/` must keep all existing routes (`/`, `/register`, `/login`, `/dashboard`, `/logout`) and existing user workflows working cleanly.
4. **Honest Reporting:** If a tool or external vulnerability feed cannot run in an offline environment, record that limitation transparently rather than fabricating results.
