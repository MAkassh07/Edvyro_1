# Cyber Security Internship Portfolio

This portfolio presents two defensive cybersecurity projects, covering threat modeling and secure authentication implementation.

## Task 1: Threat Model and Secure Configuration

Task 1 assesses the SecureVault application through architecture and data-flow modeling, STRIDE analysis, risk prioritization, and a phased security-hardening plan.

- [Task 1 overview and documentation](README.md)
- [Threat model](docs/threat-model.md)
- [Risk register](docs/risk-register.md)
- [Security hardening plan](docs/security-hardening.md)

**Technologies and methods:** Python/Flask and SQLite (target architecture), Mermaid, STRIDE, OWASP guidance, and NIST CSF.

## Task 2: Secure Authentication Lab

Task 2 implements SecureAuth, a Flask and SQLite authentication application with secure password hashing, server-side validation, rate limiting, CSRF defenses, hardened sessions, and automated security tests.

- [Task 2 project guide](task-2-secure-authentication/README.md)

**Technologies:** Python, Flask, SQLite, Werkzeug `scrypt`, Flask-Limiter, Flask-WTF, HTML/CSS/JavaScript, and pytest.

**Security concepts demonstrated:** threat modeling, STRIDE, risk assessment, password hashing, input validation, parameterized SQL, brute-force protection, CSRF protection, session security, and automated security testing.

### Run Task 2 locally

From the repository root, run:

```powershell
cd task-2-secure-authentication
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

Open `http://127.0.0.1:5000` in a browser. Configure `FLASK_SECRET_KEY` in `.env` as described in the Task 2 guide.

### Run automated tests

From `task-2-secure-authentication/`, run:

```powershell
pytest -v
```

## Task 3: Security Log Investigation

Task 3 investigates authentication logs through normalization, baseline analysis, deterministic detection rules, incident timeline reconstruction, and evidence-based response recommendations.

- [Task 3 project guide](task-3-security-log-investigation/README.md)
- [Incident report](task-3-security-log-investigation/reports/incident_report.pdf)
- [Investigation notebook](task-3-security-log-investigation/notebooks/security_log_investigation.ipynb)

**Technologies and methods:** Python, Pandas, Matplotlib, Jupyter, pytest, authentication log analysis, password-spraying and brute-force detection, and incident response.

## Task 4: Defensive Security Assessment

Task 4 conducts an authorized, non-destructive white-box assessment of the SecureAuth application from Task 2. It establishes a baseline, documents prioritized findings, records remediation, and verifies the results through repeatable retesting.

- [Task 4 assessment folder](task-4-defensive-security-assessment/)
- [Assessment report (PDF)](task-4-defensive-security-assessment/reports/defensive-security-assessment-report.pdf)

**Tools and methods:** Python, Flask test client, pytest, `pip-audit`, Bandit, and source-code review.

**Security areas assessed:** configuration and environment handling, authentication and session revocation, input validation, dependency vulnerabilities, security logging and PII, and authentication-response caching.

**Remediation and retest:** The assessment documents remediation for six prioritized findings and resolution of one informational finding. Retesting reports **22/22** Task 2 tests, **9/9** assessment checks, and **7/7** Task 4 tests passed, with **0** dependency advisories and **0** Bandit findings.
