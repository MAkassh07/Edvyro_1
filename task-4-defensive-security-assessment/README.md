# Defensive Security Assessment — Task 4

**Target:** SecureAuth (`task-2-secure-authentication/`)
**Assessment date:** 2026-11-25; final retest: 2026-11-26
**Scope:** Authorized, non-destructive local source review and verification

## Objective and scope

Task 4 assesses the Task 2 Flask authentication application, records a reproducible pre-remediation baseline, documents prioritized findings, verifies targeted remediations, and produces a sanitized assessment report. Testing is restricted to local source, Flask test clients, temporary SQLite databases, and synthetic accounts. External targets and production data are out of scope.

## Deliverables

- [Authorization and scope](docs/authorization-and-scope.md)
- [Rules of engagement](docs/rules-of-engagement.md)
- [Assessment methodology](docs/assessment-methodology.md)
- [Findings register](docs/findings-register.md)
- [Remediation notes](docs/remediation-notes.md)
- [Baseline assessment](evidence/baseline-assessment.md)
- [Baseline test and harness evidence](evidence/baseline-test-results.txt)
- [Dependency and static scan evidence](evidence/dependency-audit.txt)
- [Retest results](evidence/retest-results.md)
- [Retest test output](evidence/retest-test-results.txt)
- [Machine-readable verification summary](evidence/verification-summary.json)
- [Assessment report PDF](reports/defensive-security-assessment-report.pdf)

## Areas assessed

Configuration and dotenv handling; authentication and session revocation; login input bounds; dependency vulnerabilities; security logging and PII; HTTP security and cache headers; baseline controls including CSRF, rate limiting, password hashing, and SQL parameterization.

## Findings and remediation

Six actionable findings were fixed and verified. Test signing keys are generated to remove Bandit B105. The local `memory://` limiter remains an explicitly accepted single-process limitation; use a shared store such as Redis for multi-worker deployment.

| Result | Baseline | Retest |
|---|---:|---:|
| Task 2 tests | 22 passed | 44 passed |
| Task 4 verification tests | 1 passed, 6 failed | 8 passed |
| Combined tests | — | 52 passed |
| Assessment harness | 4/9 | 9/9 |
| pip-audit | 8 unique advisories | 0 known advisories |
| Bandit | 1 B105 finding | 0 findings |

The independent baseline harness measured 110.6 ms for the oversized login; this is a single-run local observation, not a performance guarantee. Retest evidence confirms the verifier is not called and oversized email is not reflected. Full environment details and exit codes are in the evidence files.

## Reproduce the retest (Windows PowerShell)

Run from this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

python src\security_assessment.py --mode retest
pytest -q
pytest -q ..\task-2-secure-authentication\tests -c ..\task-2-secure-authentication\pytest.ini

python -m pip_audit -r ..\task-2-secure-authentication\requirements.txt --no-deps
python -m pip_audit -r requirements.txt
python -m bandit -r ..\task-2-secure-authentication\app ..\task-2-secure-authentication\run.py -f txt

python src\security_assessment.py --generate-pdf
```

The PDF generator requires the recorded verification summary and refuses to generate a report when its recorded scans/tests fail or when the live harness no longer matches the recorded result.
