# Baseline Security Assessment — SecureAuth

**Baseline source:** committed Task 2 and Task 4 snapshot at HEAD `009d1239e5b19793a84b3cfa48f1d8ccbfc94e07`
**Independent baseline run:** 2026-11-25 17:20 UTC, Windows, Python 3.14.6, isolated baseline virtual environment
**Target:** `task-2-secure-authentication/` before the corrective changes

The committed pre-remediation source was extracted to an isolated temporary directory and retested. The original submitted Linux baseline transcript remains at the beginning of `baseline-test-results.txt` for history; the independently reproduced Windows results are recorded separately after it. The original transcript's environment and timings are not presented as measurements from this rerun.

## Baseline results

| Check | Reproduced result |
|---|---|
| Task 2 pytest suite | 22 passed in 4.75s |
| Task 4 verification tests | 6 failed, 1 passed in 2.47s; failures corresponded to missing remediations |
| Assessment harness | 4/9 passed; CHK-01, CHK-06, CHK-07, CHK-08, and CHK-09 failed |
| pip-audit | 15 advisory rows across 4 packages; 8 unique advisory identifiers; exit 1 |
| Bandit | 528 lines scanned; one low-severity, medium-confidence B105 warning; exit 1 |

### Confirmed gaps

- **FND-01 — Configuration:** `.env` values were not applied before configuration binding. `CHK-01` observed `secret_matched=False`, `SESSION_COOKIE_SECURE=False`, and a 15-minute default lifetime.
- **FND-02 — Session revocation:** `CHK-06` replayed a copied pre-logout cookie and received HTTP 200 on `/dashboard`.
- **FND-03 — Dependencies:** The pinned baseline manifest contained 8 distinct advisories across Flask 3.1.0, Werkzeug 3.1.3, python-dotenv 1.0.1, and pytest 8.3.5. The scanner emitted 15 rows because advisories appeared more than once in the dependency graph.
- **FND-04 — Login bounds:** `CHK-07` verified a 50,000-character password and reflected a 312-character email. The independently reproduced harness measured 110.6 ms for that single run; the Task 4 pytest check measured 112.6 ms. These are machine-specific observations, not guarantees.
- **FND-05 — Logging:** `CHK-08` observed registration email PII in logs and a forged multiline event after CR/LF input. The baseline Task 4 test also confirmed CSRF rejection and invalid-session events were not captured.
- **FND-06 — Cache controls:** `CHK-09` observed empty `Cache-Control` values on `/login` and `/register`.
- **FND-07 — Static analysis:** Bandit reported B105 on the literal test signing key. The `memory://` limiter backend was a documented single-process limitation, not an exploitable finding in the local assessment scope.

### Controls that passed at baseline

The original Task 2 suite and harness verified the existing salted password hashing, generic login errors, CSRF enforcement, baseline cookie attributes, core security headers, and database query protections. The overall 22-test pass did not cover the findings above.

## Reproduction commands

Run from the extracted pre-remediation source:

```powershell
python -m pytest -q task-2-secure-authentication
python -m pytest -q task-4-defensive-security-assessment
python task-4-defensive-security-assessment\src\security_assessment.py --mode baseline
python -m pip_audit -r task-2-secure-authentication\requirements.txt --no-deps
python -m bandit -r task-2-secure-authentication\app task-2-secure-authentication\run.py -f txt
```

The audit databases and environment packages are time-sensitive; the recorded output, tool versions, and exit statuses are preserved in `baseline-test-results.txt` and `dependency-audit.txt`.
