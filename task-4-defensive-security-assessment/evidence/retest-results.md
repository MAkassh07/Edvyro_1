# Retest Results — SecureAuth

**Retest date (UTC):** 2026-11-26
**Target:** `task-2-secure-authentication/`
**Environment:** Python 3.14.6; isolated retest virtual environment; Windows
**Detailed sanitized run record:** `retest-test-results.txt`

## Result summary

| Verification | Baseline | Retest | Result |
|---|---:|---:|---|
| Task 2 pytest suite | 22 passed | 44 passed | Pass |
| Task 4 pytest suite | 1 passed, 6 failed | 8 passed | Pass |
| Combined pytest suites | Not run together | 52 passed in 8.84s | Pass |
| Assessment harness | 4/9 | 9/9 at 2026-11-26T13:13:37Z | Pass |
| pip-audit | 8 unique advisories in 15 rows | 0 known advisories | Pass |
| Bandit | 1 B105 finding | 0 findings | Pass |

Baseline and retest dependency versions, command outcomes, and scanner scope are recorded in `dependency-audit.txt`. The retest used Flask 3.1.3, Werkzeug 3.1.9, Flask-Limiter 3.10.1, Flask-WTF 1.2.2, python-dotenv 1.2.2, and pytest 9.0.3. Tool versions were pip-audit 2.10.1, Bandit 1.9.4, and ReportLab 5.1.2.

## Finding-by-finding verification

| Finding | Baseline evidence | Retest evidence | Status |
|---|---|---|---|
| FND-01 — dotenv/runtime configuration | `CHK-01` failed: dotenv values were not applied; default timeout remained 15 minutes. | `CHK-01` passed with expected key, secure-cookie setting, and 25-minute test timeout. Configuration boundary and invalid-input tests passed. | Fixed and verified |
| FND-02 — session revocation | `CHK-06` failed: replayed pre-logout cookie received HTTP 200. | `CHK-06` passed: replay redirected to login. Tests confirmed stored nonce hashes, revocation, reauthentication, and expiry behavior. | Fixed and verified |
| FND-03 — dependency advisories | 8 unique advisories across four packages (15 audit rows). | Updated pins; pip-audit returned “No known vulnerabilities found” for the Task 2 manifest and full Task 4 requirements. | Fixed and verified |
| FND-04 — oversized login values | `CHK-07` called the verifier on a 50,000-character password and reflected an oversized email. The independent baseline harness observed 110.6 ms and its pytest check observed 112.6 ms. | `CHK-07` passed: verifier not called and oversized email not reflected. | Fixed and verified |
| FND-05 — PII and log injection | Registration email appeared in logs; control characters forged log lines; selected security events were missing. | `CHK-08` passed: no PII leak or forged line. Tests verified registration redaction and structured CSRF/session events. | Fixed and verified |
| FND-06 — cache controls | Login and registration responses lacked `no-store`. | `CHK-09` passed; login and registration responses include `Cache-Control` and `Pragma: no-cache`. | Fixed and verified |
| FND-07 — B105 and local limiter | Bandit reported one low-severity, medium-confidence B105 warning on the literal test key. | Bandit reported no findings after test keys became random. The process-local `memory://` limiter remains an accepted single-process limitation. | Informational; B105 fixed and verified |

## Interpretation and limitations

- Baseline timings are single-run environment-specific observations, not performance guarantees or a benchmark. Retest success is measured by no password-verifier call and no oversized email reflection, not by elapsed time.
- The final audit result reflects the manifests and environment on the retest date; it is not a guarantee against future advisories.
- The `memory://` rate-limit store is not shared across worker processes. Configure a shared backend such as Redis before multi-worker deployment.
- The original submitted baseline log is retained in `baseline-test-results.txt`; it is clearly separated from the independently reproduced baseline for this checkout.
