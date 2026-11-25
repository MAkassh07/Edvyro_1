# Investigation Summary — Security Log Investigation

## Dataset & Data Quality
- **Input Records:** 12 (100% valid, 0 duplicates, 0 invalid timestamps, 0 invalid IPs)
- **Time Range:** `2026-08-01T09:00:12Z` to `2026-08-01T11:47:09Z`
- **Unique Accounts:** 6 · **Unique Source IPs:** 4

## Authentication Baseline
- **Password Login Attempts:** 9 (2 success, 7 failure)
- **Security Control Events:** 2 (`account_lock` on `stu-117`, `rate_limit` on `203.0.113.42`)
- **Session Maintenance:** 1 (`refresh_token` for `stu-104`)

## Detections Triggered

| ID | Category | Source IP | Affected Accounts | Failures | Successes | Severity | Evidence |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **DET-01** | Brute-Force Attack | `198.51.100.27` | `stu-117` | 3 | 0 | **Medium** | EV-02, EV-03, EV-04, EV-05 |
| **DET-02** | Password Spraying | `203.0.113.42` | `stu-209, stu-311, stu-415, stu-502` | 4 | 0 | **High** | EV-06, EV-07, EV-08, EV-09, EV-10 |
| **DET-03** | Unusual Access | `192.0.2.99` | `stu-311` | 1 | 1 | **Medium** | EV-07, EV-12 |

## Severity Assessment
- **Overall Severity:** **High**
- **Rationale:** Overall incident severity is classified as High. Multiple targeted accounts (4 accounts in rapid password spraying from 203.0.113.42, plus 1 account receiving a 3-attempt brute-force burst from 198.51.100.27) justify High attention. While defensive controls (account_lock and rate_limit) fired, stu-311 recorded a subsequent successful login from a new IP/device (EV-12); because post-login audit logs and user confirmation are absent, compromise remains unconfirmed and requires verification.
