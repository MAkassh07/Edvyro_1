# Incident Response Recommendations — Security Log Investigation

> **Scope Note:** All items below are **recommended defensive actions** derived from the log investigation. Because this is a static synthetic dataset, none of these actions have been executed against a live environment.

---

## Phase 1 — Immediate Response

| Problem Addressed | Recommended Action | Priority | Verification Method |
| :--- | :--- | :---: | :--- |
| **Unverified subsequent success on `stu-311` (`EV-12`)** | Contact the owner of `stu-311` via an out-of-band verified channel to confirm whether they initiated the `11:47:09Z` login from `192.0.2.99` (`ios`). | **P1** | Documented user confirmation ticket or call log. |
| **Potential unauthorized session on `stu-311`** | If `EV-12` cannot be confirmed by the user, immediately revoke active `stu-311` refresh/session tokens and force a password reset. | **P1** | Confirm old refresh tokens return `401` and password hash updated. |
| **Suspicious activity from `203.0.113.42` and `198.51.100.27`** | Review full historical server/proxy logs for both source IPs across a wider timeframe (beyond the 2h 47m sample). | **P1** | Query centralized log store for any additional hits from both IPs. |
| **Evidence preservation** | Preserve read-only copies of `authentication-log-sample.csv`, SHA-256 checksums, and any supporting application logs. | **P1** | Verify checksum match on archived evidence files. |

---

## Phase 2 — Containment

| Problem Addressed | Recommended Action | Priority | Verification Method |
| :--- | :--- | :---: | :--- |
| **Password spraying from `203.0.113.42` (`EV-06`–`EV-09`)** | Tune per-IP rate limiting so multi-account spraying triggers blocks earlier (before 4 accounts are probed) and apply temporary IP throttling/blocking at the WAF or reverse proxy. | **P1** | Automated test confirming 4th distinct-account failure triggers HTTP `429`. |
| **Brute-force burst on `stu-117` (`EV-02`–`EV-04`)** | Confirm `account_lock` expiration policy and notify `stu-117` of the blocked attempts while checking whether MFA is enrolled. | **P2** | Inspect lockout configuration and user MFA enrollment status. |
| **Targeted accounts (`stu-117`, `stu-209`, `stu-311`, `stu-415`, `stu-502`)** | Enable heightened monitoring for password resets, new device logins, or token refreshes across all five targeted accounts. | **P2** | Verify temporary alert rule active in SIEM/log monitor. |

---

## Phase 3 — Long-Term Improvements

| Problem Addressed | Recommended Action | Priority | Verification Method |
| :--- | :--- | :---: | :--- |
| **Missing post-login & MFA telemetry** | Enforce Multi-Factor Authentication (MFA) for all user accounts and log MFA challenge outcomes alongside `password_login` events. | **P1** | Audit MFA policy enforcement and confirm MFA fields appear in auth logs. |
| **Limited device/context visibility (`device=unknown`)** | Centralize authentication logs with User-Agent, TLS/ASN context, correlation IDs, and post-login audit events (profile changes, note access). | **P2** | Inspect centralized log schema for required forensic fields. |
| **Manual log inspection lag** | Deploy automated SIEM alerts matching the documented Password Spraying, Brute-Force, and Unusual Access rules. | **P2** | Trigger synthetic test events in staging and confirm alert delivery. |
| **Abuse-resistant throttling** | Pair IP rate limits with progressive exponential backoff rather than indefinite lockouts that attackers can abuse for DoS. | **P3** | Run `pytest` rate-limit and backoff regression tests. |
| **Operational readiness** | Maintain an updated Incident Response playbook defining escalation paths, session revocation steps, and user verification workflows. | **P3** | Conduct semi-annual tabletop exercise with engineering and SOC staff. |
