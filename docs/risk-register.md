# Risk Register — SecureVault

> **Assessment Scope Notice:** Risk ratings below evaluate **hypothetical threat scenarios** identified during architectural threat modeling of SecureVault. They represent potential impact and likelihood in an unhardened baseline configuration and serve to prioritize defensive engineering work.

---

## 1. Risk Scoring Methodology

Every identified threat is evaluated using a standard two-factor matrix:

- **Likelihood (1–5):** Probability of exploitation in an unhardened deployment given attack complexity, exposure across trust boundaries, and attacker motivation.
  - `1` Rare · `2` Unlikely · `3` Possible · `4` Likely · `5` Very Likely
- **Impact (1–5):** Severity of damage to user confidentiality, data integrity, service availability, or organizational trust.
  - `1` Negligible · `2` Minor · `3` Moderate · `4` Major · `5` Severe
- **Risk Score:** $\text{Likelihood} \times \text{Impact}$ (Range: **1–25**)

### Severity Classification Scale

| Risk Score Range | Severity Level | Remediation Expectations |
| :---: | :---: | :--- |
| **17 – 25** | **Critical** | Immediate remediation required prior to any deployment (Phase 1). |
| **10 – 16** | **High** | High-priority engineering fix scheduled in Phase 1 or early Phase 2. |
| **5 – 9** | **Medium** | Important defense-in-depth improvement scheduled in Phase 2. |
| **1 – 4** | **Low** | Operational hardening and continuous maintenance in Phase 3. |

---

## 2. Prioritized Risk Register (Sorted Highest to Lowest Score)

| Risk ID | Threat Category (STRIDE) | Asset Affected | Hypothetical Risk Description | L | I | Score | Severity | Recommended Mitigation | Priority |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- | :---: |
| **RISK-01** | Tampering / Info Disclosure | SQLite Database, All User Data | **SQL Injection (SQLi):** Unparameterized query construction allows attackers to bypass login, read all users' notes, or corrupt database records. | 4 | 5 | **20** | **Critical** | Use parameterized SQL queries (`?` placeholders) exclusively across all database calls and validate input types server-side. | **P1** |
| **RISK-02** | Tampering / Info Disclosure | Personal Notes (`A-02`) | **Insecure Direct Object Reference (IDOR):** Missing server-side ownership checks on note endpoints allow authenticated users to read, modify, or delete another user's notes by altering note IDs. | 4 | 5 | **20** | **Critical** | Enforce `WHERE id = ? AND user_id = ?` on every note query and verify authenticated session identity server-side. | **P1** |
| **RISK-03** | Elevation of Privilege | Admin Controls, User Accounts | **Improper Role Validation / Mass Assignment:** Accepting role attributes from profile update payloads or missing `@admin_required` checks allows normal users to escalate to Administrator. | 4 | 5 | **20** | **Critical** | Allowlist mutable profile fields explicitly, ignore client-supplied role parameters, and enforce server-side RBAC decorators on admin routes. | **P1** |
| **RISK-04** | Spoofing / Info Disclosure | User Credentials (`A-01`) | **Weak or Unsalted Password Hashing:** Storing plaintext or fast-hashed (MD5/SHA-1) passwords enables rapid offline cracking if `securevault.db` is leaked. | 3 | 5 | **15** | **High** | Hash all passwords using Argon2id (or bcrypt with cost $\ge 12$) with unique per-user cryptographic salts. | **P1** |
| **RISK-05** | Spoofing / Info Disclosure | Session Cookies (`A-03`) | **Session Hijacking & Cookie Theft:** Missing `HttpOnly`, `Secure`, or `SameSite` flags, or transmitting cookies over plaintext HTTP, allows interception or XSS-based theft of active sessions. | 3 | 5 | **15** | **High** | Enforce HTTPS, configure `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE='Lax'`, and rotate sessions on login. | **P1** |
| **RISK-06** | Elevation of Privilege / Spoofing | Password Reset Tokens (`A-04`) | **Password Reset Token Abuse:** Predictable, non-expiring, or reusable reset tokens allow attackers to hijack accounts—including administrators—via token guessing or replay. | 3 | 5 | **15** | **High** | Generate tokens with `secrets.token_urlsafe(32)`, store SHA-256 token hashes, enforce 15-minute TTL, and invalidate immediately after single use. | **P1** |
| **RISK-07** | Spoofing / Denial of Service | Auth Module, User Accounts | **Brute-Force & Credential Stuffing:** Absence of rate limiting on `/login` and `/forgot-password` enables automated password guessing and email quota exhaustion. | 4 | 3 | **12** | **High** | Apply IP and account-based rate limiting (`Flask-Limiter`) on login, registration, and password reset endpoints. | **P1** |
| **RISK-08** | Tampering | User Notes & Account Settings | **Cross-Site Request Forgery (CSRF):** State-changing POST/PUT/DELETE endpoints without CSRF tokens allow malicious third-party sites to trigger unintended note deletions or email changes. | 3 | 4 | **12** | **High** | Implement synchronizer CSRF tokens (`Flask-WTF` / `CSRFProtect`) on all forms and state-changing requests alongside `SameSite` cookies. | **P2** |
| **RISK-09** | Information Disclosure | Flask Server, Schema Details | **Verbose Error Messages & Debug Exposure:** Running Flask with `DEBUG=True` or returning raw exceptions leaks stack traces, SQLite schemas, and filesystem paths. | 3 | 3 | **9** | **Medium** | Disable debug mode in production, register generic JSON/HTML error handlers, and log full diagnostics server-side only. | **P2** |
| **RISK-10** | Information Disclosure / Tampering | Web Browser, User Sessions | **Cross-Site Scripting (XSS) & Missing Security Headers:** Unescaped note rendering or missing Content Security Policy (`CSP`) enables malicious script execution in victims' browsers. | 2 | 4 | **8** | **Medium** | Use automatic context-aware output escaping (`textContent` / Jinja2 autoescape) and deploy strict `CSP`, `X-Content-Type-Options`, and `X-Frame-Options` headers. | **P2** |
| **RISK-11** | Repudiation | Audit Logs (`A-06`) | **Insufficient Security Audit Logging:** Lack of structured logging for logins, failed auth, password resets, and admin actions prevents incident detection and forensic reconstruction. | 3 | 2 | **6** | **Medium** | Log authentication, authorization failures, and sensitive account mutations with UTC timestamps, actor IDs, and source IPs while redacting secrets. | **P2** |
| **RISK-12** | Denial of Service | SQLite Database, Flask Server | **Unbounded Payloads & Outdated Dependencies:** Missing `MAX_CONTENT_LENGTH`, lack of SQLite backup strategy, or unpatched Python packages risk storage exhaustion and known CVEs. | 2 | 2 | **4** | **Low** | Enforce `MAX_CONTENT_LENGTH`, automate encrypted SQLite backups, set idle/absolute session timeouts, and run `pip-audit` dependency checks. | **P3** |

---

## 3. Rationale for Prioritizing Highest-Risk Items First

Addressing **Critical (Score 17–25)** and **High (Score 10–16)** risks first delivers the greatest immediate risk reduction per engineering hour:

1. **Systemic Blast Radius:** `RISK-01` (SQL Injection), `RISK-02` (IDOR), and `RISK-03` (Privilege Escalation) each carry an Impact score of `5` because a single successful exploit compromises **all users' confidentiality and integrity** rather than affecting just one isolated session.
2. **Low Attacker Barrier:** Without parameterized queries, ownership checks, or login rate limiting, an attacker needs minimal tooling (a browser DevTools proxy or basic script) to probe for IDOR, SQLi, or password brute-forcing across the Public Internet Trust Boundary.
3. **Foundation Before Polish:** Defense-in-depth controls such as security headers (`RISK-10`) and audit logging (`RISK-11`) are essential, but they cannot compensate for broken authentication, missing authorization checks, or plaintext credentials (`RISK-04`). Securing the core data and access boundaries in **Phase 1** establishes a trustworthy baseline before layering **Phase 2** and **Phase 3** controls.
