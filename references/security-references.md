# Security References

All threat scenarios, risk classifications, secure configuration recommendations, and verification procedures in this project are grounded in established defensive cybersecurity standards and vendor-neutral documentation.

## Core Threat Modeling & Application Security Standards

| Standard / Resource | Organization | Scope & Relevance to SecureVault | Official URL |
| :--- | :--- | :--- | :--- |
| **OWASP Top 10 (2021)** | OWASP Foundation | Primary baseline for web application risk categories (Broken Access Control, Cryptographic Failures, Injection, Security Misconfiguration). | https://owasp.org/www-project-top-ten/ |
| **OWASP Application Security Verification Standard (ASVS)** | OWASP Foundation | Detailed verification requirements for authentication, session management, access control, validation, and error handling. | https://owasp.org/www-project-application-security-verification-standard/ |
| **NIST Cybersecurity Framework (CSF) 2.0** | National Institute of Standards and Technology | Organizational risk management lifecycle (Govern, Identify, Protect, Detect, Respond, Recover). | https://www.nist.gov/cyberframework |
| **STRIDE Threat Modeling Methodology** | Microsoft Security Development Lifecycle | Six-category threat classification framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). | https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats |
| **MITRE CWE (Common Weakness Enumeration)** | MITRE Corporation | Standardized taxonomy of software weaknesses (e.g., CWE-89 SQL Injection, CWE-79 XSS, CWE-639 IDOR, CWE-352 CSRF). | https://cwe.mitre.org/ |

## OWASP Cheat Sheet Series (Implementation Guidance)

| Cheat Sheet | Specific Controls Applied in Hardening Plan | Official URL |
| :--- | :--- | :--- |
| **Password Storage Cheat Sheet** | Argon2id / bcrypt hashing parameters, work factors, and salting. | https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html |
| **Session Management Cheat Sheet** | `HttpOnly`, `Secure`, `SameSite` cookie flags, idle/absolute timeouts, session regeneration on login. | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html |
| **SQL Injection Prevention Cheat Sheet** | Parameterized queries (prepared statements) in Python `sqlite3` / SQLAlchemy. | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html |
| **Cross-Site Request Forgery (CSRF) Prevention Cheat Sheet** | Synchronizer token pattern and `SameSite` cookie enforcement for state-changing Flask routes. | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html |
| **Forgot Password Cheat Sheet** | Cryptographically random single-use reset tokens, short TTLs, generic user responses, hashed token storage. | https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html |
| **HTTP Headers Cheat Sheet** | Content Security Policy (CSP), `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`. | https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html |
| **Logging Cheat Sheet** | Structured security audit events, sensitive data redaction, log integrity protection. | https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html |
| **Authorization Cheat Sheet** | Server-side object ownership checks (preventing IDOR) and role-based access enforcement. | https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html |

## Platform & Language Security Documentation

| Resource | Maintainer | Relevance to SecureVault | Official URL |
| :--- | :--- | :--- | :--- |
| **Flask Security Considerations** | Pallets Projects (Flask) | Session cookie configuration, template escaping, SECRET_KEY management, proxy handling. | https://flask.palletsprojects.com/en/stable/security/ |
| **Python `sqlite3` Documentation** | Python Software Foundation | Parameterized query placeholders (`?`) and safe connection handling. | https://docs.python.org/3/library/sqlite3.html |
| **NIST SP 800-63B (Digital Identity Guidelines)** | NIST | Password complexity, rate-limiting authentication attempts, and session re-authentication. | https://pages.nist.gov/800-63-3/sp800-63b.html |
