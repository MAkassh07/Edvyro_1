# Project Overview: Threat Model and Secure Configuration (SecureVault)

## Executive Summary

This project presents a defensive security assessment, threat model, risk register, prioritized hardening plan, and verification checklist for **SecureVault**, a lightweight personal note-taking and account management web application.

The assessment applies industry-standard frameworks—including the **STRIDE** threat modeling methodology, qualitative-quantitative risk scoring (**Likelihood × Impact**), and **OWASP Application Security Verification Standard (ASVS)** controls—to identify hypothetical security threats before deployment and establish an actionable defense-in-depth roadmap.

## Scope and Target Application

**SecureVault** is modeled with the following functional scope and technical stack:

| Attribute | Specification |
| :--- | :--- |
| **Application Name** | SecureVault |
| **Core Capabilities** | User registration, login/logout, personal dashboard, personal notes CRUD, account profile updates, password reset |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript |
| **Backend** | Python Flask |
| **Database** | SQLite (embedded local file database) |
| **Authentication** | Email address and password |
| **Session Management** | Signed, cookie-based HTTP sessions |
| **External Dependency** | External email delivery service for password reset notifications |

## Assessment Methodology

1. **System Decomposition & DFD Mapping**: Identify external actors, internal processing components, data stores, data flows, and five distinct trust boundaries.
2. **STRIDE Threat Enumeration**: Evaluate Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege scenarios across each component and trust boundary.
3. **Risk Prioritization**: Score hypothetical risks on a 1–25 scale (`Likelihood × Impact`) to classify severity (`Low`, `Medium`, `High`, `Critical`).
4. **Phased Hardening Plan**: Organize practical defensive controls into three implementation phases (Critical Fixes, Important Improvements, Additional Hardening).
5. **Security Verification**: Define observable verification procedures and expected outcomes without fabricating test results.

## Assessment Boundaries and Disclaimer

- All vulnerabilities and attack scenarios described in this repository are **hypothetical threats** derived from architectural modeling of the SecureVault stack.
- This documentation does **not** claim that SecureVault has undergone penetration testing or dynamic vulnerability scanning.
- Verification statuses are initialized to **Not tested** until an operator executes the verification procedures against a live or staging deployment.
