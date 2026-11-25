# Security Log Investigation — Task 3

**Track:** Cyber Security · **Task:** TASK-3 · **Level:** Beginner-Friendly  
**Repository:** [https://github.com/MAkassh07/Edvyro_1](https://github.com/MAkassh07/Edvyro_1)

---

## 1. Project Overview

This project performs a reproducible defensive security log investigation against the supplied authentication dataset (`data/authentication-log-sample.csv`). Building upon the threat model in Task 1 and the hardened authentication controls in Task 2, Task 3 demonstrates log ingestion, normalization, baseline profiling, deterministic rule detection, incident timeline reconstruction, evidence-versus-assumption analysis, and incident response planning.

---

## 2. Investigation Objective

- Preserve original log evidence read-only while producing a separate normalized dataset.
- Establish an accurate authentication baseline distinguishing login attempts from automated control actions (`account_lock`, `rate_limit`).
- Detect **Password Spraying**, **Brute-Force Attacks**, and **Unusual Access** using configurable, transparent rules.
- Reconstruct a strictly chronological incident timeline backed by `EV-01`..`EV-12` evidence pointers.
- Separate **Confirmed Evidence**, **Analyst Inference**, and **Unverified Assumptions**.
- Produce an executable Jupyter notebook, Matplotlib visualizations, ReportLab PDF incident report, and passing `pytest` unit tests.

---

## 3. Dataset Source & Limitations

- **Official Source:** `https://edvyro.in/datasets/source-materials/authentication-log-sample.csv`
- **Local Preserved Copy:** [`data/authentication-log-sample.csv`](data/authentication-log-sample.csv) (12 event records, 6 columns: `timestamp`, `user_id`, `source_ip`, `event`, `result`, `device`)
- **Dataset Limitations:**
  - Compact 2-hour 47-minute sample window (`2026-08-01T09:00:12Z` to `2026-08-01T11:47:09Z`).
  - Uses synthetic RFC 5737 documentation IPv4 addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so real-world geolocation/ASN attribution is not applicable.
  - Lacks User-Agent strings, MFA telemetry, and post-authentication activity logs (e.g., data access or password changes), meaning account compromise cannot be proven from these logs alone.

---

## 4. Technologies Used

- **Python 3** · **Pandas** (log ingestion, normalization, and aggregation)
- **Python `ipaddress`** (IPv4 validation and documentation-range tagging)
- **Matplotlib** (6 baseline, detection, and timeline charts)
- **ReportLab** (multi-page PDF incident report generation)
- **Jupyter Notebook (`nbformat` / `nbconvert`)** (reproducible end-to-end analysis)
- **`pytest`** (10 deterministic unit tests)

---

## 5. Investigation Methodology & Normalization Approach

Full methodology is documented in [`docs/investigation-methodology.md`](docs/investigation-methodology.md):

1. Load `data/authentication-log-sample.csv` read-only with `dtype=str` and assign `EV-01`..`EV-12` evidence IDs.
2. Parse timestamps to timezone-aware UTC ISO-8601 (`timestamp_utc`), validate IPs via `ipaddress`, lowercase/trim account IDs into `account_normalized`, and separate `event` into `action_normalized` and `event_category` (`authentication`, `session_maintenance`, `security_control`).
3. Retain every row in [`data/normalized-authentication-logs.csv`](data/normalized-authentication-logs.csv) with explicit validity and duplicate flags (`0` duplicates, `0` invalid timestamps, `0` invalid IPs, `4` rows with `device='unknown'`).

---

## 6. Detection Logic & Findings Summary

Configurable rule definitions live in [`src/detection_rules.py`](src/detection_rules.py) and [`docs/detection-rules.md`](docs/detection-rules.md). Running the pipeline on the 12 actual log records produced:

- **Baseline Summary:** `9` `password_login` attempts (`2` successes, `7` failures), `2` security control events (`EV-05` `account_lock`, `EV-10` `rate_limit`), `1` `refresh_token` event (`EV-11`), `6` unique accounts, and `4` unique source IPs.

| Detection ID | Category | Source IP | Affected Account(s) | Failures / Successes | Severity | Confidence | Evidence |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **DET-01** | Brute-Force Attack | `198.51.100.27` | `stu-117` | 3 / 0 | **Medium** | High | `EV-02, EV-03, EV-04, EV-05` |
| **DET-02** | Password Spraying | `203.0.113.42` | `stu-209, stu-311, stu-415, stu-502` | 4 / 0 | **High** | High | `EV-06, EV-07, EV-08, EV-09, EV-10` |
| **DET-03** | Unusual Access | `192.0.2.99` | `stu-311` | 1 / 1 | **Medium** | Medium | `EV-07, EV-12` |

---

## 7. Incident Timeline & Evidence vs. Assumptions

- **09:00:12Z (`EV-01`) & 10:15:32Z (`EV-11`):** Baseline activity for `stu-104` from `192.0.2.18` (`android`).
- **09:03:44Z–09:05:03Z (`EV-02`–`EV-05`):** Three rapid `password_login` failures against `stu-117` from `198.51.100.27` (`windows`), stopped by server `account_lock` (`EV-05`).
- **09:21:10Z–09:22:01Z (`EV-06`–`EV-10`):** Horizontal password spray from `203.0.113.42` (`unknown` device) across `stu-209`, `stu-311`, `stu-415`, and `stu-502` within 12 seconds, triggering `rate_limit` (`EV-10`).
- **11:47:09Z (`EV-12`):** `stu-311` succeeds via `password_login` from `192.0.2.99` (`ios`). **Assessment:** Flagged as a suspicious success requiring out-of-band user verification—not definitive proof of compromise.

---

## 8. Severity Assessment & Response Recommendations

- **Overall Incident Severity:** **High** (multi-account spray + targeted brute-force burst + one subsequent unverified success on a sprayed account; compromise unconfirmed due to missing post-login telemetry).
- **Response Plan:** See [`docs/incident-response-recommendations.md`](docs/incident-response-recommendations.md) for Phase 1 Immediate Response, Phase 2 Containment, and Phase 3 Long-Term Improvements.

---

## 9. Key Project Deliverables (Direct Links)

- **Executable Jupyter Notebook:** [`notebooks/security_log_investigation.ipynb`](notebooks/security_log_investigation.ipynb)
- **Incident Report PDF:** [`reports/incident_report.pdf`](reports/incident_report.pdf)
- **Normalized Logs CSV:** [`data/normalized-authentication-logs.csv`](data/normalized-authentication-logs.csv)
- **Detection Results CSV:** [`evidence/detection-results.csv`](evidence/detection-results.csv)
- **Incident Timeline CSV:** [`evidence/incident-timeline.csv`](evidence/incident-timeline.csv)
- **Investigation Summary & CLI Output:** [`evidence/investigation-summary.md`](evidence/investigation-summary.md) · [`evidence/analysis-output.txt`](evidence/analysis-output.txt)

---

## 10. Installation, Pipeline Execution & Testing Instructions

```powershell
# Inside task-3-security-log-investigation/ (Windows PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 1. Run full investigation pipeline (normalizes CSV, computes detections/timeline, builds charts & PDF)
python src/report_generator.py

# 2. Execute automated pytest unit tests
pytest -v

# 3. Execute or open Jupyter notebook
python -m nbconvert --to notebook --execute --inplace notebooks/security_log_investigation.ipynb
```

---

## 11. References

- **MITRE ATT&CK — Brute Force (T1110):** https://attack.mitre.org/techniques/T1110/
- **MITRE ATT&CK — Password Spraying (T1110.003):** https://attack.mitre.org/techniques/T1110/003/
- **OWASP Authentication Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **NIST SP 800-63B Digital Identity Guidelines:** https://pages.nist.gov/800-63-3/sp800-63b.html
- **CISA Multi-Factor Authentication & Account Security Guidance:** https://www.cisa.gov/MFA
