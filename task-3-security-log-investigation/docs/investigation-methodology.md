# Investigation Methodology — Security Log Investigation

## 1. Investigation Approach

This investigation applies a structured, reproducible defensive SOC workflow to the supplied dataset (`data/authentication-log-sample.csv`):

1. **Evidence Preservation:** Load the raw CSV strictly read-only (`dtype=str`, `keep_default_na=False`), assign immutable `evidence_id` tags (`EV-01`..`EV-N`) and `raw_row_number` line pointers, and never overwrite the source CSV.
2. **Schema Inspection & Data Quality Audit:** Inspect exact column names (`timestamp`, `user_id`, `source_ip`, `event`, `result`, `device`), count missing fields, check for duplicates, and verify timestamp and IP validity.
3. **Normalization (`src/normalization.py`):**
   - Standardize timestamps to UTC ISO-8601 (`%Y-%m-%dT%H:%M:%SZ`).
   - Validate IPv4 addresses via Python's `ipaddress` library and flag RFC 5737 documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
   - Lowercase/trim account IDs into `account_normalized` while keeping `raw_user_id` intact.
   - Map `event` values (`password_login`, `refresh_token`, `account_lock`, `rate_limit`) into explicit `event_category` classes so defensive controls (`account_lock` with `result=success`) are never miscounted as user logins.
   - Write the normalized dataset separately to `data/normalized-authentication-logs.csv` without silently deleting any rows.
4. **Baseline Profiling (`src/timeline.py`):** Establish overall volume, login success vs. failure counts, active source IPs, targeted accounts, and security control triggers before evaluating detection rules.
5. **Deterministic Detection (`src/detection_rules.py`):** Execute transparent, threshold-based rules for Brute-Force Attacks, Password Spraying, and Unusual Access.
6. **Timeline & Evidence Separation (`src/timeline.py`):** Order events chronologically and explicitly separate **Confirmed Evidence**, **Analyst Inference**, and **Unverified Assumptions**.
