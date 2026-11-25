# Detection Rules Specification — Security Log Investigation

All detection rules in `src/detection_rules.py` are deterministic, transparent, and configurable via Python dataclasses. No machine learning or unimplemented anomaly scoring is claimed.

---

## Rule A: Password Spraying (`PasswordSprayingConfig`)

- **MITRE ATT&CK Reference:** [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- **Target Events:** `action_normalized == "password_login"` AND `result_normalized == "failure"`
- **Default Thresholds:**
  - `window_minutes = 15`
  - `min_distinct_accounts = 3`
  - `min_total_failures = 3`
  - `max_failures_per_account = 2`
- **Threshold Rationale:** In a compact sample of 12 events across 6 unique accounts, requiring $\ge 3$ distinct targeted accounts from one IP within 15 minutes while capping attempts per account at $\le 2$ isolates horizontal spraying (low attempts per account across many accounts) from vertical single-account brute force. In high-volume production environments, this threshold should be tuned higher (e.g., $\ge 10$ distinct accounts or dynamic percentage of active directory users) to reduce false positives behind corporate NAT gateways.

---

## Rule B: Brute-Force Attack (`BruteForceConfig`)

- **MITRE ATT&CK Reference:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- **Target Events:** `action_normalized == "password_login"` AND `result_normalized == "failure"`
- **Default Thresholds:**
  - `window_minutes = 15`
  - `min_failures = 3` (grouped per `(account_normalized, source_ip_normalized)`)
- **Threshold Rationale:** Three consecutive failed password attempts within 15 minutes from a single IP against one account matches the dataset's rapid burst pattern (`stu-117` receiving 3 failures in 34 seconds before `account_lock` fired). The rule also checks whether a subsequent `password_login` `success` or `account_lock` occurred to contextualize severity.

---

## Rule C: Unusual Access (`UnusualAccessConfig`)

- **Target Events:** `action_normalized == "password_login"` AND `result_normalized == "success"`
- **Default Thresholds:**
  - `prior_failure_lookback_hours = 24`
  - `flag_on_prior_failure = True`
  - `flag_on_new_ip_after_activity = True`
- **Analyst Safeguard:** A successful login from a new IP address or device after an earlier failure is **not** proof of account compromise—it could reflect the legitimate user authenticating later from a mobile network or personal phone. Rule C flags such events strictly as **suspicious successes requiring verification**.
