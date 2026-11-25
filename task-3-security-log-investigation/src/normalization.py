"""Log normalization and data-quality reporting for authentication records."""

import ipaddress
from typing import Any
import pandas as pd

ACTION_MAP = {
    "password_login": "password_login",
    "login": "password_login",
    "refresh_token": "refresh_token",
    "token_refresh": "refresh_token",
    "account_lock": "account_lock",
    "lockout": "account_lock",
    "rate_limit": "rate_limit",
}

EVENT_CATEGORY_MAP = {
    "password_login": "authentication",
    "refresh_token": "session_maintenance",
    "account_lock": "security_control",
    "rate_limit": "security_control",
}

RESULT_MAP = {
    "success": "success",
    "succeeded": "success",
    "ok": "success",
    "failure": "failure",
    "fail": "failure",
    "failed": "failure",
    "blocked": "blocked",
    "deny": "blocked",
    "denied": "blocked",
}

DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def normalize_timestamp(raw_value: str) -> tuple[Any, str, bool]:
    """Parse raw timestamp into timezone-aware UTC datetime and ISO-8601 string."""
    cleaned = str(raw_value).strip()
    if not cleaned:
        return pd.NaT, "", False

    parsed = pd.to_datetime(cleaned, utc=True, errors="coerce")
    if pd.isna(parsed):
        return pd.NaT, "", False

    return parsed, parsed.strftime("%Y-%m-%dT%H:%M:%SZ"), True


def normalize_ip(raw_value: str) -> tuple[str, int | None, bool, bool]:
    """Validate and normalize IP address via Python's ipaddress module."""
    cleaned = str(raw_value).strip()
    if not cleaned:
        return "", None, False, False

    try:
        ip_obj = ipaddress.ip_address(cleaned)
        is_doc = any(ip_obj in net for net in DOC_NETWORKS) if ip_obj.version == 4 else False
        return str(ip_obj), ip_obj.version, True, is_doc
    except ValueError:
        return "", None, False, False


def normalize_account(raw_value: str) -> str:
    """Normalize account identifier consistently while preserving original value separately."""
    return str(raw_value).strip().lower()


def normalize_action(raw_value: str) -> tuple[str, str]:
    """Standardize authentication/control event names and assign an event category."""
    cleaned = str(raw_value).strip().lower()
    if not cleaned:
        return "", "unknown"
    action = ACTION_MAP.get(cleaned, cleaned)
    category = EVENT_CATEGORY_MAP.get(action, "other")
    return action, category


def normalize_result(raw_value: str) -> str:
    """Standardize result strings into success, failure, blocked, or unknown."""
    cleaned = str(raw_value).strip().lower()
    if not cleaned:
        return ""
    return RESULT_MAP.get(cleaned, "unknown")


def normalize_device(raw_value: str) -> str:
    """Standardize device label while preserving 'unknown' explicitly."""
    cleaned = str(raw_value).strip().lower()
    return cleaned if cleaned else "missing"


def normalize_logs(raw_df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    """
    Normalize raw authentication logs into a separate DataFrame without deleting records.
    Returns (normalized_df, data_quality_summary).
    """
    transformation_log = [
        "Preserved all original columns with 'raw_' prefix and added stable 'evidence_id' (EV-01..EV-N).",
        "Parsed 'timestamp' into timezone-aware UTC timestamps (ISO-8601 'timestamp_utc') via pandas.to_datetime(utc=True).",
        "Validated and canonicalized 'source_ip' using Python's ipaddress.ip_address() and flagged RFC 5737 documentation IPs.",
        "Normalized 'user_id' into lowercase trimmed 'account_normalized' without altering 'raw_user_id'.",
        "Standardized 'event' into 'action_normalized' and classified into 'event_category' (authentication vs security_control vs session_maintenance).",
        "Standardized 'result' into 'result_normalized' (success, failure, blocked, unknown).",
        "Retained all rows and flagged duplicates explicitly instead of silently dropping records.",
    ]

    records: list[dict[str, Any]] = []
    source_cols = [c for c in raw_df.columns if c not in {"evidence_id", "raw_row_number"}]
    dup_series = raw_df.duplicated(subset=source_cols, keep="first")

    for idx, row in raw_df.iterrows():
        raw_ts = str(row.get("timestamp", ""))
        raw_user = str(row.get("user_id", ""))
        raw_ip = str(row.get("source_ip", ""))
        raw_event = str(row.get("event", ""))
        raw_result = str(row.get("result", ""))
        raw_device = str(row.get("device", ""))

        ts_dt, ts_iso, ts_valid = normalize_timestamp(raw_ts)
        ip_norm, ip_ver, ip_valid, is_doc_ip = normalize_ip(raw_ip)
        account_norm = normalize_account(raw_user)
        action_norm, event_cat = normalize_action(raw_event)
        result_norm = normalize_result(raw_result)
        device_norm = normalize_device(raw_device)
        is_dup = bool(dup_series.loc[idx])

        notes: list[str] = []
        if not ts_valid:
            notes.append("invalid_or_missing_timestamp")
        if not ip_valid:
            notes.append("invalid_or_missing_ip")
        if not account_norm:
            notes.append("missing_account")
        if not action_norm:
            notes.append("missing_action")
        if not result_norm or result_norm == "unknown":
            notes.append("missing_or_unknown_result")
        if device_norm == "unknown":
            notes.append("device_reported_as_unknown")
        if is_dup:
            notes.append("exact_duplicate_record")

        is_valid_record = bool(
            ts_valid
            and ip_valid
            and account_norm
            and action_norm
            and result_norm in {"success", "failure", "blocked"}
        )

        records.append(
            {
                "evidence_id": row["evidence_id"],
                "raw_row_number": int(row["raw_row_number"]),
                "timestamp_utc": ts_iso,
                "timestamp_dt": ts_dt,
                "timestamp_valid": ts_valid,
                "source_ip_normalized": ip_norm,
                "ip_version": ip_ver if ip_ver is not None else "",
                "ip_valid": ip_valid,
                "is_documentation_ip": is_doc_ip,
                "account_normalized": account_norm,
                "action_normalized": action_norm,
                "event_category": event_cat,
                "result_normalized": result_norm,
                "device_normalized": device_norm,
                "is_duplicate": is_dup,
                "is_valid_record": is_valid_record,
                "normalization_notes": "; ".join(notes) if notes else "clean",
                "raw_timestamp": raw_ts,
                "raw_user_id": raw_user,
                "raw_source_ip": raw_ip,
                "raw_event": raw_event,
                "raw_result": raw_result,
                "raw_device": raw_device,
            }
        )

    norm_df = pd.DataFrame(records)

    missing_values = {
        col: int((raw_df[col].astype(str).str.strip() == "").sum())
        for col in source_cols
    }
    invalid_ts_count = int((~norm_df["timestamp_valid"]).sum())
    invalid_ip_count = int((~norm_df["ip_valid"]).sum())
    duplicate_count = int(norm_df["is_duplicate"].sum())
    valid_count = int(norm_df["is_valid_record"].sum())

    excluded = norm_df.loc[~norm_df["is_valid_record"], ["evidence_id", "normalization_notes"]].to_dict(
        orient="records"
    )

    summary = {
        "total_input_records": int(len(raw_df)),
        "valid_records": valid_count,
        "duplicate_records": duplicate_count,
        "missing_values_by_field": missing_values,
        "invalid_timestamps": invalid_ts_count,
        "invalid_ip_addresses": invalid_ip_count,
        "excluded_records_count": len(excluded),
        "excluded_records": excluded,
        "unknown_device_records": int((norm_df["device_normalized"] == "unknown").sum()),
        "documentation_ip_records": int(norm_df["is_documentation_ip"].sum()),
        "transformation_log": transformation_log,
    }
    return norm_df, summary
