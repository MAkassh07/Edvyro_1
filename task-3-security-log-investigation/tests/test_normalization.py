"""Unit tests for log ingestion and normalization using synthetic fixtures."""

import pandas as pd
from src.normalization import (
    normalize_ip,
    normalize_logs,
    normalize_result,
    normalize_timestamp,
)


def _make_raw_df(rows):
    df = pd.DataFrame(rows)
    df.insert(0, "raw_row_number", range(2, len(df) + 2))
    df.insert(0, "evidence_id", [f"EV-{i:02d}" for i in range(1, len(df) + 1)])
    return df


def test_timestamp_normalization_preserves_utc():
    dt, iso, valid = normalize_timestamp("2026-08-01T09:00:12+02:00")
    assert valid is True
    assert not pd.isna(dt)
    assert iso == "2026-08-01T07:00:12Z"


def test_invalid_timestamp_is_flagged_not_silently_dropped():
    raw = _make_raw_df(
        [
            {
                "timestamp": "not-a-timestamp",
                "user_id": "stu-999",
                "source_ip": "192.0.2.10",
                "event": "password_login",
                "result": "failure",
                "device": "linux",
            }
        ]
    )
    norm_df, summary = normalize_logs(raw)
    assert len(norm_df) == 1
    assert bool(norm_df.loc[0, "timestamp_valid"]) is False
    assert bool(norm_df.loc[0, "is_valid_record"]) is False
    assert summary["invalid_timestamps"] == 1
    assert summary["excluded_records_count"] == 1


def test_ip_address_validation_and_canonicalization():
    ip_norm, ver, valid, is_doc = normalize_ip("203.0.113.42")
    assert valid is True
    assert ip_norm == "203.0.113.42"
    assert ver == 4
    assert is_doc is True

    _, _, bad_valid, _ = normalize_ip("999.999.1.1")
    assert bad_valid is False


def test_missing_field_and_duplicate_record_detection():
    row = {
        "timestamp": "2026-08-01T10:00:00Z",
        "user_id": "Stu-100",
        "source_ip": "192.0.2.5",
        "event": "password_login",
        "result": "FAILURE",
        "device": "",
    }
    raw = _make_raw_df([row, row.copy()])
    norm_df, summary = normalize_logs(raw)

    assert summary["total_input_records"] == 2
    assert summary["duplicate_records"] == 1
    assert summary["missing_values_by_field"]["device"] == 1 or summary["missing_values_by_field"]["device"] == 2
    assert bool(norm_df.loc[0, "is_duplicate"]) is False
    assert bool(norm_df.loc[1, "is_duplicate"]) is True
    assert norm_df.loc[0, "account_normalized"] == "stu-100"
    assert norm_df.loc[0, "raw_user_id"] == "Stu-100"
    assert norm_df.loc[0, "device_normalized"] == "missing"


def test_authentication_result_normalization():
    assert normalize_result("SUCCESS") == "success"
    assert normalize_result("failed") == "failure"
    assert normalize_result("DENIED") == "blocked"
    assert normalize_result("unexpected_value") == "unknown"
