"""Unit tests for Password Spraying, Brute-Force, and Unusual Access detection rules."""

import pandas as pd
from src.detection_rules import (
    BruteForceConfig,
    PasswordSprayingConfig,
    UnusualAccessConfig,
    detect_brute_force,
    detect_password_spraying,
    detect_unusual_access,
    run_all_detections,
)
from src.normalization import normalize_logs


def _build_norm(rows):
    df = pd.DataFrame(rows)
    df.insert(0, "raw_row_number", range(2, len(df) + 2))
    df.insert(0, "evidence_id", [f"EV-{i:02d}" for i in range(1, len(df) + 1)])
    norm_df, _ = normalize_logs(df)
    return norm_df


def test_password_spraying_rule_triggers_on_multi_account_low_per_account():
    rows = [
        {"timestamp": "2026-08-01T09:00:00Z", "user_id": "u1", "source_ip": "203.0.113.9", "event": "password_login", "result": "failure", "device": "unknown"},
        {"timestamp": "2026-08-01T09:00:05Z", "user_id": "u2", "source_ip": "203.0.113.9", "event": "password_login", "result": "failure", "device": "unknown"},
        {"timestamp": "2026-08-01T09:00:10Z", "user_id": "u3", "source_ip": "203.0.113.9", "event": "password_login", "result": "failure", "device": "unknown"},
    ]
    norm_df = _build_norm(rows)
    dets = detect_password_spraying(norm_df, PasswordSprayingConfig(window_minutes=15, min_distinct_accounts=3, min_total_failures=3, max_failures_per_account=2))
    assert len(dets) == 1
    assert dets[0].detection_category == "Password Spraying"
    assert dets[0].failure_count == 3
    assert "u1" in dets[0].affected_accounts and "u3" in dets[0].affected_accounts


def test_brute_force_rule_triggers_and_ignores_account_lock_as_login_success():
    rows = [
        {"timestamp": "2026-08-01T09:01:00Z", "user_id": "u1", "source_ip": "198.51.100.5", "event": "password_login", "result": "failure", "device": "windows"},
        {"timestamp": "2026-08-01T09:01:10Z", "user_id": "u1", "source_ip": "198.51.100.5", "event": "password_login", "result": "failure", "device": "windows"},
        {"timestamp": "2026-08-01T09:01:20Z", "user_id": "u1", "source_ip": "198.51.100.5", "event": "password_login", "result": "failure", "device": "windows"},
        {"timestamp": "2026-08-01T09:01:30Z", "user_id": "u1", "source_ip": "198.51.100.5", "event": "account_lock", "result": "success", "device": "server"},
    ]
    norm_df = _build_norm(rows)
    dets = detect_brute_force(norm_df, BruteForceConfig(window_minutes=15, min_failures=3))
    assert len(dets) == 1
    assert dets[0].detection_category == "Brute-Force Attack"
    assert dets[0].failure_count == 3
    assert dets[0].success_count == 0
    assert "EV-04" in dets[0].supporting_event_ids


def test_unusual_access_rule_flags_success_after_prior_failure_and_new_ip():
    rows = [
        {"timestamp": "2026-08-01T09:00:00Z", "user_id": "u2", "source_ip": "203.0.113.10", "event": "password_login", "result": "failure", "device": "unknown"},
        {"timestamp": "2026-08-01T10:30:00Z", "user_id": "u2", "source_ip": "192.0.2.50", "event": "password_login", "result": "success", "device": "ios"},
        {"timestamp": "2026-08-01T10:40:00Z", "user_id": "u_clean", "source_ip": "192.0.2.51", "event": "password_login", "result": "success", "device": "android"},
    ]
    norm_df = _build_norm(rows)
    dets = detect_unusual_access(norm_df, UnusualAccessConfig(prior_failure_lookback_hours=24))
    assert len(dets) == 1
    assert dets[0].affected_accounts == "u2"
    assert dets[0].supporting_event_ids == "EV-01, EV-02"


def test_run_all_detections_assigns_deterministic_ids():
    rows = [
        {"timestamp": "2026-08-01T09:00:00Z", "user_id": "a1", "source_ip": "198.51.100.2", "event": "password_login", "result": "failure", "device": "windows"},
        {"timestamp": "2026-08-01T09:00:05Z", "user_id": "a1", "source_ip": "198.51.100.2", "event": "password_login", "result": "failure", "device": "windows"},
        {"timestamp": "2026-08-01T09:00:10Z", "user_id": "a1", "source_ip": "198.51.100.2", "event": "password_login", "result": "failure", "device": "windows"},
    ]
    norm_df = _build_norm(rows)
    det_df = run_all_detections(norm_df)
    assert list(det_df["detection_id"]) == ["DET-01"]
