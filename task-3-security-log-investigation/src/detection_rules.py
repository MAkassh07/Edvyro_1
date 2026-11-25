"""Configurable, transparent detection rules for Password Spraying, Brute-Force, and Unusual Access."""

from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any
import pandas as pd


@dataclass(frozen=True)
class PasswordSprayingConfig:
    window_minutes: int = 15
    min_distinct_accounts: int = 3
    min_total_failures: int = 3
    max_failures_per_account: int = 2


@dataclass(frozen=True)
class BruteForceConfig:
    window_minutes: int = 15
    min_failures: int = 3


@dataclass(frozen=True)
class UnusualAccessConfig:
    prior_failure_lookback_hours: int = 24
    flag_on_prior_failure: bool = True
    flag_on_new_ip_after_activity: bool = True


@dataclass
class DetectionResult:
    detection_id: str
    detection_category: str
    source_ip: str
    affected_accounts: str
    first_observed: str
    last_observed: str
    attempt_count: int
    failure_count: int
    success_count: int
    threshold: str
    supporting_event_ids: str
    severity: str
    confidence: str
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _valid_events(norm_df: pd.DataFrame) -> pd.DataFrame:
    df = norm_df.loc[norm_df["is_valid_record"]].copy()
    if "timestamp_dt" not in df.columns or df["timestamp_dt"].dtype == object:
        df["timestamp_dt"] = pd.to_datetime(df["timestamp_utc"], utc=True, errors="coerce")
    return df.sort_values(["timestamp_dt", "evidence_id"]).reset_index(drop=True)


def detect_password_spraying(
    norm_df: pd.DataFrame,
    config: PasswordSprayingConfig | None = None,
) -> list[DetectionResult]:
    """Detect a single source IP failing authentication across multiple distinct accounts."""
    cfg = config or PasswordSprayingConfig()
    df = _valid_events(norm_df)
    failed_logins = df.loc[
        (df["action_normalized"] == "password_login") & (df["result_normalized"] == "failure")
    ]
    if failed_logins.empty:
        return []

    results: list[DetectionResult] = []
    window_delta = timedelta(minutes=cfg.window_minutes)

    for source_ip, ip_group in failed_logins.groupby("source_ip_normalized", sort=True):
        ip_group = ip_group.sort_values(["timestamp_dt", "evidence_id"]).reset_index(drop=True)

        # Find maximal sliding window matching thresholds
        best_window: pd.DataFrame | None = None
        for start_idx in range(len(ip_group)):
            start_ts = ip_group.loc[start_idx, "timestamp_dt"]
            end_ts = start_ts + window_delta
            sub = ip_group.loc[
                (ip_group["timestamp_dt"] >= start_ts) & (ip_group["timestamp_dt"] <= end_ts)
            ]
            distinct_accounts = sub["account_normalized"].nunique()
            max_per_account = int(sub.groupby("account_normalized").size().max())
            if (
                distinct_accounts >= cfg.min_distinct_accounts
                and len(sub) >= cfg.min_total_failures
                and max_per_account <= cfg.max_failures_per_account
            ):
                if best_window is None or len(sub) > len(best_window):
                    best_window = sub

        if best_window is None:
            continue

        accounts = sorted(best_window["account_normalized"].unique().tolist())
        first_ts = best_window["timestamp_dt"].min()
        last_ts = best_window["timestamp_dt"].max()

        # Check related defensive controls (rate_limit) and subsequent successes from this IP
        ip_all = df.loc[df["source_ip_normalized"] == source_ip]
        ip_successes = int(
            (
                (ip_all["action_normalized"] == "password_login")
                & (ip_all["result_normalized"] == "success")
            ).sum()
        )
        rate_limited = ip_all.loc[
            (ip_all["action_normalized"] == "rate_limit")
            & (ip_all["timestamp_dt"] >= first_ts)
        ]

        support_ids = best_window["evidence_id"].tolist() + rate_limited["evidence_id"].tolist()
        # Preserve chronological order without duplicates
        support_ids = list(dict.fromkeys(support_ids))

        control_note = (
            f" Defensive rate_limit triggered ({', '.join(rate_limited['evidence_id'].tolist())})."
            if not rate_limited.empty
            else " No defensive rate_limit event observed from this IP."
        )

        threshold_desc = (
            f">= {cfg.min_distinct_accounts} distinct accounts, >= {cfg.min_total_failures} failures, "
            f"<= {cfg.max_failures_per_account} failures/account within {cfg.window_minutes}m"
        )
        duration_sec = int((last_ts - first_ts).total_seconds())
        explanation = (
            f"Source IP {source_ip} recorded {len(best_window)} failed password_login attempts across "
            f"{len(accounts)} distinct accounts ({', '.join(accounts)}) within {duration_sec} seconds "
            f"(1–{int(best_window.groupby('account_normalized').size().max())} attempt(s) per account), "
            f"matching horizontal password spraying behavior.{control_note}"
        )

        results.append(
            DetectionResult(
                detection_id="",
                detection_category="Password Spraying",
                source_ip=str(source_ip),
                affected_accounts=", ".join(accounts),
                first_observed=first_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                last_observed=last_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                attempt_count=int(len(best_window) + ip_successes),
                failure_count=int(len(best_window)),
                success_count=ip_successes,
                threshold=threshold_desc,
                supporting_event_ids=", ".join(support_ids),
                severity="High",
                confidence="High",
                explanation=explanation,
            )
        )

    return results


def detect_brute_force(
    norm_df: pd.DataFrame,
    config: BruteForceConfig | None = None,
) -> list[DetectionResult]:
    """Detect repeated failed password_login attempts against the same account."""
    cfg = config or BruteForceConfig()
    df = _valid_events(norm_df)
    failed_logins = df.loc[
        (df["action_normalized"] == "password_login") & (df["result_normalized"] == "failure")
    ]
    if failed_logins.empty:
        return []

    results: list[DetectionResult] = []
    window_delta = timedelta(minutes=cfg.window_minutes)

    for (account, source_ip), group in failed_logins.groupby(
        ["account_normalized", "source_ip_normalized"], sort=True
    ):
        group = group.sort_values(["timestamp_dt", "evidence_id"]).reset_index(drop=True)
        best_window: pd.DataFrame | None = None
        for start_idx in range(len(group)):
            start_ts = group.loc[start_idx, "timestamp_dt"]
            end_ts = start_ts + window_delta
            sub = group.loc[
                (group["timestamp_dt"] >= start_ts) & (group["timestamp_dt"] <= end_ts)
            ]
            if len(sub) >= cfg.min_failures:
                if best_window is None or len(sub) > len(best_window):
                    best_window = sub

        if best_window is None:
            continue

        first_ts = best_window["timestamp_dt"].min()
        last_ts = best_window["timestamp_dt"].max()

        subsequent_success = df.loc[
            (df["account_normalized"] == account)
            & (df["action_normalized"] == "password_login")
            & (df["result_normalized"] == "success")
            & (df["timestamp_dt"] > last_ts)
        ]
        lock_events = df.loc[
            (df["account_normalized"] == account)
            & (df["action_normalized"] == "account_lock")
            & (df["timestamp_dt"] >= first_ts)
        ]

        support_ids = list(
            dict.fromkeys(best_window["evidence_id"].tolist() + lock_events["evidence_id"].tolist())
        )
        duration_sec = int((last_ts - first_ts).total_seconds())
        success_count = int(len(subsequent_success))

        if success_count > 0:
            severity = "High"
            outcome_note = "A subsequent password_login success occurred after the failures."
        elif not lock_events.empty:
            severity = "Medium"
            outcome_note = (
                f"Defensive account_lock ({', '.join(lock_events['evidence_id'].tolist())}) "
                f"mitigated the burst; no successful login followed."
            )
        else:
            severity = "Medium"
            outcome_note = "No subsequent successful login was observed in the dataset."

        threshold_desc = f">= {cfg.min_failures} failed password_login attempts per account within {cfg.window_minutes}m"
        explanation = (
            f"Account {account} experienced {len(best_window)} consecutive failed password_login attempts "
            f"from {source_ip} within {duration_sec} seconds. {outcome_note}"
        )

        results.append(
            DetectionResult(
                detection_id="",
                detection_category="Brute-Force Attack",
                source_ip=str(source_ip),
                affected_accounts=str(account),
                first_observed=first_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                last_observed=last_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                attempt_count=int(len(best_window) + success_count),
                failure_count=int(len(best_window)),
                success_count=success_count,
                threshold=threshold_desc,
                supporting_event_ids=", ".join(support_ids),
                severity=severity,
                confidence="High",
                explanation=explanation,
            )
        )

    return results


def detect_unusual_access(
    norm_df: pd.DataFrame,
    config: UnusualAccessConfig | None = None,
) -> list[DetectionResult]:
    """Flag successful logins preceded by failures or shifting from prior IP/device context."""
    cfg = config or UnusualAccessConfig()
    df = _valid_events(norm_df)
    successful_logins = df.loc[
        (df["action_normalized"] == "password_login") & (df["result_normalized"] == "success")
    ]
    if successful_logins.empty:
        return []

    results: list[DetectionResult] = []
    lookback = timedelta(hours=cfg.prior_failure_lookback_hours)

    for _, row in successful_logins.iterrows():
        account = row["account_normalized"]
        login_ts = row["timestamp_dt"]
        login_ip = row["source_ip_normalized"]
        login_device = row["device_normalized"]

        prior_events = df.loc[
            (df["account_normalized"] == account) & (df["timestamp_dt"] < login_ts)
        ]
        prior_failures = prior_events.loc[
            (prior_events["action_normalized"] == "password_login")
            & (prior_events["result_normalized"] == "failure")
            & (prior_events["timestamp_dt"] >= (login_ts - lookback))
        ]
        prior_ips = set(prior_events["source_ip_normalized"].tolist())
        has_new_ip = bool(prior_ips) and (login_ip not in prior_ips)

        reasons: list[str] = []
        if cfg.flag_on_prior_failure and not prior_failures.empty:
            reasons.append(
                f"{len(prior_failures)} prior failed password_login attempt(s) within {cfg.prior_failure_lookback_hours}h "
                f"({', '.join(prior_failures['evidence_id'].tolist())})"
            )
        if cfg.flag_on_new_ip_after_activity and has_new_ip:
            reasons.append(
                f"source IP changed from {', '.join(sorted(prior_ips))} to {login_ip} (device: {login_device})"
            )

        if not reasons:
            continue

        support_ids = list(
            dict.fromkeys(prior_failures["evidence_id"].tolist() + [row["evidence_id"]])
        )
        first_ts = (
            prior_failures["timestamp_dt"].min() if not prior_failures.empty else login_ts
        )
        threshold_desc = (
            f"Successful password_login within {cfg.prior_failure_lookback_hours}h after prior failure "
            f"or source IP change"
        )
        explanation = (
            f"Account {account} recorded a successful password_login ({row['evidence_id']}) from {login_ip} "
            f"({login_device}) after {' and '.join(reasons)}. Requires user verification—a login from a new IP "
            f"or device after a spray attempt is a suspicious success, not definitive proof of compromise."
        )

        results.append(
            DetectionResult(
                detection_id="",
                detection_category="Unusual Access",
                source_ip=str(login_ip),
                affected_accounts=str(account),
                first_observed=first_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                last_observed=login_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                attempt_count=int(len(prior_failures) + 1),
                failure_count=int(len(prior_failures)),
                success_count=1,
                threshold=threshold_desc,
                supporting_event_ids=", ".join(support_ids),
                severity="Medium",
                confidence="Medium",
                explanation=explanation,
            )
        )

    return results


def run_all_detections(
    norm_df: pd.DataFrame,
    spray_cfg: PasswordSprayingConfig | None = None,
    brute_cfg: BruteForceConfig | None = None,
    unusual_cfg: UnusualAccessConfig | None = None,
) -> pd.DataFrame:
    """Execute all three detection rules and assign sequential Detection IDs."""
    all_detections = (
        detect_brute_force(norm_df, brute_cfg)
        + detect_password_spraying(norm_df, spray_cfg)
        + detect_unusual_access(norm_df, unusual_cfg)
    )

    # Sort chronologically by first_observed for reproducible IDs
    all_detections.sort(key=lambda d: (d.first_observed, d.detection_category, d.source_ip))
    for idx, det in enumerate(all_detections, start=1):
        det.detection_id = f"DET-{idx:02d}"

    columns = [
        "detection_id",
        "detection_category",
        "source_ip",
        "affected_accounts",
        "first_observed",
        "last_observed",
        "attempt_count",
        "failure_count",
        "success_count",
        "threshold",
        "supporting_event_ids",
        "severity",
        "confidence",
        "explanation",
    ]
    if not all_detections:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame([d.to_dict() for d in all_detections], columns=columns)
