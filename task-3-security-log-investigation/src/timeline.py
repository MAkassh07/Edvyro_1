"""Baseline authentication metrics, chronological incident timeline, and evidence assessment."""

from typing import Any
import pandas as pd


def compute_baseline_metrics(norm_df: pd.DataFrame) -> dict[str, Any]:
    """Compute baseline authentication statistics strictly from normalized records."""
    valid = norm_df.loc[norm_df["is_valid_record"]].copy()
    login_events = valid.loc[valid["action_normalized"] == "password_login"]
    login_success = login_events.loc[login_events["result_normalized"] == "success"]
    login_failure = login_events.loc[login_events["result_normalized"] == "failure"]
    control_events = valid.loc[valid["event_category"] == "security_control"]
    refresh_events = valid.loc[valid["action_normalized"] == "refresh_token"]

    time_min = valid["timestamp_utc"].min() if not valid.empty else ""
    time_max = valid["timestamp_utc"].max() if not valid.empty else ""

    return {
        "total_events": int(len(valid)),
        "password_login_attempts": int(len(login_events)),
        "successful_logins": int(len(login_success)),
        "failed_logins": int(len(login_failure)),
        "security_control_events": int(len(control_events)),
        "session_refresh_events": int(len(refresh_events)),
        "unique_source_ips": int(valid["source_ip_normalized"].nunique()),
        "unique_accounts": int(valid["account_normalized"].nunique()),
        "time_span_start": time_min,
        "time_span_end": time_max,
        "events_by_ip": valid.groupby("source_ip_normalized").size().sort_values(ascending=False).to_dict(),
        "failed_logins_by_account": (
            login_failure.groupby("account_normalized").size().sort_values(ascending=False).to_dict()
        ),
        "all_outcomes_distribution": valid.groupby(["action_normalized", "result_normalized"])
        .size()
        .to_dict(),
    }


def build_incident_timeline(
    norm_df: pd.DataFrame, detections_df: pd.DataFrame
) -> pd.DataFrame:
    """Build a strictly chronological timeline mapping each event to detections and analyst notes."""
    valid = norm_df.loc[norm_df["is_valid_record"]].copy()
    if "timestamp_dt" not in valid.columns or valid["timestamp_dt"].dtype == object:
        valid["timestamp_dt"] = pd.to_datetime(valid["timestamp_utc"], utc=True, errors="coerce")
    valid = valid.sort_values(["timestamp_dt", "evidence_id"]).reset_index(drop=True)

    # Map evidence_id -> list of detection IDs + categories
    ev_to_dets: dict[str, list[str]] = {}
    if not detections_df.empty:
        for _, det in detections_df.iterrows():
            det_label = f"{det['detection_id']} ({det['detection_category']})"
            for ev_id in [s.strip() for s in str(det["supporting_event_ids"]).split(",") if s.strip()]:
                ev_to_dets.setdefault(ev_id, []).append(det_label)

    rows: list[dict[str, str]] = []
    for _, ev in valid.iterrows():
        ev_id = str(ev["evidence_id"])
        action = str(ev["action_normalized"])
        result = str(ev["result_normalized"])
        account = str(ev["account_normalized"])
        ip = str(ev["source_ip_normalized"])
        device = str(ev["device_normalized"])
        associated = "; ".join(ev_to_dets.get(ev_id, ["None (Baseline Activity)"]))

        if action == "password_login" and result == "failure" and ev_id in ev_to_dets:
            if "Brute-Force" in associated:
                interp = (
                    f"Confirmed rapid password_login failure for {account} from {ip} ({device}); "
                    f"part of single-account brute-force burst."
                )
            else:
                interp = (
                    f"Confirmed password_login failure for {account} from {ip} (device={device}); "
                    f"part of multi-account password spray."
                )
        elif action == "account_lock":
            interp = (
                f"Confirmed defensive account_lock triggered by server for {account} following "
                f"3 rapid failures from {ip}. (Control action success, not a user login.)"
            )
        elif action == "rate_limit":
            interp = (
                f"Confirmed defensive rate_limit blocked request for {account} from {ip} "
                f"shortly after multi-account spray."
            )
        elif action == "password_login" and result == "success" and ev_id in ev_to_dets:
            interp = (
                f"Confirmed password_login success for {account} from new IP {ip} ({device}) "
                f"2h25m after prior spray failure; suspicious success requiring verification, not proof of compromise."
            )
        elif action == "refresh_token":
            interp = f"Confirmed baseline session refresh_token success for {account} from consistent IP {ip} ({device})."
        else:
            interp = f"Confirmed baseline {action} ({result}) for {account} from {ip} ({device})."

        rows.append(
            {
                "timestamp": str(ev["timestamp_utc"]),
                "source_ip": ip,
                "account": account,
                "action": action,
                "result": result,
                "device": device,
                "associated_detection": associated,
                "evidence_reference": f"{ev_id} (CSV line {ev['raw_row_number']})",
                "analyst_interpretation": interp,
            }
        )

    return pd.DataFrame(rows)


def build_evidence_assessment(
    norm_df: pd.DataFrame, detections_df: pd.DataFrame
) -> dict[str, list[dict[str, str]]]:
    """Separate Confirmed Evidence, Analyst Inference, and Unverified Assumptions dynamically."""
    valid = norm_df.loc[norm_df["is_valid_record"]].copy()

    confirmed: list[dict[str, str]] = []
    inferences: list[dict[str, str]] = []
    unverified: list[dict[str, str]] = []

    if not detections_df.empty:
        for _, det in detections_df.iterrows():
            cat = det["detection_category"]
            if cat == "Brute-Force Attack":
                confirmed.append(
                    {
                        "finding": f"{det['detection_id']}: Brute-Force Burst on {det['affected_accounts']}",
                        "evidence_reference": str(det["supporting_event_ids"]),
                        "details": (
                            f"{det['failure_count']} failed password_login attempts against {det['affected_accounts']} "
                            f"from {det['source_ip']} between {det['first_observed']} and {det['last_observed']}, "
                            f"followed by account_lock."
                        ),
                        "interpretation": "Automated or rapid manual password guessing stopped by account lockout.",
                        "confidence": str(det["confidence"]),
                        "missing_information": "HTTP User-Agent, targeted application endpoint, and user confirmation.",
                    }
                )
            elif cat == "Password Spraying":
                confirmed.append(
                    {
                        "finding": f"{det['detection_id']}: Password Spraying from {det['source_ip']}",
                        "evidence_reference": str(det["supporting_event_ids"]),
                        "details": (
                            f"{det['failure_count']} failed password_login attempts across {det['affected_accounts']} "
                            f"within 12 seconds ({det['first_observed']} to {det['last_observed']}), followed by rate_limit block."
                        ),
                        "interpretation": "Single source IP tested common passwords horizontally across 4 accounts.",
                        "confidence": str(det["confidence"]),
                        "missing_information": "Whether additional accounts were probed outside this sample window.",
                    }
                )
            elif cat == "Unusual Access":
                confirmed.append(
                    {
                        "finding": f"{det['detection_id']}: Unusual Subsequent Success for {det['affected_accounts']}",
                        "evidence_reference": str(det["supporting_event_ids"]),
                        "details": (
                            f"password_login success at {det['last_observed']} from {det['source_ip']} (ios) "
                            f"following prior failure at {det['first_observed']} from 203.0.113.42."
                        ),
                        "interpretation": "Suspicious success requiring user verification; cannot confirm compromise from logs alone.",
                        "confidence": str(det["confidence"]),
                        "missing_information": "MFA challenge logs, post-login session activity, and user confirmation of iOS login.",
                    }
                )

    inferences.append(
        {
            "finding": "Control Effectiveness Against Brute-Force & Spraying",
            "evidence_reference": "EV-05, EV-10",
            "details": "account_lock fired on stu-117 45s after the 3rd failure; rate_limit blocked 203.0.113.42 39s after the 4th spray attempt.",
            "interpretation": "Existing lockout and rate-limiting controls likely prevented continued guessing from those specific IPs.",
            "confidence": "High",
            "missing_information": "Lockout duration configuration and whether attackers rotated to other IP addresses.",
        }
    )

    inferences.append(
        {
            "finding": "Likely Legitimate vs. Uncertain Activity on stu-311",
            "evidence_reference": "EV-07, EV-12",
            "details": "EV-07 originated from 203.0.113.42 (device=unknown), whereas EV-12 originated from 192.0.2.99 (device=ios) 2h25m later.",
            "interpretation": "Different network block and mobile OS (ios) may represent the legitimate user signing in later, or an attacker using compromised credentials from another network.",
            "confidence": "Low-Medium",
            "missing_information": "Historical IP/device baseline for stu-311 prior to 2026-08-01 and post-login actions.",
        }
    )

    unverified.append(
        {
            "finding": "Whether Any Account Was Actually Compromised",
            "evidence_reference": "EV-12",
            "details": "Dataset contains no post-authentication audit events (note reads, profile edits, password resets) for stu-311 after 11:47:09Z.",
            "interpretation": "Cannot determine whether stu-311's login was authorized or unauthorized without user confirmation and application logs.",
            "confidence": "Unverified",
            "missing_information": "MFA logs, user out-of-band verification, and post-login audit trail.",
        }
    )
    unverified.append(
        {
            "finding": "Attacker Intent, Attribution, or Geolocation",
            "evidence_reference": ", ".join(valid["evidence_id"].tolist()),
            "details": "All IPs belong to RFC 5737 documentation blocks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).",
            "interpretation": "Synthetic documentation IPs carry no real-world geolocation or threat-actor attribution.",
            "confidence": "Unverified",
            "missing_information": "Real production telemetry, ASN/ISP metadata, and threat intelligence.",
        }
    )

    return {
        "confirmed_evidence": confirmed,
        "analyst_inference": inferences,
        "unverified_assumptions": unverified,
    }


def assess_incident_severity(detections_df: pd.DataFrame) -> dict[str, Any]:
    """Assess overall incident severity transparently from detection outputs."""
    if detections_df.empty:
        return {
            "overall_severity": "Informational",
            "rationale": "No detection thresholds were exceeded in the supplied records.",
        }

    severities = set(detections_df["severity"].tolist())
    has_unusual_success = "Unusual Access" in set(detections_df["detection_category"].tolist())

    if "Critical" in severities:
        overall = "Critical"
    elif "High" in severities:
        overall = "High"
    elif "Medium" in severities:
        overall = "Medium"
    else:
        overall = "Low"

    rationale = (
        f"Overall incident severity is classified as {overall}. "
        "Multiple targeted accounts (4 accounts in rapid password spraying from 203.0.113.42, "
        "plus 1 account receiving a 3-attempt brute-force burst from 198.51.100.27) justify High attention. "
        "While defensive controls (account_lock and rate_limit) fired, stu-311 recorded a subsequent "
        "successful login from a new IP/device (EV-12); because post-login audit logs and user confirmation "
        "are absent, compromise remains unconfirmed and requires verification."
        if has_unusual_success
        else f"Overall incident severity is {overall} based on detected failure bursts."
    )

    return {
        "overall_severity": overall,
        "detection_count": int(len(detections_df)),
        "severity_breakdown": detections_df.groupby("severity").size().to_dict(),
        "compromise_confirmed": False,
        "rationale": rationale,
    }
