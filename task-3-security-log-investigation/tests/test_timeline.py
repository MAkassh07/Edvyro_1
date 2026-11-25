"""Unit tests for chronological timeline ordering and evidence reference consistency."""

import pandas as pd
from src.detection_rules import run_all_detections
from src.normalization import normalize_logs
from src.timeline import build_incident_timeline


def test_timeline_is_chronologically_ordered_and_references_valid_evidence():
    # Intentionally supply unsorted rows to confirm timeline sorts chronologically
    rows = [
        {"timestamp": "2026-08-01T11:00:00Z", "user_id": "u2", "source_ip": "192.0.2.88", "event": "password_login", "result": "success", "device": "ios"},
        {"timestamp": "2026-08-01T09:00:00Z", "user_id": "u2", "source_ip": "203.0.113.8", "event": "password_login", "result": "failure", "device": "unknown"},
        {"timestamp": "2026-08-01T09:00:05Z", "user_id": "u3", "source_ip": "203.0.113.8", "event": "password_login", "result": "failure", "device": "unknown"},
        {"timestamp": "2026-08-01T09:00:10Z", "user_id": "u4", "source_ip": "203.0.113.8", "event": "password_login", "result": "failure", "device": "unknown"},
    ]
    raw = pd.DataFrame(rows)
    raw.insert(0, "raw_row_number", range(2, len(raw) + 2))
    raw.insert(0, "evidence_id", [f"EV-{i:02d}" for i in range(1, len(raw) + 1)])

    norm_df, _ = normalize_logs(raw)
    det_df = run_all_detections(norm_df)
    tl_df = build_incident_timeline(norm_df, det_df)

    timestamps = pd.to_datetime(tl_df["timestamp"], utc=True).tolist()
    assert timestamps == sorted(timestamps)

    valid_ev_ids = set(norm_df["evidence_id"].tolist())
    for _, det in det_df.iterrows():
        for ref in [s.strip() for s in det["supporting_event_ids"].split(",")]:
            assert ref in valid_ev_ids

    for ref_cell in tl_df["evidence_reference"]:
        ev_id = ref_cell.split(" ")[0]
        assert ev_id in valid_ev_ids
