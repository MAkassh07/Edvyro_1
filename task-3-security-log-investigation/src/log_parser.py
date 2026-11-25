"""Log ingestion utilities that preserve the raw authentication CSV."""

from pathlib import Path
from typing import Any
import pandas as pd

EXPECTED_COLUMNS = ["timestamp", "user_id", "source_ip", "event", "result", "device"]


def load_raw_logs(csv_path: str | Path) -> pd.DataFrame:
    """Load the original authentication CSV as raw strings without altering source data."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Authentication log dataset not found at: {path}")

    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df.insert(0, "raw_row_number", range(2, len(df) + 2))
    df.insert(0, "evidence_id", [f"EV-{idx:02d}" for idx in range(1, len(df) + 1)])
    return df


def inspect_raw_schema(raw_df: pd.DataFrame) -> dict[str, Any]:
    """Inspect schema, record counts, missing values, and exact duplicate rows."""
    data_columns = [c for c in raw_df.columns if c not in {"evidence_id", "raw_row_number"}]
    missing_by_field = {
        col: int((raw_df[col].astype(str).str.strip() == "").sum()) for col in data_columns
    }
    duplicate_mask = raw_df.duplicated(subset=data_columns, keep="first")

    return {
        "columns": data_columns,
        "matches_expected_columns": data_columns == EXPECTED_COLUMNS,
        "total_input_records": int(len(raw_df)),
        "missing_values_by_field": missing_by_field,
        "exact_duplicate_count": int(duplicate_mask.sum()),
    }
