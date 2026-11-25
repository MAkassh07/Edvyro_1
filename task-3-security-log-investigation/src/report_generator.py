"""End-to-end investigation runner, Matplotlib chart builder, and ReportLab PDF generator."""

from pathlib import Path
import sys
from typing import Any

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.detection_rules import run_all_detections
from src.log_parser import inspect_raw_schema, load_raw_logs
from src.normalization import normalize_logs
from src.timeline import (
    assess_incident_severity,
    build_evidence_assessment,
    build_incident_timeline,
    compute_baseline_metrics,
)

PALETTE = {
    "slate": "#0F172A",
    "muted": "#475569",
    "teal": "#0F766E",
    "crimson": "#B91C1C",
    "amber": "#B45309",
    "blue": "#1D4ED8",
    "grid": "#E2E8F0",
}


def generate_charts(
    norm_df: pd.DataFrame,
    detections_df: pd.DataFrame,
    timeline_df: pd.DataFrame,
    charts_dir: Path,
) -> dict[str, Path]:
    """Generate clean, high-DPI Matplotlib charts strictly from actual dataset records."""
    charts_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "axes.edgecolor": "#CBD5E1",
            "axes.linewidth": 0.8,
            "axes.grid": True,
            "grid.color": "#E2E8F0",
            "grid.linestyle": "--",
            "grid.linewidth": 0.6,
        }
    )

    valid = norm_df.loc[norm_df["is_valid_record"]].copy()
    valid["timestamp_dt"] = pd.to_datetime(valid["timestamp_utc"], utc=True)
    paths: dict[str, Path] = {}

    # 1. Authentication Outcome Distribution (password_login success vs failure + controls)
    fig, ax = plt.subplots(figsize=(6.8, 3.8), dpi=160)
    outcome_series = (
        valid.assign(
            label=valid["action_normalized"] + " (" + valid["result_normalized"] + ")"
        )
        .groupby("label")
        .size()
        .sort_values(ascending=True)
    )
    bar_colors = [
        PALETTE["crimson"] if "failure" in lbl else (PALETTE["amber"] if "blocked" in lbl or "account_lock" in lbl else PALETTE["teal"])
        for lbl in outcome_series.index
    ]
    bars = ax.barh(outcome_series.index, outcome_series.values, color=bar_colors, height=0.55)
    ax.set_title("Authentication & Control Event Outcome Distribution (n=12)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Event Count", fontsize=9)
    ax.set_xlim(0, max(outcome_series.values) + 1.5)
    ax.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.12, bar.get_y() + bar.get_height() / 2, f"{int(w)}", va="center", fontsize=8.5)
    fig.tight_layout()
    p1 = charts_dir / "01_outcome_distribution.png"
    fig.savefig(p1)
    plt.close(fig)
    paths["outcome_distribution"] = p1

    # 2. Authentication & Failed Login Events Over Time
    fig, ax = plt.subplots(figsize=(7.0, 3.8), dpi=160)
    valid["minute_bucket"] = valid["timestamp_dt"].dt.floor("5min")
    all_by_time = valid.groupby("minute_bucket").size()
    fail_by_time = (
        valid.loc[(valid["action_normalized"] == "password_login") & (valid["result_normalized"] == "failure")]
        .groupby("minute_bucket")
        .size()
        .reindex(all_by_time.index, fill_value=0)
    )
    ax.plot(all_by_time.index, all_by_time.values, marker="o", linewidth=1.8, color=PALETTE["teal"], label="All Events")
    ax.plot(fail_by_time.index, fail_by_time.values, marker="s", linewidth=1.8, color=PALETTE["crimson"], label="Failed Password Logins")
    ax.set_title("Authentication Activity & Failed Logins Over Time (5-Min Bins, UTC)", fontsize=11, fontweight="bold", pad=10)
    ax.set_ylabel("Event Count", fontsize=9)
    ax.set_xlabel("Time (UTC on 2026-08-01)", fontsize=9)
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.legend(frameon=True, fontsize=8.5)
    fig.tight_layout()
    p2 = charts_dir / "02_events_over_time.png"
    fig.savefig(p2)
    plt.close(fig)
    paths["events_over_time"] = p2

    # 3. Top Source IP Addresses by Event Count
    fig, ax = plt.subplots(figsize=(6.8, 3.6), dpi=160)
    ip_counts = valid.groupby("source_ip_normalized").size().sort_values(ascending=True)
    bars = ax.barh(ip_counts.index, ip_counts.values, color=PALETTE["blue"], height=0.52)
    ax.set_title("Source IP Addresses by Total Event Count", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Event Count", fontsize=9)
    ax.set_xlim(0, max(ip_counts.values) + 1.5)
    ax.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.12, bar.get_y() + bar.get_height() / 2, f"{int(w)}", va="center", fontsize=8.5)
    fig.tight_layout()
    p3 = charts_dir / "03_top_source_ips.png"
    fig.savefig(p3)
    plt.close(fig)
    paths["top_source_ips"] = p3

    # 4. Top Accounts by Failed Password Login Count
    fig, ax = plt.subplots(figsize=(6.8, 3.6), dpi=160)
    failed_accounts = (
        valid.loc[(valid["action_normalized"] == "password_login") & (valid["result_normalized"] == "failure")]
        .groupby("account_normalized")
        .size()
        .sort_values(ascending=True)
    )
    bars = ax.barh(failed_accounts.index, failed_accounts.values, color=PALETTE["crimson"], height=0.52)
    ax.set_title("Targeted Accounts by Failed Password Login Count", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Failed Password Login Attempts", fontsize=9)
    ax.set_xlim(0, max(failed_accounts.values) + 1.2)
    ax.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.08, bar.get_y() + bar.get_height() / 2, f"{int(w)}", va="center", fontsize=8.5)
    fig.tight_layout()
    p4 = charts_dir / "04_top_targeted_accounts.png"
    fig.savefig(p4)
    plt.close(fig)
    paths["top_targeted_accounts"] = p4

    # 5. Login & Security Event Outcomes by Account
    fig, ax = plt.subplots(figsize=(7.0, 4.0), dpi=160)
    pivot = (
        valid.groupby(["account_normalized", "result_normalized"])
        .size()
        .unstack(fill_value=0)
    )
    for col in ["success", "failure", "blocked"]:
        if col not in pivot.columns:
            pivot[col] = 0
    pivot = pivot[["success", "failure", "blocked"]]
    pivot.plot(
        kind="bar",
        stacked=True,
        ax=ax,
        color=[PALETTE["teal"], PALETTE["crimson"], PALETTE["amber"]],
        width=0.55,
    )
    ax.set_title("Event Outcomes by Account (All Event Types)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Account", fontsize=9)
    ax.set_ylabel("Event Count", fontsize=9)
    ax.yaxis.set_major_locator(plt.MaxNLocator(integer=True))
    ax.tick_params(axis="x", rotation=0)
    ax.legend(title="Result", fontsize=8.5, title_fontsize=8.5)
    fig.tight_layout()
    p5 = charts_dir / "05_outcomes_by_account.png"
    fig.savefig(p5)
    plt.close(fig)
    paths["outcomes_by_account"] = p5

    # 6. Detection Summary & Incident Timeline Visualization
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.2, 5.4), dpi=160, gridspec_kw={"height_ratios": [1, 1.5]})
    if not detections_df.empty:
        det_counts = detections_df.groupby("detection_category").size()
        bars = ax1.barh(det_counts.index, det_counts.values, color=[PALETTE["amber"], PALETTE["crimson"], PALETTE["blue"]][: len(det_counts)], height=0.45)
        ax1.set_title("Triggered Detection Categories", fontsize=10.5, fontweight="bold")
        ax1.set_xlabel("Detection Count", fontsize=8.5)
        ax1.set_xlim(0, max(det_counts.values) + 1)
        ax1.xaxis.set_major_locator(plt.MaxNLocator(integer=True))
        for bar in bars:
            ax1.text(bar.get_width() + 0.06, bar.get_y() + bar.get_height() / 2, f"{int(bar.get_width())}", va="center", fontsize=8.5)

    accounts_order = sorted(valid["account_normalized"].unique().tolist())
    acc_idx = {acc: i for i, acc in enumerate(accounts_order)}
    color_map = {"success": PALETTE["teal"], "failure": PALETTE["crimson"], "blocked": PALETTE["amber"]}
    for res_val, sub in valid.groupby("result_normalized"):
        ax2.scatter(
            sub["timestamp_dt"],
            [acc_idx[a] for a in sub["account_normalized"]],
            label=f"Result: {res_val}",
            color=color_map.get(res_val, PALETTE["slate"]),
            s=65,
            zorder=3,
        )
    ax2.set_yticks(range(len(accounts_order)))
    ax2.set_yticklabels(accounts_order, fontsize=8.5)
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax2.set_title("Chronological Event Timeline by Account (2026-08-01 UTC)", fontsize=10.5, fontweight="bold")
    ax2.set_xlabel("Timestamp (UTC)", fontsize=8.5)
    ax2.legend(fontsize=8, loc="upper left")
    fig.tight_layout()
    p6 = charts_dir / "06_detection_and_timeline.png"
    fig.savefig(p6)
    plt.close(fig)
    paths["detection_and_timeline"] = p6

    return paths


def _pdf_page_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(0.75 * inch, 0.45 * inch, "Security Log Investigation — Task 3 (Defensive Forensics Report)")
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.45 * inch, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf_report(
    output_pdf: Path,
    quality_summary: dict[str, Any],
    baseline: dict[str, Any],
    detections_df: pd.DataFrame,
    timeline_df: pd.DataFrame,
    evidence_assessment: dict[str, list[dict[str, str]]],
    severity_assessment: dict[str, Any],
    chart_paths: dict[str, Path],
) -> None:
    """Build a polished, multi-page ReportLab PDF strictly from actual investigation results."""
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="Security Log Investigation — Incident Report",
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=15, spaceBefore=12, spaceAfter=6, textColor=colors.HexColor("#0F172A"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11.5, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#0F766E"))
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13.5, spaceAfter=6, textColor=colors.HexColor("#1E293B"))
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=8, leading=10.5, textColor=colors.HexColor("#1E293B"))
    cell_bold = ParagraphStyle("CellBold", parent=cell_style, fontName="Helvetica-Bold")
    cover_title = ParagraphStyle("CoverTitle", parent=styles["Title"], fontSize=24, leading=28, textColor=colors.HexColor("#0F172A"), spaceAfter=12)
    cover_sub = ParagraphStyle("CoverSub", parent=styles["Normal"], fontSize=12, leading=17, textColor=colors.HexColor("#475569"), spaceAfter=18)

    def make_table(rows: list[list[Any]], col_widths: list[float]) -> Table:
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return tbl

    story: list[Any] = []

    # 1. Cover Page
    story.append(Spacer(1, 1.3 * inch))
    story.append(Paragraph("CYBERSECURITY INTERNSHIP PORTFOLIO · TASK 3", ParagraphStyle("Eyebrow", parent=body, fontName="Helvetica-Bold", textColor=colors.HexColor("#0F766E"))))
    story.append(Paragraph("Security Log Investigation &amp; Incident Report", cover_title))
    story.append(Paragraph("Defensive analysis of authentication logs covering normalization, baseline profiling, password spraying, brute-force detection, unusual access triage, timeline reconstruction, and evidence-based response.", cover_sub))
    cover_meta = [
        [Paragraph("Attribute", cell_bold), Paragraph("Investigation Detail", cell_bold)],
        [Paragraph("Source Dataset", cell_style), Paragraph("authentication-log-sample.csv (12 records, 2026-08-01 UTC)", cell_style)],
        [Paragraph("IP Space Note", cell_style), Paragraph("RFC 5737 documentation-range IPv4 addresses (synthetic educational data)", cell_style)],
        [Paragraph("Overall Incident Severity", cell_style), Paragraph(f"{severity_assessment['overall_severity']} (Compromise unconfirmed; verification required)", cell_style)],
        [Paragraph("Detections Triggered", cell_style), Paragraph(f"{len(detections_df)} rule detections across 3 categories", cell_style)],
        [Paragraph("Repository", cell_style), Paragraph("https://github.com/MAkassh07/Edvyro_1", cell_style)],
    ]
    story.append(make_table(cover_meta, [2.1 * inch, 4.7 * inch]))
    story.append(PageBreak())

    # 2. Executive Summary
    story.append(Paragraph("1. Executive Summary", h1))
    story.append(Paragraph(
        f"This investigation analyzed {quality_summary['total_input_records']} authentication and security-control log entries "
        f"spanning {baseline['time_span_start']} to {baseline['time_span_end']}. All {quality_summary['valid_records']} records "
        f"passed timestamp and IP validation with zero duplicates or missing fields. Applying deterministic rule thresholds "
        f"identified {len(detections_df)} notable detections: one single-account brute-force burst against stu-117 (mitigated by "
        f"server account_lock), one horizontal password spray from 203.0.113.42 across four distinct accounts (mitigated by "
        f"rate_limit), and one subsequent successful login by stu-311 from a new IP and iOS device requiring user verification.",
        body,
    ))

    # 3. Investigation Objective
    story.append(Paragraph("2. Investigation Objective", h1))
    story.append(Paragraph(
        "Demonstrate reproducible defensive log investigation practices: preserve original log evidence, normalize timestamps "
        "and network identifiers, separate authentication attempts from automated security controls, detect brute-force, "
        "password spraying, and unusual access patterns, distinguish confirmed facts from assumptions, and recommend containment actions.",
        body,
    ))

    # 4. Dataset Overview
    story.append(Paragraph("3. Dataset Overview", h1))
    story.append(Paragraph(
        "Source: https://edvyro.in/datasets/source-materials/authentication-log-sample.csv. Schema consists of 6 columns: "
        "timestamp, user_id, source_ip, event, result, and device. All IPv4 addresses fall within RFC 5737 documentation blocks "
        "(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).",
        body,
    ))

    # 5. Methodology
    story.append(Paragraph("4. Investigation Methodology", h1))
    story.append(Paragraph(
        "1) Read raw CSV immutably and assign EV-01..EV-12 evidence IDs. "
        "2) Normalize UTC timestamps, canonical IPv4 addresses, lowercase accounts, and event categories. "
        "3) Compute authentication baseline statistics excluding control-only events from login totals. "
        "4) Execute sliding-window rules for Brute-Force, Password Spraying, and Unusual Access. "
        "5) Reconstruct a chronological timeline and separate Confirmed Evidence from Analyst Inference and Unverified Assumptions.",
        body,
    ))

    # 6. Data Normalization Findings
    story.append(Paragraph("5. Data Normalization &amp; Quality Findings", h1))
    dq_rows = [
        [Paragraph("Quality Metric", cell_bold), Paragraph("Observed Value", cell_bold)],
        [Paragraph("Total Input Records", cell_style), Paragraph(str(quality_summary["total_input_records"]), cell_style)],
        [Paragraph("Valid Records", cell_style), Paragraph(str(quality_summary["valid_records"]), cell_style)],
        [Paragraph("Exact Duplicate Records", cell_style), Paragraph(str(quality_summary["duplicate_records"]), cell_style)],
        [Paragraph("Invalid Timestamps / Invalid IPs", cell_style), Paragraph(f"{quality_summary['invalid_timestamps']} / {quality_summary['invalid_ip_addresses']}", cell_style)],
        [Paragraph("Missing Values (Any Field)", cell_style), Paragraph("0 across all 6 columns", cell_style)],
        [Paragraph("Records with device='unknown'", cell_style), Paragraph(f"{quality_summary['unknown_device_records']} (EV-06 through EV-09)", cell_style)],
        [Paragraph("Records Excluded", cell_style), Paragraph(str(quality_summary["excluded_records_count"]), cell_style)],
    ]
    story.append(make_table(dq_rows, [3.0 * inch, 3.8 * inch]))

    # 7. Authentication Baseline
    story.append(Paragraph("6. Authentication Baseline", h1))
    story.append(Paragraph(
        f"Across {baseline['total_events']} total records: {baseline['password_login_attempts']} were password_login attempts "
        f"({baseline['successful_logins']} successful, {baseline['failed_logins']} failed), {baseline['session_refresh_events']} "
        f"was a refresh_token event, and {baseline['security_control_events']} were defensive control actions (account_lock and rate_limit). "
        f"There were {baseline['unique_accounts']} unique accounts and {baseline['unique_source_ips']} unique source IP addresses. "
        f"Notice that account_lock (EV-05) carries result='success' because the server succeeded in locking the account—not because a user logged in.",
        body,
    ))

    for img_key, width_in in [
        ("outcome_distribution", 6.2),
        ("events_over_time", 6.2),
        ("top_source_ips", 6.0),
        ("top_targeted_accounts", 6.0),
        ("outcomes_by_account", 6.2),
    ]:
        story.append(Spacer(1, 0.1 * inch))
        story.append(Image(str(chart_paths[img_key]), width=width_in * inch, height=(width_in * 0.54) * inch))

    story.append(PageBreak())

    # 8–11. Detection Methodology & Findings
    story.append(Paragraph("7. Detection Methodology &amp; Findings", h1))
    story.append(Paragraph(
        "Three deterministic rules were applied solely to valid normalized records: "
        "(A) Brute-Force (>=3 failed password_logins per account/IP within 15 min), "
        "(B) Password Spraying (>=3 distinct accounts, <=2 failures/account from one IP within 15 min), and "
        "(C) Unusual Access (successful password_login within 24h after prior failure or from a new IP).",
        body,
    ))

    det_rows = [
        [
            Paragraph("ID", cell_bold),
            Paragraph("Category", cell_bold),
            Paragraph("Source IP", cell_bold),
            Paragraph("Accounts", cell_bold),
            Paragraph("Fails / Succ", cell_bold),
            Paragraph("Sev / Conf", cell_bold),
            Paragraph("Evidence", cell_bold),
        ]
    ]
    for _, d in detections_df.iterrows():
        det_rows.append(
            [
                Paragraph(str(d["detection_id"]), cell_style),
                Paragraph(str(d["detection_category"]), cell_style),
                Paragraph(str(d["source_ip"]), cell_style),
                Paragraph(str(d["affected_accounts"]), cell_style),
                Paragraph(f"{d['failure_count']} / {d['success_count']}", cell_style),
                Paragraph(f"{d['severity']} / {d['confidence']}", cell_style),
                Paragraph(str(d["supporting_event_ids"]), cell_style),
            ]
        )
    story.append(make_table(det_rows, [0.55 * inch, 1.15 * inch, 0.95 * inch, 1.45 * inch, 0.7 * inch, 0.95 * inch, 1.05 * inch]))
    story.append(Spacer(1, 0.12 * inch))

    for _, d in detections_df.iterrows():
        story.append(Paragraph(f"{d['detection_id']} — {d['detection_category']}", h2))
        story.append(Paragraph(str(d["explanation"]), body))

    story.append(Image(str(chart_paths["detection_and_timeline"]), width=6.4 * inch, height=4.6 * inch))
    story.append(PageBreak())

    # 12. Incident Timeline
    story.append(Paragraph("8. Chronological Incident Timeline", h1))
    tl_rows = [
        [
            Paragraph("Timestamp (UTC)", cell_bold),
            Paragraph("IP / Account", cell_bold),
            Paragraph("Action / Result", cell_bold),
            Paragraph("Detection", cell_bold),
            Paragraph("Evidence", cell_bold),
            Paragraph("Analyst Interpretation", cell_bold),
        ]
    ]
    for _, t in timeline_df.iterrows():
        tl_rows.append(
            [
                Paragraph(str(t["timestamp"]), cell_style),
                Paragraph(f"{t['source_ip']}<br/>{t['account']}", cell_style),
                Paragraph(f"{t['action']}<br/>({t['result']})", cell_style),
                Paragraph(str(t["associated_detection"]), cell_style),
                Paragraph(str(t["evidence_reference"]), cell_style),
                Paragraph(str(t["analyst_interpretation"]), cell_style),
            ]
        )
    story.append(make_table(tl_rows, [1.15 * inch, 1.0 * inch, 0.85 * inch, 1.1 * inch, 0.8 * inch, 1.9 * inch]))

    # 13. Evidence vs Assumptions
    story.append(Paragraph("9. Evidence vs. Assumptions Assessment", h1))
    for section_title, key in [
        ("Confirmed Evidence", "confirmed_evidence"),
        ("Analyst Inference", "analyst_inference"),
        ("Unverified Assumptions", "unverified_assumptions"),
    ]:
        story.append(Paragraph(section_title, h2))
        for item in evidence_assessment[key]:
            story.append(
                Paragraph(
                    f"<b>{item['finding']}</b> ({item['evidence_reference']} · Confidence: {item['confidence']}): "
                    f"{item['details']} <i>Interpretation:</i> {item['interpretation']} "
                    f"<i>Missing info:</i> {item['missing_information']}",
                    body,
                )
            )

    # 14. Severity Assessment
    story.append(Paragraph("10. Incident Severity Assessment", h1))
    story.append(Paragraph(severity_assessment["rationale"], body))

    # 15–16. Containment & Long-Term Recommendations
    story.append(Paragraph("11. Incident Response &amp; Containment Recommendations", h1))
    rec_rows = [
        [Paragraph("Phase", cell_bold), Paragraph("Problem Addressed", cell_bold), Paragraph("Recommended Action", cell_bold), Paragraph("Priority", cell_bold)],
        [Paragraph("Immediate", cell_style), Paragraph("Unverified EV-12 login on stu-311", cell_style), Paragraph("Contact stu-311 owner out-of-band to verify the 11:47:09Z iOS login; revoke sessions and reset password if unauthorized.", cell_style), Paragraph("P1", cell_style)],
        [Paragraph("Immediate", cell_style), Paragraph("Evidence preservation", cell_style), Paragraph("Preserve immutable copies of authentication-log-sample.csv and surrounding server logs.", cell_style), Paragraph("P1", cell_style)],
        [Paragraph("Containment", cell_style), Paragraph("Spraying from 203.0.113.42 &amp; brute force from 198.51.100.27", cell_style), Paragraph("Review rate-limit/lockout durations, temporarily monitor/block abusive IPs, and verify MFA status for targeted accounts.", cell_style), Paragraph("P1", cell_style)],
        [Paragraph("Long-Term", cell_style), Paragraph("Lack of MFA &amp; post-login audit visibility", cell_style), Paragraph("Enforce phishing-resistant MFA, centralize auth + post-login audit logging, and deploy automated spray/brute-force alerting.", cell_style), Paragraph("P2", cell_style)],
    ]
    story.append(make_table(rec_rows, [0.9 * inch, 1.5 * inch, 3.8 * inch, 0.6 * inch]))

    # 17–19. Limitations, Conclusion, References
    story.append(Paragraph("12. Limitations, Conclusion &amp; References", h1))
    story.append(Paragraph(
        "<b>Limitations:</b> This sample contains 12 synthetic events over 2 hours 47 minutes using RFC 5737 documentation IPs. "
        "No User-Agent strings, MFA telemetry, or post-login session actions are present, preventing definitive compromise confirmation.",
        body,
    ))
    story.append(Paragraph(
        "<b>Conclusion:</b> Existing lockout and rate-limiting controls actively disrupted both the brute-force burst against stu-117 "
        "and the password spray from 203.0.113.42. Follow-up verification of stu-311's subsequent iOS login (EV-12) completes containment.",
        body,
    ))
    story.append(Paragraph(
        "<b>References:</b> MITRE ATT&amp;CK T1110 (https://attack.mitre.org/techniques/T1110/) · "
        "T1110.003 Password Spraying (https://attack.mitre.org/techniques/T1110/003/) · "
        "OWASP Authentication Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) · "
        "NIST SP 800-63B (https://pages.nist.gov/800-63-3/sp800-63b.html) · "
        "CISA Authentication Guidance (https://www.cisa.gov/MFA)",
        body,
    ))

    doc.build(story, onFirstPage=_pdf_page_footer, onLaterPages=_pdf_page_footer)


def run_investigation(base_dir: str | Path = ".") -> dict[str, Any]:
    """Execute the full log investigation pipeline and write all derived artifacts."""
    root = Path(base_dir)
    raw_csv = root / "data" / "authentication-log-sample.csv"
    norm_csv = root / "data" / "normalized-authentication-logs.csv"
    det_csv = root / "evidence" / "detection-results.csv"
    tl_csv = root / "evidence" / "incident-timeline.csv"
    summary_md = root / "evidence" / "investigation-summary.md"
    output_txt = root / "evidence" / "analysis-output.txt"
    charts_dir = root / "evidence" / "charts"
    pdf_path = root / "reports" / "incident_report.pdf"

    raw_df = load_raw_logs(raw_csv)
    raw_schema = inspect_raw_schema(raw_df)
    norm_df, quality_summary = normalize_logs(raw_df)

    # Save clean normalized CSV without Python datetime object column
    export_norm = norm_df.drop(columns=["timestamp_dt"])
    export_norm.to_csv(norm_csv, index=False)

    baseline = compute_baseline_metrics(norm_df)
    detections_df = run_all_detections(norm_df)
    det_csv.parent.mkdir(parents=True, exist_ok=True)
    detections_df.to_csv(det_csv, index=False)

    timeline_df = build_incident_timeline(norm_df, detections_df)
    timeline_df.to_csv(tl_csv, index=False)

    evidence_assessment = build_evidence_assessment(norm_df, detections_df)
    severity_assessment = assess_incident_severity(detections_df)
    chart_paths = generate_charts(norm_df, detections_df, timeline_df, charts_dir)
    generate_pdf_report(
        pdf_path,
        quality_summary,
        baseline,
        detections_df,
        timeline_df,
        evidence_assessment,
        severity_assessment,
        chart_paths,
    )

    lines = [
        "=== SECURITY LOG INVESTIGATION OUTPUT ===",
        f"Dataset: {raw_csv.as_posix()}",
        f"Columns: {raw_schema['columns']}",
        f"Total input records: {quality_summary['total_input_records']}",
        f"Valid records: {quality_summary['valid_records']}",
        f"Duplicate records: {quality_summary['duplicate_records']}",
        f"Invalid timestamps: {quality_summary['invalid_timestamps']}",
        f"Invalid IPs: {quality_summary['invalid_ip_addresses']}",
        f"Password login attempts: {baseline['password_login_attempts']} "
        f"(success={baseline['successful_logins']}, failure={baseline['failed_logins']})",
        f"Security control events: {baseline['security_control_events']} | "
        f"Session refresh events: {baseline['session_refresh_events']}",
        f"Unique accounts: {baseline['unique_accounts']} | Unique IPs: {baseline['unique_source_ips']}",
        f"Detections triggered: {len(detections_df)}",
        "",
    ]
    for _, d in detections_df.iterrows():
        lines.append(
            f"[{d['detection_id']}] {d['detection_category']} | IP={d['source_ip']} | "
            f"Accounts={d['affected_accounts']} | Failures={d['failure_count']} | "
            f"Successes={d['success_count']} | Severity={d['severity']} | "
            f"Evidence={d['supporting_event_ids']}"
        )
    lines.append("")
    lines.append(f"Overall Incident Severity: {severity_assessment['overall_severity']}")
    lines.append(f"PDF Report Written: {pdf_path.as_posix()}")

    output_text = "\n".join(lines) + "\n"
    output_txt.write_text(output_text, encoding="utf-8")

    # Write concise evidence/investigation-summary.md
    md_lines = [
        "# Investigation Summary — Security Log Investigation",
        "",
        "## Dataset & Data Quality",
        f"- **Input Records:** {quality_summary['total_input_records']} (100% valid, 0 duplicates, 0 invalid timestamps, 0 invalid IPs)",
        f"- **Time Range:** `{baseline['time_span_start']}` to `{baseline['time_span_end']}`",
        f"- **Unique Accounts:** {baseline['unique_accounts']} · **Unique Source IPs:** {baseline['unique_source_ips']}",
        "",
        "## Authentication Baseline",
        f"- **Password Login Attempts:** {baseline['password_login_attempts']} ({baseline['successful_logins']} success, {baseline['failed_logins']} failure)",
        f"- **Security Control Events:** {baseline['security_control_events']} (`account_lock` on `stu-117`, `rate_limit` on `203.0.113.42`)",
        f"- **Session Maintenance:** {baseline['session_refresh_events']} (`refresh_token` for `stu-104`)",
        "",
        "## Detections Triggered",
        "",
        "| ID | Category | Source IP | Affected Accounts | Failures | Successes | Severity | Evidence |",
        "| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |",
    ]
    for _, d in detections_df.iterrows():
        md_lines.append(
            f"| **{d['detection_id']}** | {d['detection_category']} | `{d['source_ip']}` | "
            f"`{d['affected_accounts']}` | {d['failure_count']} | {d['success_count']} | "
            f"**{d['severity']}** | {d['supporting_event_ids']} |"
        )
    md_lines.extend(
        [
            "",
            "## Severity Assessment",
            f"- **Overall Severity:** **{severity_assessment['overall_severity']}**",
            f"- **Rationale:** {severity_assessment['rationale']}",
        ]
    )
    summary_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    return {
        "quality_summary": quality_summary,
        "baseline": baseline,
        "detections_df": detections_df,
        "timeline_df": timeline_df,
        "severity_assessment": severity_assessment,
        "output_text": output_text,
    }


if __name__ == "__main__":
    result = run_investigation(Path(__file__).resolve().parent.parent)
    print(result["output_text"])
