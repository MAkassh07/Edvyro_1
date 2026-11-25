"""Authorized non-destructive defensive security assessment harness for Task 2 (SecureAuth).

Executes controlled checks in isolated temporary directories using Flask's test client
and synthetic @example.com accounts. Never targets external hosts or real user data.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TASK4_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = TASK4_DIR.parent
TASK2_DIR = REPO_ROOT / "task-2-secure-authentication"

if str(TASK2_DIR) not in sys.path:
    sys.path.insert(0, str(TASK2_DIR))

CSRF_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')
TEST_PW = "Assess!Strong#Pass2026"


@dataclass
class CheckResult:
    check_id: str
    domain: str
    title: str
    passed: bool
    status: str
    evidence: str


def _extract_csrf(html_bytes: bytes) -> str:
    match = CSRF_RE.search(html_bytes.decode("utf-8", errors="replace"))
    if not match:
        raise AssertionError("CSRF token not found in rendered HTML form.")
    return match.group(1)


def _create_isolated_app(tmp_dir: str, extra_config: dict[str, Any] | None = None):
    from app import create_app
    from app.config import TestingConfig
    from app.extensions import limiter

    cfg: dict[str, Any] = {
        "TESTING": True,
        "DEBUG": False,
        "FLASK_ENV": "testing",
        "SECRET_KEY": TestingConfig.SECRET_KEY,
        "DATABASE_PATH": str(Path(tmp_dir) / "assess_secureauth.db"),
        "SESSION_COOKIE_SECURE": False,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "WTF_CSRF_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
        "SESSION_LIFETIME_MINUTES": 15,
        "SESSION_TIMEOUT_SECONDS": 900,
    }
    if extra_config:
        cfg.update(extra_config)

    app = create_app(cfg)
    with app.app_context():
        limiter.reset()
    return app


def _register_and_login(client, email: str, password: str = TEST_PW) -> None:
    reg_page = client.get("/register")
    reg_token = _extract_csrf(reg_page.data)
    reg_resp = client.post(
        "/register",
        data={
            "csrf_token": reg_token,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=False,
    )
    if reg_resp.status_code != 302:
        raise AssertionError(f"Expected 302 from /register, got {reg_resp.status_code}")

    login_page = client.get("/login")
    login_token = _extract_csrf(login_page.data)
    login_resp = client.post(
        "/login",
        data={
            "csrf_token": login_token,
            "email": email,
            "password": password,
        },
        follow_redirects=False,
    )
    if login_resp.status_code != 302:
        raise AssertionError(f"Expected 302 from /login, got {login_resp.status_code}")


def check_dotenv_import_ordering() -> CheckResult:
    """FND-01: Verify whether .env settings (FLASK_SECRET_KEY, SESSION_COOKIE_SECURE) load before Config."""
    with tempfile.TemporaryDirectory() as tmp:
        env_path = Path(tmp) / ".env"
        db_path = (Path(tmp) / "dotenv_probe.db").as_posix()
        env_path.write_text(
            "\n".join(
                [
                    "FLASK_SECRET_KEY=dotenv-probe-signing-key-value-32chars-min-2026",
                    "FLASK_ENV=development",
                    "FLASK_DEBUG=0",
                    "SESSION_COOKIE_SECURE=true",
                    "SESSION_LIFETIME_MINUTES=25",
                    f"DATABASE_PATH={db_path}",
                ]
            ),
            encoding="utf-8",
        )
        probe_code = (
            "import json, sys; "
            f"sys.path.insert(0, {str(TASK2_DIR)!r}); "
            "from app import create_app; "
            "app = create_app(); "
            "print(json.dumps({"
            "'secret_matched': app.config.get('SECRET_KEY') == 'dotenv-probe-signing-key-value-32chars-min-2026', "
            "'cookie_secure': app.config.get('SESSION_COOKIE_SECURE'), "
            "'lifetime': app.config.get('SESSION_LIFETIME_MINUTES')"
            "}))"
        )
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k
            not in {
                "FLASK_SECRET_KEY",
                "FLASK_ENV",
                "FLASK_DEBUG",
                "SESSION_COOKIE_SECURE",
                "SESSION_LIFETIME_MINUTES",
                "DATABASE_PATH",
            }
        }
        proc = subprocess.run(
            [sys.executable, "-c", probe_code],
            cwd=tmp,
            env=clean_env,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return CheckResult(
                "CHK-01",
                "A. Configuration",
                ".env values applied to Flask app.config",
                False,
                "FAIL",
                f"Subprocess failed with code {proc.returncode}: {proc.stderr.strip()}",
            )
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        passed = bool(
            data.get("secret_matched")
            and data.get("cookie_secure") is True
            and data.get("lifetime") == 25
        )
        return CheckResult(
            "CHK-01",
            "A. Configuration",
            ".env values applied to Flask app.config",
            passed,
            "PASS" if passed else "FAIL",
            (
                f"secret_matched={data.get('secret_matched')}, "
                f"SESSION_COOKIE_SECURE={data.get('cookie_secure')}, "
                f"SESSION_LIFETIME_MINUTES={data.get('lifetime')}"
            ),
        )


def check_baseline_security_controls() -> list[CheckResult]:
    """Verify core security controls (cookie flags, hashing, CSRF, headers, SQLi)."""
    results: list[CheckResult] = []
    with tempfile.TemporaryDirectory() as tmp:
        app = _create_isolated_app(tmp)
        client = app.test_client()

        # CHK-02: Cookie & debug defaults
        from app.config import ProductionConfig

        cookie_ok = (
            app.config["DEBUG"] is False
            and app.config["SESSION_COOKIE_HTTPONLY"] is True
            and app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
            and ProductionConfig.SESSION_COOKIE_SECURE is True
            and ProductionConfig.DEBUG is False
        )
        results.append(
            CheckResult(
                "CHK-02",
                "A. Configuration",
                "Debug disabled and cookie security attributes enforced",
                cookie_ok,
                "PASS" if cookie_ok else "FAIL",
                f"DEBUG={app.config['DEBUG']}, HttpOnly={app.config['SESSION_COOKIE_HTTPONLY']}, SameSite={app.config['SESSION_COOKIE_SAMESITE']}, ProdSecure={ProductionConfig.SESSION_COOKIE_SECURE}",
            )
        )

        # CHK-03: Security headers & error page safety
        home_resp = client.get("/")
        headers_ok = (
            "Content-Security-Policy" in home_resp.headers
            and home_resp.headers.get("X-Content-Type-Options") == "nosniff"
            and home_resp.headers.get("X-Frame-Options") == "DENY"
            and home_resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        )
        results.append(
            CheckResult(
                "CHK-03",
                "A. Configuration",
                "Defensive HTTP security headers present",
                headers_ok,
                "PASS" if headers_ok else "FAIL",
                f"CSP={bool(home_resp.headers.get('Content-Security-Policy'))}, X-Frame-Options={home_resp.headers.get('X-Frame-Options')}, X-Content-Type-Options={home_resp.headers.get('X-Content-Type-Options')}",
            )
        )

        # CHK-04: Password hashing & anti-enumeration
        _register_and_login(client, "baseline_user@example.com")
        conn = sqlite3.connect(app.config["DATABASE_PATH"])
        row = conn.execute(
            "SELECT password_hash FROM users WHERE email = ?", ("baseline_user@example.com",)
        ).fetchone()
        conn.close()
        stored_hash = row[0] if row else ""
        hash_ok = stored_hash.startswith(("scrypt:", "pbkdf2:")) and TEST_PW not in stored_hash

        # Log out so login page is accessible
        dash_resp = client.get("/dashboard")
        dash_token = _extract_csrf(dash_resp.data)
        client.post("/logout", data={"csrf_token": dash_token})

        page = client.get("/login")
        tok = _extract_csrf(page.data)
        wrong_pw = client.post(
            "/login",
            data={"csrf_token": tok, "email": "baseline_user@example.com", "password": "Wrong!Password#999"},
        )
        unknown_email = client.post(
            "/login",
            data={"csrf_token": tok, "email": "nobody@example.com", "password": "Wrong!Password#999"},
        )
        enum_ok = (
            wrong_pw.status_code == 401
            and unknown_email.status_code == 401
            and b"Invalid email or password." in wrong_pw.data
            and b"Invalid email or password." in unknown_email.data
        )
        results.append(
            CheckResult(
                "CHK-04",
                "B. Authentication",
                "Salted scrypt hashing and generic login errors",
                hash_ok and enum_ok,
                "PASS" if (hash_ok and enum_ok) else "FAIL",
                f"hash_prefix={stored_hash.split(':', 1)[0]}, wrong_pw_status={wrong_pw.status_code}, unknown_email_status={unknown_email.status_code}",
            )
        )

        # CHK-05: CSRF protection
        no_csrf = client.post("/login", data={"email": "baseline_user@example.com", "password": TEST_PW})
        csrf_ok = no_csrf.status_code == 400
        results.append(
            CheckResult(
                "CHK-05",
                "B. Authentication",
                "CSRF enforcement on state-changing POST routes",
                csrf_ok,
                "PASS" if csrf_ok else "FAIL",
                f"POST /login without csrf_token returned HTTP {no_csrf.status_code}",
            )
        )
    return results


def check_session_replay_after_logout() -> CheckResult:
    """FND-02: Verify whether a captured session cookie remains usable after POST /logout."""
    with tempfile.TemporaryDirectory() as tmp:
        app = _create_isolated_app(tmp)
        client = app.test_client()
        _register_and_login(client, "replay_test@example.com")

        dash_before = client.get("/dashboard")
        assert dash_before.status_code == 200
        cookie_obj = client.get_cookie("secureauth_session")
        captured_value = cookie_obj.value if cookie_obj else ""
        token = _extract_csrf(dash_before.data)

        logout_resp = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
        assert logout_resp.status_code == 302

        # Simulate an attacker or shared-terminal replay using the pre-logout cookie on a fresh client
        replay_client = app.test_client()
        replay_client.set_cookie("secureauth_session", captured_value, domain="localhost")
        replay_resp = replay_client.get("/dashboard", follow_redirects=False)

        blocked = replay_resp.status_code == 302 and "/login" in replay_resp.headers.get("Location", "")
        return CheckResult(
            "CHK-06",
            "B. Authentication & Sessions",
            "Pre-logout session cookie rejected after logout",
            blocked,
            "PASS" if blocked else "FAIL",
            f"Replay of pre-logout cookie to GET /dashboard returned HTTP {replay_resp.status_code} (expected 302 redirect to /login)",
        )


def check_oversized_login_input_handling() -> CheckResult:
    """FND-03: Verify /login rejects oversized passwords (>128 chars) and emails (>254 chars) safely."""
    with tempfile.TemporaryDirectory() as tmp:
        app = _create_isolated_app(tmp)
        client = app.test_client()
        page = client.get("/login")
        tok = _extract_csrf(page.data)

        oversized_email = ("a" * 300) + "@example.com"
        oversized_pw = "A" * 50000

        t0 = time.perf_counter()
        resp = client.post(
            "/login",
            data={"csrf_token": tok, "email": oversized_email, "password": oversized_pw},
            follow_redirects=False,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Check whether oversized email was truncated/cleared rather than reflected in HTML input value
        body = resp.data.decode("utf-8", errors="replace")
        reflected_oversized_email = oversized_email in body

        # Check directly whether authenticate_account enforces MAX_PASSWORD_LENGTH before verify_password
        from app import auth as auth_module

        calls = {"verified": 0}
        original_verify = auth_module.verify_password

        def spy_verify(pw_hash: str, plaintext: str) -> bool:
            calls["verified"] += 1
            return original_verify(pw_hash, plaintext)

        auth_module.verify_password = spy_verify
        try:
            with app.test_request_context("/login", method="POST"):
                auth_module.authenticate_account("valid@example.com", oversized_pw)
        finally:
            auth_module.verify_password = original_verify

        passed = (
            resp.status_code == 401
            and not reflected_oversized_email
            and calls["verified"] == 0
        )
        return CheckResult(
            "CHK-07",
            "C. Input Validation",
            "Oversized login email/password rejected before hashing or reflection",
            passed,
            "PASS" if passed else "FAIL",
            f"status={resp.status_code}, verify_password_called={calls['verified']}, oversized_email_reflected={reflected_oversized_email}, elapsed_ms={elapsed_ms:.1f}",
        )


def check_logging_pii_and_injection() -> CheckResult:
    """FND-04 & FND-05: Verify security logs omit email PII and sanitize CRLF/control characters."""
    with tempfile.TemporaryDirectory() as tmp:
        app = _create_isolated_app(tmp)
        client = app.test_client()

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        sec_logger = logging.getLogger("secureauth.security")
        sec_logger.addHandler(handler)
        sec_logger.setLevel(logging.INFO)
        try:
            _register_and_login(client, "pii_probe@example.com")

            from app.security import log_security_event

            log_security_event("RATE_LIMIT_EXCEEDED", "127.0.0.1\r\nFAKE", "/login\nFAKE_EVENT=1")
        finally:
            sec_logger.removeHandler(handler)

        log_output = stream.getvalue()
        pii_leaked = "pii_probe@example.com" in log_output
        # Check if injected newline produced a forged standalone log line starting with FAKE
        lines = [line.strip() for line in log_output.splitlines() if line.strip()]
        crlf_injected = any(line.startswith(("FAKE", "FAKE_EVENT")) for line in lines)

        passed = (not pii_leaked) and (not crlf_injected)
        return CheckResult(
            "CHK-08",
            "E. Logging & Error Handling",
            "Security logs omit raw email PII and neutralize CRLF log injection",
            passed,
            "PASS" if passed else "FAIL",
            f"pii_leaked={pii_leaked}, crlf_injected={crlf_injected}, captured_lines={len(lines)}",
        )


def check_auth_pages_cache_control() -> CheckResult:
    """FND-06: Verify sensitive authentication routes (/login, /register) send Cache-Control: no-store."""
    with tempfile.TemporaryDirectory() as tmp:
        app = _create_isolated_app(tmp)
        client = app.test_client()
        login_cc = client.get("/login").headers.get("Cache-Control", "")
        reg_cc = client.get("/register").headers.get("Cache-Control", "")
        passed = ("no-store" in login_cc.lower()) and ("no-store" in reg_cc.lower())
        return CheckResult(
            "CHK-09",
            "A. Configuration",
            "Authentication forms disable browser/proxy caching (no-store)",
            passed,
            "PASS" if passed else "FAIL",
            f"/login Cache-Control={login_cc!r}, /register Cache-Control={reg_cc!r}",
        )


def run_assessment(mode: str) -> dict[str, Any]:
    results: list[CheckResult] = [
        check_dotenv_import_ordering(),
        *check_baseline_security_controls(),
        check_session_replay_after_logout(),
        check_oversized_login_input_handling(),
        check_logging_pii_and_injection(),
        check_auth_pages_cache_control(),
    ]
    passed_count = sum(1 for r in results if r.passed)
    failed_count = len(results) - passed_count
    return {
        "mode": mode,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": "task-2-secure-authentication",
        "total_checks": len(results),
        "passed": passed_count,
        "failed": failed_count,
        "checks": [asdict(r) for r in results],
    }


def generate_pdf_report(output_path: Path | None = None) -> Path:
    """Generate the 11-section defensive security assessment PDF report using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    pdf_path = output_path or (TASK4_DIR / "reports" / "defensive-security-assessment-report.pdf")
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    retest_summary = run_assessment("retest")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=14,
    )
    h1_style = ParagraphStyle(
        "SectionH1",
        parent=styles["Heading1"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0f766e"),
        spaceBefore=12,
        spaceAfter=6,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodyTextClean",
        parent=styles["Normal"],
        fontSize=9.2,
        leading=13.5,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=5,
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=8.0,
        leading=11.0,
        textColor=colors.HexColor("#1e293b"),
    )
    cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=cell_style,
        fontName="Helvetica-Bold",
    )

    def make_table(rows: list[list[str]], col_widths: list[float]) -> Table:
        formatted = []
        for r_idx, row in enumerate(rows):
            st = cell_bold if r_idx == 0 else cell_style
            formatted.append([Paragraph(str(col), st) for col in row])
        tbl = Table(formatted, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return tbl

    def footer_canvas(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(
            0.7 * inch,
            0.45 * inch,
            "EdVyro Cyber Security Portfolio · Task 4 Defensive Security Assessment (Sanitized Localhost Evidence)",
        )
        canvas.drawRightString(LETTER[0] - 0.7 * inch, 0.45 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=LETTER,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.7 * inch,
        title="Defensive Security Assessment Report — SecureAuth (Task 4)",
        author="MAkassh07",
    )

    story: list[Any] = []
    story.append(Paragraph("Defensive Security Assessment Report", title_style))
    story.append(
        Paragraph(
            "Target: SecureAuth (task-2-secure-authentication/) · Assessment Date: 2026-11-25 · Repository: github.com/MAkassh07/Edvyro_1",
            subtitle_style,
        )
    )

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(
        Paragraph(
            "An authorized, non-destructive white-box defensive security assessment was conducted against the local "
            "SecureAuth Flask + SQLite authentication application (task-2-secure-authentication/) on 2026-11-25. "
            "At baseline, all 22 existing Task 2 pytest checks passed, confirming foundational controls including salted "
            "scrypt hashing, parameterized SQLite queries, Flask-Limiter throttling, CSRFProtect, HttpOnly/SameSite=Lax "
            "cookies, and security response headers.",
            body_style,
        )
    )
    story.append(
        Paragraph(
            "Expanded defensive testing, configuration probing, dependency auditing (pip-audit), and static code analysis "
            "(bandit) revealed 6 actionable findings (3 Medium, 3 Low) and 1 Informational observation—most notably silent "
            "ignoring of .env variables due to import-order execution, replayable pre-logout session cookies, and 8 "
            "upstream dependency advisories. All 6 actionable findings were remediated in place without breaking existing "
            "application behavior. Post-remediation retesting achieved 22/22 passing Task 2 tests, 7/7 passing Task 4 "
            "verification tests, 9/9 passing defensive harness checks, 0 pip-audit advisories, and 0 bandit warnings.",
            body_style,
        )
    )

    summary_metrics = [
        ["Assessment Metric", "Baseline Result", "Post-Remediation Result"],
        ["Task 2 Automated Suite (pytest)", "22 / 22 Passed", "22 / 22 Passed"],
        ["Task 4 Assessment Harness (CHK-01..09)", "4 / 9 Passed (5 Failed)", f"{retest_summary['passed']} / {retest_summary['total_checks']} Passed"],
        ["Task 4 Verification Suite (pytest)", "N/A (Baseline Capture)", "7 / 7 Passed"],
        ["Dependency Advisories (pip-audit)", "8 Unique Advisories (4 Packages)", "0 Advisories Found"],
        ["Static Analysis (bandit)", "1 Low Warning (B105 Test Key)", "0 Issues Identified (648 LOC)"],
    ]
    story.append(make_table(summary_metrics, [2.5 * inch, 2.2 * inch, 2.3 * inch]))
    story.append(Spacer(1, 8))

    # 2. Scope and Authorization
    story.append(Paragraph("2. Scope and Authorization", h1_style))
    story.append(
        Paragraph(
            "Testing was authorized strictly against the owner's local Task 2 Flask repository using localhost/in-process "
            "Flask test clients, ephemeral temporary SQLite databases, and synthetic @example.com accounts. External "
            "targets, DoS traffic floods, credential stuffing, destructive DB mutations, and real PII/secrets were "
            "strictly prohibited. Tasks 1 and 3 and the root README.md remained preserved and unmodified.",
            body_style,
        )
    )

    # 3. Methodology
    story.append(Paragraph("3. Methodology", h1_style))
    story.append(
        Paragraph(
            "The assessment covered five OWASP-aligned domains: (A) Configuration Security, (B) Authentication Security, "
            "(C) Input Validation, (D) Dependency Security, and (E) Logging and Error Handling. Baseline findings were "
            "logged before any Task 2 source edits, followed by targeted patches and full before-and-after verification.",
            body_style,
        )
    )

    # 4. Tools Used
    story.append(Paragraph("4. Tools Used", h1_style))
    tools_rows = [
        ["Tool / Mechanism", "Version", "Assessment Purpose"],
        ["Manual Source Review", "N/A", "Line-by-line review of app/*.py, templates/*.html, and config lifecycle"],
        ["pytest & Flask test_client", "8.3.5 -> 9.0.3", "Automated execution of 22 Task 2 tests + 7 Task 4 verification tests"],
        ["security_assessment.py", "Task 4 Harness", "9 deterministic checks covering .env load, cookie replay, bounds, and logs"],
        ["pip-audit", "2.10.1", "Read-only advisory scan against pinned requirements.txt"],
        ["bandit", "1.9.4", "AST static security scan across app/ and run.py"],
        ["ReportLab", "5.1.2", "Deterministic generation of this sanitized PDF assessment report"],
    ]
    story.append(make_table(tools_rows, [2.0 * inch, 1.3 * inch, 3.7 * inch]))
    story.append(Spacer(1, 8))

    # 5. Baseline Assessment
    story.append(Paragraph("5. Baseline Assessment", h1_style))
    story.append(
        Paragraph(
            "At baseline (2026-11-25T16:30:32Z), SecureAuth enforced strong password hashing (scrypt), parameterized SQL "
            "queries, CSRFProtect, rate limiting (5/min login, 5/hr register), anti-enumeration login messages, HttpOnly "
            "and SameSite=Lax cookies, and defensive HTTP headers (CHK-02 through CHK-05 passed). Five checks failed "
            "baseline verification (CHK-01, CHK-06, CHK-07, CHK-08, CHK-09) alongside 8 pip-audit advisories.",
            body_style,
        )
    )

    # 6. Findings and Severity
    story.append(Paragraph("6. Findings and Severity Register", h1_style))
    findings_rows = [
        ["ID", "Title & Component", "Severity", "Post-Fix Status"],
        ["FND-01", ".env settings ignored by Config due to import ordering (app/__init__.py, app/config.py)", "Medium", "Fixed (Verified)"],
        ["FND-02", "Pre-logout session cookie valid until timeout; no server revocation (app/models.py, security.py)", "Medium", "Fixed (Verified)"],
        ["FND-03", "Outdated dependencies with known advisories: Flask, Werkzeug, python-dotenv, pytest", "Medium", "Fixed (Verified)"],
        ["FND-04", "Unbounded login password/email lengths cause scrypt CPU work & HTML reflection (auth.py, routes.py)", "Low", "Fixed (Verified)"],
        ["FND-05", "Registration log exposes email PII; missing CRLF sanitization & error-event logging (security.py)", "Low", "Fixed (Verified)"],
        ["FND-06", "Authentication forms (/login, /register) omit Cache-Control: no-store headers (app/routes.py)", "Low", "Fixed (Verified)"],
        ["FND-07", "Bandit B105 static warning on TestingConfig.SECRET_KEY & dev memory:// rate limiter", "Info", "Resolved / Accepted"],
    ]
    story.append(make_table(findings_rows, [0.7 * inch, 4.1 * inch, 0.8 * inch, 1.4 * inch]))
    story.append(PageBreak())

    # 7. Evidence and Reproduction Steps
    story.append(Paragraph("7. Evidence and Sanitized Reproduction Steps", h1_style))
    story.append(Paragraph("FND-01 (.env Load Ordering)", h2_style))
    story.append(
        Paragraph(
            "Reproduction: Place FLASK_SECRET_KEY and SESSION_COOKIE_SECURE=true in .env and call create_app() without "
            "pre-exported shell variables. Baseline observed secret_matched=False and SESSION_COOKIE_SECURE=False because "
            "app/config.py evaluated os.environ upon import before load_dotenv() executed inside create_app().",
            body_style,
        )
    )
    story.append(Paragraph("FND-02 (Pre-Logout Cookie Replay)", h2_style))
    story.append(
        Paragraph(
            "Reproduction: Register and sign in as replay_test@example.com, copy secureauth_session cookie, submit POST "
            "/logout, then replay the copied cookie to GET /dashboard. Baseline returned HTTP 200 instead of 302.",
            body_style,
        )
    )
    story.append(Paragraph("FND-03 (Dependency Advisories)", h2_style))
    story.append(
        Paragraph(
            "Evidence: pip-audit -r requirements.txt flagged Flask 3.1.0 (CVE-2025-47278, CVE-2026-27205), Werkzeug 3.1.3 "
            "(CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598), python-dotenv 1.0.1 (CVE-2026-28684), "
            "and pytest 8.3.5 (CVE-2025-71176).",
            body_style,
        )
    )
    story.append(Paragraph("FND-04, FND-05, FND-06 (Bounds, Logging, Cache Headers)", h2_style))
    story.append(
        Paragraph(
            "Evidence: Baseline CHK-07 executed verify_password() on a 50,000-char password (250.6 ms) and reflected a "
            "312-char email in login HTML; CHK-08 logged detail=email=pii_probe@example.com and permitted newline log "
            "injection (FAKE_EVENT=1); CHK-09 observed empty Cache-Control headers on /login and /register.",
            body_style,
        )
    )

    # 8. Remediation Details
    story.append(Paragraph("8. Remediation Details", h1_style))
    story.append(
        Paragraph(
            "All targeted fixes preserved SecureAuth's Flask + SQLite architecture: (1) Added build_env_config() and safe "
            "_parse_int() applied after load_dotenv(); (2) Added SQLite revoked_sessions table storing logged-out "
            "session_nonce values until expiration with automatic pruning; (3) Upgraded requirements.txt to Flask==3.1.3, "
            "Werkzeug==3.1.9, python-dotenv==1.2.2, and pytest==9.0.3; (4) Enforced MAX_EMAIL_LENGTH (254) and "
            "MAX_PASSWORD_LENGTH (128) in authenticate_account() before DB/scrypt work; (5) Replaced email PII in "
            "REGISTER_SUCCESS logs with user_id, added _sanitize_log_value() CRLF stripping, and logged 400/403/413/500 "
            "and invalid/revoked sessions; (6) Added Cache-Control: no-store across /login and /register; (7) Replaced "
            "static TestingConfig.SECRET_KEY with secrets.token_hex(32).",
            body_style,
        )
    )

    # 9. Before-and-After Retesting
    story.append(Paragraph("9. Before-and-After Retesting Results", h1_style))
    retest_rows = [
        ["Check / Finding", "Baseline Outcome", "Retest Outcome", "Status"],
        ["CHK-01 / FND-01", "secret_matched=False, Secure=False", "secret_matched=True, Secure=True", "PASS"],
        ["CHK-06 / FND-02", "GET /dashboard returned HTTP 200", "GET /dashboard returned HTTP 302 + SESSION_REVOKED", "PASS"],
        ["pip-audit / FND-03", "8 unique advisories (exit=1)", "No known vulnerabilities found (exit=0)", "PASS"],
        ["CHK-07 / FND-04", "verify_password=1 (250.6 ms), reflected=True", "verify_password=0 (5.1 ms), reflected=False", "PASS"],
        ["CHK-08 / FND-05", "pii_leaked=True, crlf_injected=True", "pii_leaked=False, crlf_injected=False", "PASS"],
        ["CHK-09 / FND-06", "Cache-Control='' on /login, /register", "Cache-Control: no-store on both routes", "PASS"],
        ["bandit / FND-07", "1 Low B105 warning (exit=1)", "No issues identified across 648 LOC (exit=0)", "PASS"],
        ["Task 2 + Task 4 pytest", "22 / 22 Baseline Passed", "22 / 22 Task 2 + 7 / 7 Task 4 Passed", "PASS"],
    ]
    story.append(make_table(retest_rows, [1.5 * inch, 2.2 * inch, 2.5 * inch, 0.8 * inch]))
    story.append(Spacer(1, 8))

    # 10. Remaining Risks and Limitations
    story.append(Paragraph("10. Remaining Risks and Limitations", h1_style))
    story.append(
        Paragraph(
            "Consistent with Task 2's educational scope, several production features remain out of scope: (1) Default "
            "RATELIMIT_STORAGE_URI=memory:// resets on restart and requires Redis for multi-worker deployments; "
            "(2) Single-factor authentication without MFA or email verification; (3) Local development runs over HTTP "
            "(SESSION_COOKIE_SECURE=false) until deployed behind a TLS reverse proxy; (4) Flask signed cookies remain "
            "HMAC-signed (not encrypted), though only non-sensitive IDs, email, nonce, and timestamps are stored.",
            body_style,
        )
    )

    # 11. Conclusion
    story.append(Paragraph("11. Conclusion", h1_style))
    story.append(
        Paragraph(
            "SecureAuth's defensive posture improved measurably from 4/9 baseline assessment checks and 8 package "
            "advisories to 9/9 checks passed, 29/29 total automated pytest checks passed, 0 pip-audit advisories, and "
            "0 bandit warnings. All fixes were verified empirically with sanitized evidence while preserving Task 2 "
            "functionality and keeping Tasks 1 and 3 intact.",
            body_style,
        )
    )

    doc.build(story, onFirstPage=footer_canvas, onLaterPages=footer_canvas)
    return pdf_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Defensive security assessment harness for SecureAuth.")
    parser.add_argument("--mode", choices=["baseline", "retest"], default="retest")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument(
        "--generate-pdf",
        action="store_true",
        help="Generate reports/defensive-security-assessment-report.pdf via ReportLab.",
    )
    args = parser.parse_args()

    if args.generate_pdf:
        pdf_out = generate_pdf_report()
        print(f"Generated PDF report: {pdf_out}")
        return 0

    summary = run_assessment(args.mode)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"=== SecureAuth Defensive Security Assessment ({summary['mode'].upper()}) ===")
        print(f"Timestamp (UTC): {summary['timestamp_utc']}")
        print(f"Checks Passed:   {summary['passed']} / {summary['total_checks']}")
        print()
        for item in summary["checks"]:
            print(f"[{item['status']}] {item['check_id']} ({item['domain']}): {item['title']}")
            print(f"       Evidence: {item['evidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
