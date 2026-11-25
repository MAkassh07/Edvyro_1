"""Flask route handlers for SecureAuth."""

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from app.auth import authenticate_account, login_required, register_account
from app.extensions import limiter
from app.security import (
    clear_authenticated_session,
    log_security_event,
    normalize_email,
    validate_active_session,
)

main_bp = Blueprint("main", __name__)


@main_bp.route("/", methods=["GET"])
def index():
    """Render the SecureAuth home page."""
    is_valid, user, _reason = validate_active_session()
    return render_template("index.html", current_user=user if is_valid else None)


@main_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", exempt_when=lambda: request.method != "POST")
def register():
    """Render registration form and process new account sign-ups."""
    is_valid, user, _reason = validate_active_session()
    if is_valid and user is not None:
        return redirect(url_for("main.dashboard"))

    errors: list[str] = []
    submitted_email = ""

    if request.method == "POST":
        submitted_email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        success, errors = register_account(submitted_email, password, confirm_password)
        if success:
            flash("Account created successfully. Please sign in.", "success")
            return redirect(url_for("main.login"))

        return render_template(
            "register.html",
            errors=errors,
            email=submitted_email,
        ), 400

    return render_template("register.html", errors=errors, email=submitted_email)


@main_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", exempt_when=lambda: request.method != "POST")
def login():
    """Render login form and authenticate credentials."""
    is_valid, user, _reason = validate_active_session()
    if is_valid and user is not None:
        return redirect(url_for("main.dashboard"))

    error: str | None = None
    submitted_email = ""

    if request.method == "POST":
        submitted_email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")

        success, _authed_user, err_msg = authenticate_account(submitted_email, password)
        if success:
            flash("Signed in securely.", "success")
            return redirect(url_for("main.dashboard"))

        error = err_msg
        return render_template("login.html", error=error, email=submitted_email), 401

    return render_template("login.html", error=error, email=submitted_email)


@main_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    """Render protected user dashboard displaying only the authenticated user's profile."""
    timeout_minutes = current_app.config.get("SESSION_LIFETIME_MINUTES", 15)
    response = make_response(
        render_template(
            "dashboard.html",
            user=g.current_user,
            timeout_minutes=timeout_minutes,
        )
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@main_bp.route("/logout", methods=["POST"])
def logout():
    """Clear the authenticated session and redirect to login."""
    is_valid, user, _reason = validate_active_session()
    if is_valid and user is not None:
        log_security_event("LOGOUT", request.remote_addr, f"user_id={user['id']}")

    clear_authenticated_session()
    flash("You have been logged out securely.", "success")
    return redirect(url_for("main.login"))
