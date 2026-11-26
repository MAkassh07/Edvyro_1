"""Authentication business logic and route protection decorator."""

from functools import wraps
from typing import Any, Callable
from flask import flash, g, redirect, request, url_for
from app.models import create_user, get_user_for_auth
from app.security import (
    create_authenticated_session,
    get_dummy_hash,
    hash_password,
    log_security_event,
    MAX_EMAIL_LENGTH,
    MAX_PASSWORD_LENGTH,
    normalize_email,
    validate_active_session,
    validate_email,
    validate_password,
    verify_password,
)

GENERIC_LOGIN_ERROR = "Invalid email or password."
GENERIC_REGISTER_DUPLICATE_ERROR = (
    "Unable to complete registration with the provided details. Please verify your input or sign in."
)


def register_account(
    raw_email: Any, raw_password: Any, raw_confirm_password: Any
) -> tuple[bool, list[str]]:
    """Validate registration payload, enforce password policy, and store hashed credentials."""
    email_ok, email_err = validate_email(raw_email)
    if not email_ok:
        return False, [email_err or "Invalid email address."]

    password_ok, password_errors = validate_password(raw_password)
    if not password_ok:
        return False, password_errors

    if not isinstance(raw_confirm_password, str) or raw_password != raw_confirm_password:
        return False, ["Password and confirmation password do not match."]

    normalized_email = normalize_email(raw_email)
    existing = get_user_for_auth(normalized_email)
    if existing is not None:
        log_security_event("REGISTER_DUPLICATE", request.remote_addr, "duplicate email rejected")
        return False, [GENERIC_REGISTER_DUPLICATE_ERROR]

    password_hash = hash_password(raw_password)
    created, user_id = create_user(normalized_email, password_hash)
    if not created:
        log_security_event("REGISTER_CONFLICT", request.remote_addr, "unique constraint conflict")
        return False, [GENERIC_REGISTER_DUPLICATE_ERROR]

    log_security_event("REGISTER_SUCCESS", request.remote_addr, f"user_id={user_id}")
    return True, []


def authenticate_account(raw_email: Any, raw_password: Any) -> tuple[bool, dict[str, Any] | None, str]:
    """Authenticate a user with generic error messages and timing equalization."""
    if not isinstance(raw_email, str) or not isinstance(raw_password, str):
        return False, None, GENERIC_LOGIN_ERROR

    email = normalize_email(raw_email)
    email_valid, _email_error = validate_email(raw_email)
    if (
        not email_valid
        or len(email) > MAX_EMAIL_LENGTH
        or not raw_password
        or len(raw_password) > MAX_PASSWORD_LENGTH
        or "\x00" in raw_password
    ):
        log_security_event("LOGIN_FAILED", request.remote_addr, "invalid input")
        return False, None, GENERIC_LOGIN_ERROR

    user = get_user_for_auth(email)
    if user is None:
        # Execute a dummy hash verification to avoid account enumeration via response timing
        verify_password(get_dummy_hash(), raw_password)
        log_security_event("LOGIN_FAILED", request.remote_addr, "unknown account")
        return False, None, GENERIC_LOGIN_ERROR

    if not verify_password(user["password_hash"], raw_password):
        log_security_event("LOGIN_FAILED", request.remote_addr, f"user_id={user['id']}")
        return False, None, GENERIC_LOGIN_ERROR

    safe_user = {
        "id": user["id"],
        "email": user["email"],
        "created_at": user["created_at"],
    }
    create_authenticated_session(safe_user)
    log_security_event("LOGIN_SUCCESS", request.remote_addr, f"user_id={user['id']}")
    return True, safe_user, ""


def login_required(view: Callable[..., Any]) -> Callable[..., Any]:
    """Protect routes from unauthenticated or expired sessions."""

    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        is_valid, user, reason = validate_active_session()
        if not is_valid or user is None:
            if reason == "expired":
                flash("Your session expired due to inactivity. Please sign in again.", "warning")
            else:
                flash("Please sign in to access your dashboard.", "warning")
            return redirect(url_for("main.login"))

        g.current_user = user
        return view(*args, **kwargs)

    return wrapped_view
