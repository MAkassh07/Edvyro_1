"""Password hashing, server-side input validation, session lifecycle, and safe audit logging."""

import hashlib
import logging
import re
import secrets
import time
from typing import Any
from flask import current_app, session
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import get_public_user_by_id

security_logger = logging.getLogger("secureauth.security")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
SPECIAL_CHARS_REGEX = re.compile(r"[^A-Za-z0-9\s]")

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MAX_EMAIL_LENGTH = 254

_DUMMY_HASH: str | None = None


def preferred_hash_method() -> str:
    """Use scrypt when supported by OpenSSL/hashlib, otherwise PBKDF2-SHA256."""
    return "scrypt" if hasattr(hashlib, "scrypt") else "pbkdf2:sha256:600000"


def hash_password(plaintext_password: str) -> str:
    """Hash a password with a cryptographic salt via Werkzeug."""
    return generate_password_hash(plaintext_password, method=preferred_hash_method())


def verify_password(password_hash: str, plaintext_password: str) -> bool:
    """Verify a plaintext password against a stored Werkzeug hash."""
    if not password_hash or not plaintext_password:
        return False
    return check_password_hash(password_hash, plaintext_password)


def get_dummy_hash() -> str:
    """Return a cached dummy hash used to equalize timing on unknown accounts."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("Dummy!Constant#Time1234")
    return _DUMMY_HASH


def normalize_email(raw_email: Any) -> str:
    """Normalize user email input consistently."""
    if not isinstance(raw_email, str):
        return ""
    return raw_email.strip().lower()


def validate_email(raw_email: Any) -> tuple[bool, str | None]:
    """Validate email format, length, and safe characters on the server."""
    if not isinstance(raw_email, str):
        return False, "A valid email address is required."

    email = normalize_email(raw_email)
    if not email:
        return False, "Email address is required."
    if len(email) > MAX_EMAIL_LENGTH:
        return False, f"Email address must not exceed {MAX_EMAIL_LENGTH} characters."
    if any(ch in email for ch in ("\r", "\n", "\x00")):
        return False, "Email address contains invalid characters."
    if not EMAIL_REGEX.match(email):
        return False, "Please enter a valid email address."
    return True, None


def validate_password(raw_password: Any) -> tuple[bool, list[str]]:
    """Enforce server-side password length and complexity policy."""
    errors: list[str] = []
    if not isinstance(raw_password, str) or not raw_password:
        return False, ["Password is required."]
    if "\x00" in raw_password:
        return False, ["Password contains unsupported characters."]
    if len(raw_password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(raw_password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must not exceed {MAX_PASSWORD_LENGTH} characters.")
    if not any(c.isupper() for c in raw_password):
        errors.append("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in raw_password):
        errors.append("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in raw_password):
        errors.append("Password must contain at least one number.")
    if not SPECIAL_CHARS_REGEX.search(raw_password):
        errors.append("Password must contain at least one special character (e.g., !@#$%^&*).")

    return len(errors) == 0, errors


def create_authenticated_session(user: dict[str, Any]) -> None:
    """Clear any existing session state and establish a fresh authenticated session."""
    session.clear()
    now = time.time()
    session.permanent = True
    session["user_id"] = user["id"]
    session["user_email"] = user["email"]
    session["session_nonce"] = secrets.token_urlsafe(16)
    session["issued_at"] = now
    session["last_active_at"] = now


def clear_authenticated_session() -> None:
    """Clear all session keys on logout or expiration."""
    session.clear()


def validate_active_session() -> tuple[bool, dict[str, Any] | None, str | None]:
    """Validate active session existence, inactivity timeout, and user record."""
    user_id = session.get("user_id")
    last_active_at = session.get("last_active_at")
    issued_at = session.get("issued_at")

    if not isinstance(user_id, int) or not isinstance(last_active_at, (int, float)):
        return False, None, "unauthenticated"

    timeout_seconds = current_app.config.get("SESSION_TIMEOUT_SECONDS", 900)
    now = time.time()

    if (now - float(last_active_at)) > timeout_seconds:
        clear_authenticated_session()
        return False, None, "expired"

    if isinstance(issued_at, (int, float)) and (now - float(issued_at)) > (timeout_seconds * 48):
        clear_authenticated_session()
        return False, None, "expired"

    user = get_public_user_by_id(user_id)
    if user is None:
        clear_authenticated_session()
        return False, None, "invalid"

    # Slide activity window on verified request
    session["last_active_at"] = now
    return True, user, None


def log_security_event(event_type: str, ip_address: str | None, detail: str) -> None:
    """Record structured security events without ever logging passwords or tokens."""
    safe_ip = ip_address or "unknown"
    security_logger.info("event=%s ip=%s detail=%s", event_type, safe_ip, detail)
