"""Application configuration classes for SecureAuth."""

import os
import secrets
from datetime import timedelta


def _parse_bool(value: str | None, default: bool, name: str) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


def _parse_int(
    value: str | None,
    default: int,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if value is None:
        return default
    try:
        parsed = int(value.strip())
    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer between {minimum} and {maximum}."
        ) from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}.")
    return parsed


def build_env_config() -> dict[str, object]:
    """Build runtime configuration after dotenv has populated the environment."""
    flask_env = os.environ.get("FLASK_ENV", "development").strip().lower()
    if flask_env not in {"development", "testing", "production"}:
        raise ValueError("FLASK_ENV must be development, testing, or production.")

    debug = _parse_bool(os.environ.get("FLASK_DEBUG"), False, "FLASK_DEBUG")
    if flask_env == "production" and debug:
        raise ValueError("FLASK_DEBUG must be disabled in production.")

    session_cookie_secure = _parse_bool(
        os.environ.get("SESSION_COOKIE_SECURE"),
        flask_env == "production",
        "SESSION_COOKIE_SECURE",
    )
    if flask_env == "production" and not session_cookie_secure:
        raise ValueError("SESSION_COOKIE_SECURE must be enabled in production.")

    session_lifetime_minutes = _parse_int(
        os.environ.get("SESSION_LIFETIME_MINUTES"),
        15,
        "SESSION_LIFETIME_MINUTES",
        1,
        1440,
    )

    secret_key = os.environ.get("FLASK_SECRET_KEY")
    if flask_env == "production" and not secret_key:
        raise ValueError("FLASK_SECRET_KEY must be set in production environments.")
    if not secret_key:
        secret_key = secrets.token_hex(32)
    if flask_env == "production" and len(secret_key) < 32:
        raise ValueError("FLASK_SECRET_KEY must contain at least 32 characters in production.")

    return {
        "FLASK_ENV": flask_env,
        "DEBUG": debug,
        "SECRET_KEY": secret_key,
        "DATABASE_PATH": os.environ.get("DATABASE_PATH") or "instance/secureauth.db",
        "SESSION_COOKIE_SECURE": session_cookie_secure,
        "SESSION_LIFETIME_MINUTES": session_lifetime_minutes,
        "PERMANENT_SESSION_LIFETIME": timedelta(minutes=session_lifetime_minutes),
        "SESSION_TIMEOUT_SECONDS": session_lifetime_minutes * 60,
        "WTF_CSRF_ENABLED": _parse_bool(
            os.environ.get("WTF_CSRF_ENABLED"), True, "WTF_CSRF_ENABLED"
        ),
        "RATELIMIT_STORAGE_URI": os.environ.get("RATELIMIT_STORAGE_URI") or "memory://",
    }


class Config:
    """Base configuration driven by environment variables."""

    FLASK_ENV = "development"
    DEBUG = False
    TESTING = False

    SECRET_KEY = secrets.token_hex(32)
    DATABASE_PATH = "instance/secureauth.db"

    # Cookie-based session hardening
    SESSION_COOKIE_NAME = "secureauth_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False

    SESSION_LIFETIME_MINUTES = 15
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_LIFETIME_MINUTES)
    SESSION_TIMEOUT_SECONDS = SESSION_LIFETIME_MINUTES * 60

    # CSRF & request size limits
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 1024 * 1024  # 1 MB limit to prevent oversized payloads

    # Rate limiting storage
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_HEADERS_ENABLED = True


class ProductionConfig(Config):
    """Hardened configuration for HTTPS production deployments."""

    FLASK_ENV = "production"
    DEBUG = False
    TESTING = False
    SECRET_KEY = None
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class TestingConfig(Config):
    """Isolated deterministic configuration for pytest."""

    FLASK_ENV = "testing"
    TESTING = True
    DEBUG = False
    SECRET_KEY = secrets.token_hex(32)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"
