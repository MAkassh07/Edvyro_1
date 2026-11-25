"""Application configuration classes for SecureAuth."""

import os
import secrets
from datetime import timedelta


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Config:
    """Base configuration driven by environment variables."""

    FLASK_ENV = os.environ.get("FLASK_ENV", "development").strip().lower()
    DEBUG = _parse_bool(os.environ.get("FLASK_DEBUG"), default=False)
    TESTING = False

    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
    DATABASE_PATH = os.environ.get("DATABASE_PATH", "instance/secureauth.db")

    # Cookie-based session hardening
    SESSION_COOKIE_NAME = "secureauth_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _parse_bool(os.environ.get("SESSION_COOKIE_SECURE"), default=False)

    SESSION_LIFETIME_MINUTES = max(1, int(os.environ.get("SESSION_LIFETIME_MINUTES", "15")))
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_LIFETIME_MINUTES)
    SESSION_TIMEOUT_SECONDS = SESSION_LIFETIME_MINUTES * 60

    # CSRF & request size limits
    WTF_CSRF_ENABLED = _parse_bool(os.environ.get("WTF_CSRF_ENABLED"), default=True)
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = 1024 * 1024  # 1 MB limit to prevent oversized payloads

    # Rate limiting storage
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True


class ProductionConfig(Config):
    """Hardened configuration for HTTPS production deployments."""

    FLASK_ENV = "production"
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class TestingConfig(Config):
    """Isolated deterministic configuration for pytest."""

    FLASK_ENV = "testing"
    TESTING = True
    DEBUG = False
    SECRET_KEY = "test-only-ephemeral-signing-key-not-for-production"
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
    RATELIMIT_STORAGE_URI = "memory://"
