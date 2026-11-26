"""Tests for environment-backed configuration and generated test secrets."""

import re
import secrets

import pytest
from app import create_app
from app.config import ProductionConfig, TestingConfig, build_env_config


@pytest.fixture()
def development_environment(monkeypatch):
    defaults = {
        "FLASK_ENV": "development",
        "FLASK_DEBUG": "false",
        "FLASK_SECRET_KEY": secrets.token_hex(32),
        "SESSION_COOKIE_SECURE": "false",
        "SESSION_LIFETIME_MINUTES": "15",
        "WTF_CSRF_ENABLED": "true",
        "DATABASE_PATH": "instance/test-secureauth.db",
        "RATELIMIT_STORAGE_URI": "memory://",
    }
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)
    return defaults


def test_runtime_environment_is_read_when_config_is_built(
    monkeypatch, development_environment
):
    dotenv_secret = secrets.token_hex(32)
    monkeypatch.setenv("FLASK_SECRET_KEY", dotenv_secret)
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    monkeypatch.setenv("SESSION_LIFETIME_MINUTES", "25")

    config = build_env_config()

    assert config["SECRET_KEY"] == dotenv_secret
    assert config["SESSION_COOKIE_SECURE"] is True
    assert config["SESSION_LIFETIME_MINUTES"] == 25
    assert config["SESSION_TIMEOUT_SECONDS"] == 1500


@pytest.mark.parametrize("value", ["", "invalid", "1.5", "0", "1441"])
def test_invalid_session_lifetime_is_rejected(
    monkeypatch, development_environment, value
):
    monkeypatch.setenv("SESSION_LIFETIME_MINUTES", value)

    with pytest.raises(ValueError, match="SESSION_LIFETIME_MINUTES"):
        build_env_config()


def test_invalid_boolean_configuration_is_rejected(
    monkeypatch, development_environment
):
    monkeypatch.setenv("FLASK_DEBUG", "sometimes")

    with pytest.raises(ValueError, match="FLASK_DEBUG"):
        build_env_config()


def test_production_configuration_rejects_insecure_values(
    monkeypatch, development_environment
):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("FLASK_DEBUG", "false")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")

    with pytest.raises(ValueError, match="SESSION_COOKIE_SECURE"):
        build_env_config()


def test_production_environment_requires_explicit_secret(
    monkeypatch, development_environment
):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("FLASK_DEBUG", "false")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    monkeypatch.delenv("FLASK_SECRET_KEY")

    with pytest.raises(ValueError, match="FLASK_SECRET_KEY"):
        build_env_config()


def test_testing_secret_is_generated_not_hardcoded():
    assert re.fullmatch(r"[0-9a-f]{64}", TestingConfig.SECRET_KEY)


def test_production_config_uses_environment_secret(monkeypatch, tmp_path):
    class IsolatedProductionConfig(ProductionConfig):
        SECRET_KEY = None
        DATABASE_PATH = str(tmp_path / "production.db")

    secret = secrets.token_hex(32)
    monkeypatch.setenv("FLASK_SECRET_KEY", secret)

    app = create_app(IsolatedProductionConfig)

    assert app.config["SECRET_KEY"] == secret


def test_production_config_rejects_missing_environment_secret(monkeypatch, tmp_path):
    class IsolatedProductionConfig(ProductionConfig):
        SECRET_KEY = None
        DATABASE_PATH = str(tmp_path / "production.db")

    monkeypatch.delenv("FLASK_SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="FLASK_SECRET_KEY"):
        create_app(IsolatedProductionConfig)
