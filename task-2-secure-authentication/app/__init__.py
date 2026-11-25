"""Flask application factory for SecureAuth."""

import logging
import os
from typing import Any
from dotenv import load_dotenv
from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from app.config import Config
from app.extensions import csrf, limiter
from app.models import init_app as init_db_app
from app.routes import main_bp
from app.security import log_security_event


def create_app(test_config: dict[str, Any] | type[Config] | None = None) -> Flask:
    """Create and configure a SecureAuth Flask application instance."""
    load_dotenv()

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    if test_config is not None:
        if isinstance(test_config, dict):
            app.config.update(test_config)
        else:
            app.config.from_object(test_config)

    if (
        test_config is None
        and app.config.get("FLASK_ENV") == "production"
        and not os.environ.get("FLASK_SECRET_KEY")
    ):
        raise RuntimeError("FLASK_SECRET_KEY must be set in production environments.")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    csrf.init_app(app)
    limiter.init_app(app)
    init_db_app(app)
    app.register_blueprint(main_bp)

    @app.after_request
    def apply_security_headers(response):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';",
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.errorhandler(400)
    def handle_bad_request(_error):
        return (
            render_template(
                "login.html",
                error="Your request could not be processed. Please refresh the page and try again.",
                email="",
            ),
            400,
        )

    @app.errorhandler(403)
    def handle_forbidden(_error):
        return (
            render_template(
                "login.html",
                error="Access denied.",
                email="",
            ),
            403,
        )

    @app.errorhandler(404)
    def handle_not_found(_error):
        return (
            render_template(
                "index.html",
                current_user=None,
                not_found=True,
            ),
            404,
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_payload_too_large(_error):
        return (
            render_template(
                "login.html",
                error="Submitted request exceeds maximum allowed size.",
                email="",
            ),
            413,
        )

    @app.errorhandler(429)
    def handle_rate_limit(_error):
        log_security_event("RATE_LIMIT_EXCEEDED", request.remote_addr, f"path={request.path}")
        return (
            render_template(
                "login.html",
                error="Too many attempts. Please wait a moment before trying again.",
                email="",
            ),
            429,
        )

    @app.errorhandler(500)
    def handle_internal_error(_error):
        return (
            render_template(
                "login.html",
                error="An unexpected error occurred. Please try again later.",
                email="",
            ),
            500,
        )

    return app
