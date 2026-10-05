"""Flask application factory for the local CipherForge demonstration."""

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from app.constants import MAX_REQUEST_BYTES
from app.routes import api


def _error_response(code: str, message: str, status_code: int):
    return jsonify({"error": {"code": code, "message": message}}), status_code


def create_app(test_config: dict | None = None) -> Flask:
    """Create the local app without performing work at module import time."""
    application = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="../templates",
        static_folder="../static",
        static_url_path="/static",
    )
    application.config.from_mapping(
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        SEND_FILE_MAX_AGE_DEFAULT=0,
    )
    if test_config:
        application.config.update(test_config)

    application.register_blueprint(api)

    @application.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(_error):
        return _error_response("FILE_TOO_LARGE", "The selected file exceeds the upload limit.", 413)

    @application.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        if request.path.startswith("/api/"):
            return _error_response(
                "REQUEST_ERROR",
                "The request could not be completed.",
                error.code or 400,
            )
        return error

    @application.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        # Log only the exception type. Request bodies and cryptographic material
        # must never be included in application logs.
        application.logger.error("Unhandled application error (%s)", type(error).__name__)
        if request.path.startswith("/api/"):
            return _error_response(
                "INTERNAL_ERROR",
                "The request could not be completed. Please try again.",
                500,
            )
        return "The page could not be loaded.", 500

    return application
