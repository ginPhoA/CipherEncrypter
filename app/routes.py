"""HTML page and AES-CBC API routes."""

import io
import mimetypes
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from app.services.aes_cbc_service import (
    InvalidEncryptedPackage,
    decrypt_package,
    decrypted_download_name,
    encrypt_bytes,
    encrypted_download_name,
)
from app.validators import RequestValidationError, require_algorithm, require_file, require_password

api = Blueprint("api", __name__)
GENERIC_DECRYPTION_ERROR = (
    "Could not decrypt this file. The passcode may be incorrect, "
    "or the package may be invalid or modified."
)


@api.get("/")
def index():
    return render_template("index.html")


@api.get("/api/algorithms")
def algorithms_list():
    return jsonify(
        {
            "algorithms": [
                {
                    "id": "aes-cbc",
                    "label": "AES-CBC",
                    "status": "active",
                    "supports": ["files-within-upload-limit"],
                    "educational_warning": "AES-CBC is included for educational purposes.",
                },
                {
                    "id": "rsa",
                    "label": "RSA",
                    "status": "planned",
                    "day": 2,
                    "supports": [],
                    "educational_warning": "Direct RSA is not available yet.",
                },
            ]
        }
    )


def _download_response(contents: bytes, filename: str, mime_type: str):
    response = send_file(
        io.BytesIO(contents),
        mimetype=mime_type,
        as_attachment=True,
        download_name=filename,
        max_age=0,
        conditional=False,
    )
    response.headers["X-Download-Filename"] = filename
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@api.post("/api/encrypt")
def encrypt_file():
    require_algorithm(request)
    password = require_password(request, confirm=True)
    filename, plaintext = require_file(request)

    mime_type = mimetypes.guess_type(filename)[0]
    encrypted_package = encrypt_bytes(plaintext, password, filename, mime_type)
    download_name = encrypted_download_name(filename)
    return _download_response(encrypted_package, download_name, "application/octet-stream")


@api.post("/api/decrypt")
def decrypt_file():
    require_algorithm(request)
    password = require_password(request)
    _uploaded_filename, package = require_file(request, package=True)

    try:
        decrypted = decrypt_package(package, password)
    except InvalidEncryptedPackage:
        return (
            jsonify(
                {
                    "error": {
                        "code": "DECRYPTION_FAILED",
                        "message": GENERIC_DECRYPTION_ERROR,
                    }
                }
            ),
            400,
        )

    original_filename = secure_filename(decrypted.original_filename)
    if not original_filename:
        return (
            jsonify(
                {
                    "error": {
                        "code": "DECRYPTION_FAILED",
                        "message": GENERIC_DECRYPTION_ERROR,
                    }
                }
            ),
            400,
        )

    download_name = decrypted_download_name(original_filename)
    response_mime = decrypted.mime_type or mimetypes.guess_type(Path(original_filename).name)[0]
    return _download_response(
        decrypted.contents,
        download_name,
        response_mime or "application/octet-stream",
    )


@api.app_errorhandler(RequestValidationError)
def handle_validation_error(error: RequestValidationError):
    return (
        jsonify({"error": {"code": error.code, "message": error.message}}),
        error.status_code,
    )
