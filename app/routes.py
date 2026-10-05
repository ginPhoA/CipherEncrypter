"""HTML page and local AES-CBC and direct-RSA API routes."""

import io
import mimetypes
import zipfile
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from app.constants import MAX_RSA_ENCRYPTED_FILE_BYTES
from app.services import rsa_service
from app.services.aes_cbc_service import (
    InvalidEncryptedPackage,
    decrypt_package,
    decrypted_download_name,
    encrypt_bytes,
    encrypted_download_name,
)
from app.validators import (
    RequestValidationError,
    optional_rsa_passphrase,
    require_algorithm,
    require_file,
    require_key_upload,
    require_password,
    require_rsa_key_generation_options,
)

api = Blueprint("api", __name__)
GENERIC_DECRYPTION_ERROR = (
    "Could not decrypt this file. The key may not match, the passphrase may be incorrect, "
    "or the encrypted file may be invalid."
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
                    "status": "active",
                    "supports": ["rsa-2048-oaep-small-files"],
                    "educational_warning": (
                        "Direct RSA is for very small demonstration files only. "
                        "RSA-2048 with OAEP-SHA256 accepts at most 190 bytes."
                    ),
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


def _decryption_error_response():
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


def _rsa_plaintext_limit_message(maximum_bytes: int) -> str:
    return (
        f"RSA-2048 with OAEP-SHA256 can encrypt at most {maximum_bytes} bytes directly. "
        "Choose a smaller demonstration file."
    )


@api.post("/api/keys/rsa")
def generate_rsa_key_pair():
    """Generate one ephemeral RSA-2048 pair and return both PEM files in a ZIP."""
    passphrase = require_rsa_key_generation_options(request)
    try:
        key_pair = rsa_service.generate_key_pair(passphrase)
    except rsa_service.InvalidRSAKey as error:
        raise RequestValidationError(
            "INVALID_RSA_PASSPHRASE", "Enter a non-empty valid RSA key passphrase."
        ) from error

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as key_archive:
        key_archive.writestr("cipherforge-rsa-2048-public.pem", key_pair.public_pem)
        key_archive.writestr("cipherforge-rsa-2048-private.pem", key_pair.private_pem)
    return _download_response(
        archive.getvalue(),
        "cipherforge-rsa-2048-key-pair.zip",
        "application/zip",
    )


@api.post("/api/encrypt")
def encrypt_file():
    algorithm = require_algorithm(request)
    if algorithm == "aes-cbc":
        password = require_password(request, confirm=True)
        filename, plaintext = require_file(request)

        mime_type = mimetypes.guess_type(filename)[0]
        encrypted_package = encrypt_bytes(plaintext, password, filename, mime_type)
        download_name = encrypted_download_name(filename)
        return _download_response(encrypted_package, download_name, "application/octet-stream")

    public_pem = require_key_upload(request, "rsa_public_key", "PUBLIC")
    try:
        public_key = rsa_service.load_public_key(public_pem)
    except rsa_service.InvalidRSAKey as error:
        raise RequestValidationError(
            "INVALID_RSA_PUBLIC_KEY",
            "Upload a valid RSA-2048 public PEM with public exponent 65537.",
        ) from error

    maximum_plaintext = rsa_service.oaep_plaintext_limit(public_key)
    filename, plaintext = require_file(
        request,
        maximum_bytes=maximum_plaintext,
        too_large_message=_rsa_plaintext_limit_message(maximum_plaintext),
    )

    mime_type = mimetypes.guess_type(filename)[0]
    encrypted_package = rsa_service.encrypt_bytes(plaintext, public_key, filename, mime_type)
    download_name = rsa_service.encrypted_download_name(filename)
    return _download_response(encrypted_package, download_name, "application/octet-stream")


@api.post("/api/decrypt")
def decrypt_file():
    algorithm = require_algorithm(request)
    if algorithm == "aes-cbc":
        password = require_password(request)
        _, package = require_file(request, package=True)

        try:
            decrypted = decrypt_package(package, password)
        except InvalidEncryptedPackage:
            return _decryption_error_response()

        original_filename = secure_filename(decrypted.original_filename)
        if not original_filename:
            return _decryption_error_response()

        download_name = decrypted_download_name(original_filename)
        response_mime = decrypted.mime_type or mimetypes.guess_type(Path(original_filename).name)[0]
        return _download_response(
            decrypted.contents,
            download_name,
            response_mime or "application/octet-stream",
        )

    private_pem = require_key_upload(request, "rsa_private_key", "PRIVATE")
    passphrase = optional_rsa_passphrase(request)
    _, package = require_file(
        request,
        maximum_bytes=MAX_RSA_ENCRYPTED_FILE_BYTES,
        too_large_message="The encrypted RSA file exceeds the supported size.",
    )
    try:
        private_key = rsa_service.load_private_key(private_pem, passphrase)
        decrypted = rsa_service.decrypt_package(package, private_key)
    except (rsa_service.InvalidRSAEncryptedFile, rsa_service.InvalidRSAKey):
        return _decryption_error_response()

    original_filename = secure_filename(decrypted.original_filename)
    if not original_filename:
        return _decryption_error_response()

    download_name = rsa_service.decrypted_download_name(original_filename)
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
