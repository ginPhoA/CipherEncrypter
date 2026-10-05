"""Request validation for the local file-processing API."""

import hmac

from flask import Request
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from app.constants import (
    MAX_FILE_BYTES,
    MAX_PACKAGE_BYTES,
    MAX_PASSWORD_BYTES,
    MAX_RSA_KEY_BYTES,
)
from app.storage import UploadTooLargeError, read_upload_bytes


class RequestValidationError(Exception):
    """A safe, user-facing request validation error."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def require_algorithm(request: Request) -> str:
    algorithm = request.form.get("algorithm", "")
    if algorithm not in {"aes-cbc", "rsa"}:
        raise RequestValidationError(
            "UNSUPPORTED_ALGORITHM",
            "Choose either AES-CBC or RSA.",
        )
    return algorithm


def require_password(request: Request, *, confirm: bool = False) -> str:
    password = request.form.get("password", "")
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError as error:
        raise RequestValidationError("INVALID_PASSWORD", "Enter a valid passcode.") from error

    if not password.strip():
        raise RequestValidationError("MISSING_PASSWORD", "Enter the AES-CBC passcode.")
    if len(password_bytes) > MAX_PASSWORD_BYTES:
        raise RequestValidationError(
            "PASSWORD_TOO_LONG",
            "The passcode must be no longer than 1,024 UTF-8 bytes.",
        )

    if confirm:
        confirmation = request.form.get("password_confirmation", "")
        try:
            confirmation_bytes = confirmation.encode("utf-8")
        except UnicodeEncodeError as error:
            raise RequestValidationError(
                "INVALID_PASSWORD_CONFIRMATION", "The passcode entries do not match."
            ) from error
        if not hmac.compare_digest(password_bytes, confirmation_bytes):
            raise RequestValidationError("PASSWORD_MISMATCH", "The passcode entries do not match.")

    return password


def require_file(
    request: Request,
    *,
    package: bool = False,
    maximum_bytes: int | None = None,
    too_large_message: str | None = None,
) -> tuple[str, bytes]:
    upload: FileStorage | None = request.files.get("file")
    if upload is None or not upload.filename:
        raise RequestValidationError("MISSING_FILE", "Choose a file to continue.")

    filename = secure_filename(upload.filename)
    if not filename:
        raise RequestValidationError("INVALID_FILENAME", "The selected filename is not valid.")
    if len(filename) > 255:
        raise RequestValidationError("INVALID_FILENAME", "The selected filename is too long.")

    byte_limit = (
        maximum_bytes
        if maximum_bytes is not None
        else (MAX_PACKAGE_BYTES if package else MAX_FILE_BYTES)
    )
    try:
        contents = read_upload_bytes(upload, byte_limit)
    except UploadTooLargeError as error:
        raise RequestValidationError(
            "FILE_TOO_LARGE",
            too_large_message or "The selected file exceeds the upload limit.",
            status_code=413,
        ) from error

    if not contents:
        raise RequestValidationError("EMPTY_FILE", "Choose a file that contains data.")

    return filename, contents


def require_key_upload(request: Request, field_name: str, label: str) -> bytes:
    """Read one bounded PEM upload without using its client-provided filename."""
    upload: FileStorage | None = request.files.get(field_name)
    if upload is None or not upload.filename:
        raise RequestValidationError(
            f"MISSING_RSA_{label}_KEY", f"Choose an RSA {label.lower()} key."
        )
    try:
        contents = read_upload_bytes(upload, MAX_RSA_KEY_BYTES)
    except UploadTooLargeError as error:
        raise RequestValidationError(
            f"RSA_{label}_KEY_TOO_LARGE",
            "The RSA key file is too large.",
            status_code=413,
        ) from error
    if not contents:
        raise RequestValidationError(
            f"EMPTY_RSA_{label}_KEY", f"Choose an RSA {label.lower()} key that contains data."
        )
    return contents


def optional_rsa_passphrase(request: Request, field_name: str = "rsa_passphrase") -> str | None:
    """Return an optional valid passphrase for a generated or imported private PEM."""
    passphrase = request.form.get(field_name, "")
    try:
        passphrase_bytes = passphrase.encode("utf-8")
    except UnicodeEncodeError as error:
        raise RequestValidationError(
            "INVALID_RSA_PASSPHRASE", "Enter a valid RSA key passphrase."
        ) from error
    if len(passphrase_bytes) > MAX_PASSWORD_BYTES:
        raise RequestValidationError(
            "RSA_PASSPHRASE_TOO_LONG",
            "The RSA key passphrase must be no longer than 1,024 UTF-8 bytes.",
        )
    return passphrase or None


def require_rsa_key_generation_options(request: Request) -> str | None:
    """Validate the server-controlled RSA-2048 generation request."""
    requested_key_size = request.form.get("key_size", "2048")
    if requested_key_size != "2048":
        raise RequestValidationError(
            "UNSUPPORTED_RSA_KEY_SIZE",
            "CipherForge generates RSA-2048 keys only.",
        )
    passphrase = optional_rsa_passphrase(request, "passphrase")
    confirmation = request.form.get("passphrase_confirmation", "")
    if passphrase is not None and not hmac.compare_digest(passphrase, confirmation):
        raise RequestValidationError(
            "RSA_PASSPHRASE_MISMATCH", "The RSA key passphrase entries do not match."
        )
    if passphrase is None and confirmation:
        raise RequestValidationError(
            "RSA_PASSPHRASE_MISMATCH", "The RSA key passphrase entries do not match."
        )
    return passphrase
