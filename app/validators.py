"""Request validation for the local file-processing API."""

import hmac

from flask import Request
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from app.constants import MAX_FILE_BYTES, MAX_PACKAGE_BYTES, MAX_PASSWORD_BYTES
from app.storage import UploadTooLargeError, read_upload_bytes


class RequestValidationError(Exception):
    """A safe, user-facing request validation error."""

    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def require_algorithm(request: Request) -> None:
    algorithm = request.form.get("algorithm", "")
    if algorithm != "aes-cbc":
        raise RequestValidationError(
            "UNSUPPORTED_ALGORITHM",
            "AES-CBC is the only available algorithm in this release.",
        )


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


def require_file(request: Request, *, package: bool = False) -> tuple[str, bytes]:
    upload: FileStorage | None = request.files.get("file")
    if upload is None or not upload.filename:
        raise RequestValidationError("MISSING_FILE", "Choose a file to continue.")

    filename = secure_filename(upload.filename)
    if not filename:
        raise RequestValidationError("INVALID_FILENAME", "The selected filename is not valid.")
    if len(filename) > 255:
        raise RequestValidationError("INVALID_FILENAME", "The selected filename is too long.")

    byte_limit = MAX_PACKAGE_BYTES if package else MAX_FILE_BYTES
    try:
        contents = read_upload_bytes(upload, byte_limit)
    except UploadTooLargeError as error:
        raise RequestValidationError(
            "FILE_TOO_LARGE",
            "The selected file exceeds the upload limit.",
            status_code=413,
        ) from error

    if not contents:
        raise RequestValidationError("EMPTY_FILE", "Choose a file that contains data.")

    return filename, contents
