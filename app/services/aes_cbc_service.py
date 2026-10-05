"""Password-based AES-256-CBC encryption with Encrypt-then-MAC authentication."""

import base64
import binascii
import hashlib
import hmac
import json
import mimetypes
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.constants import AES_BLOCK_BYTES, MAX_FILE_BYTES, MAX_PACKAGE_BYTES, MAX_PASSWORD_BYTES

FORMAT_VERSION = 1
ALGORITHM_ID = "AES-256-CBC-HMAC-SHA256"
KDF_ID = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 600_000
SALT_BYTES = 16
IV_BYTES = AES_BLOCK_BYTES
AES_KEY_BYTES = 32
MAC_KEY_BYTES = 32
HMAC_BYTES = hashlib.sha256().digest_size
_MIME_TYPE = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+\Z")

_PACKAGE_FIELDS = {
    "format_version",
    "algorithm",
    "kdf",
    "iterations",
    "original_filename",
    "mime_type",
    "salt",
    "iv",
    "ciphertext",
    "hmac",
}


class InvalidEncryptedPackage(Exception):
    """Raised for malformed, unauthenticated, or undecryptable packages."""


@dataclass(frozen=True)
class DecryptedFile:
    contents: bytes
    original_filename: str
    mime_type: str | None


def _derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    password_bytes = password.encode("utf-8")
    if not password.strip() or len(password_bytes) > MAX_PASSWORD_BYTES:
        raise ValueError("Invalid passcode")

    derivation = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES + MAC_KEY_BYTES,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    material = derivation.derive(password_bytes)
    return material[:AES_KEY_BYTES], material[AES_KEY_BYTES:]


def _canonical_manifest(manifest: dict[str, object]) -> bytes:
    return json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise InvalidEncryptedPackage
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidEncryptedPackage from error


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest field")
        result[key] = value
    return result


def _validated_manifest(package: bytes) -> tuple[dict[str, object], bytes, bytes, bytes, bytes]:
    if not package or len(package) > MAX_PACKAGE_BYTES:
        raise InvalidEncryptedPackage

    try:
        manifest = json.loads(package.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise InvalidEncryptedPackage from error

    if not isinstance(manifest, dict) or set(manifest) != _PACKAGE_FIELDS:
        raise InvalidEncryptedPackage
    if (
        type(manifest["format_version"]) is not int
        or manifest["format_version"] != FORMAT_VERSION
        or manifest["algorithm"] != ALGORITHM_ID
        or manifest["kdf"] != KDF_ID
        or type(manifest["iterations"]) is not int
        or manifest["iterations"] != KDF_ITERATIONS
    ):
        raise InvalidEncryptedPackage

    filename = manifest["original_filename"]
    mime_type = manifest["mime_type"]
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise InvalidEncryptedPackage
    if mime_type is not None and (
        not isinstance(mime_type, str)
        or len(mime_type) > 255
        or not _MIME_TYPE.fullmatch(mime_type)
    ):
        raise InvalidEncryptedPackage

    salt = _decode(manifest["salt"])
    iv = _decode(manifest["iv"])
    ciphertext = _decode(manifest["ciphertext"])
    tag = _decode(manifest["hmac"])

    if len(salt) != SALT_BYTES or len(iv) != IV_BYTES or len(tag) != HMAC_BYTES:
        raise InvalidEncryptedPackage
    if (
        not ciphertext
        or len(ciphertext) % AES_BLOCK_BYTES != 0
        or len(ciphertext) > MAX_FILE_BYTES + AES_BLOCK_BYTES
    ):
        raise InvalidEncryptedPackage

    return manifest, salt, iv, ciphertext, tag


def encrypt_bytes(
    plaintext: bytes,
    password: str,
    original_filename: str,
    mime_type: str | None = None,
) -> bytes:
    """Encrypt file bytes into the documented JSON `.aescbc` package format."""
    if not isinstance(plaintext, bytes) or not plaintext or len(plaintext) > MAX_FILE_BYTES:
        raise ValueError("File contents must be non-empty and within the upload limit")
    if (
        not isinstance(original_filename, str)
        or not original_filename
        or len(original_filename) > 255
    ):
        raise ValueError("Invalid filename")
    if mime_type is not None and (
        not isinstance(mime_type, str)
        or len(mime_type) > 255
        or not _MIME_TYPE.fullmatch(mime_type)
    ):
        mime_type = None

    salt = secrets.token_bytes(SALT_BYTES)
    iv = secrets.token_bytes(IV_BYTES)
    encryption_key, authentication_key = _derive_keys(password, salt)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    manifest: dict[str, object] = {
        "format_version": FORMAT_VERSION,
        "algorithm": ALGORITHM_ID,
        "kdf": KDF_ID,
        "iterations": KDF_ITERATIONS,
        "original_filename": original_filename,
        "mime_type": mime_type or mimetypes.guess_type(original_filename)[0],
        "salt": _encode(salt),
        "iv": _encode(iv),
        "ciphertext": _encode(ciphertext),
    }
    manifest["hmac"] = _encode(
        hmac.new(authentication_key, _canonical_manifest(manifest), hashlib.sha256).digest()
    )
    package = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return package.encode("utf-8")


def decrypt_package(package: bytes, password: str) -> DecryptedFile:
    """Authenticate a package before decrypting or removing PKCS7 padding."""
    try:
        manifest, salt, iv, ciphertext, actual_tag = _validated_manifest(package)
        encryption_key, authentication_key = _derive_keys(password, salt)

        unsigned_manifest = dict(manifest)
        del unsigned_manifest["hmac"]
        expected_tag = hmac.new(
            authentication_key,
            _canonical_manifest(unsigned_manifest),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(actual_tag, expected_tag):
            raise InvalidEncryptedPackage

        # Only authenticated ciphertext reaches the CBC decryptor or unpadder.
        decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except InvalidEncryptedPackage:
        raise
    except (ValueError, TypeError, binascii.Error, RecursionError) as error:
        raise InvalidEncryptedPackage from error

    return DecryptedFile(
        contents=plaintext,
        original_filename=manifest["original_filename"],
        mime_type=manifest["mime_type"],
    )


def encrypted_download_name(original_filename: str) -> str:
    """Append `.encrypt` before the package extension."""
    return f"{Path(original_filename).stem}.encrypt.aescbc"


def decrypted_download_name(original_filename: str) -> str:
    """Append `.decrypt` before the original file extension."""
    path = Path(original_filename)
    return f"{path.stem}.decrypt{path.suffix}"
