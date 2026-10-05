"""Direct RSA-OAEP helpers for CipherForge's small-file demonstration."""

import base64
import binascii
import json
import mimetypes
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.constants import (
    MAX_PASSWORD_BYTES,
    MAX_RSA_ENCRYPTED_FILE_BYTES,
    MAX_RSA_KEY_BYTES,
    RSA_KEY_SIZE,
    RSA_PUBLIC_EXPONENT,
)

FORMAT_VERSION = 1
ALGORITHM_ID = "RSA-OAEP-SHA256"
OAEP_HASH = hashes.SHA256()
_MIME_TYPE = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+\Z")
_PACKAGE_FIELDS = {
    "format_version",
    "algorithm",
    "key_size",
    "original_filename",
    "mime_type",
    "ciphertext",
}


class InvalidRSAKey(Exception):
    """Raised when an uploaded PEM is not an accepted RSA key."""


class InvalidRSAEncryptedFile(Exception):
    """Raised for malformed or undecryptable RSA encrypted files."""


@dataclass(frozen=True)
class GeneratedKeyPair:
    public_pem: bytes
    private_pem: bytes


@dataclass(frozen=True)
class DecryptedFile:
    contents: bytes
    original_filename: str
    mime_type: str | None


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def oaep_plaintext_limit(key: rsa.RSAPublicKey | rsa.RSAPrivateKey) -> int:
    """Return the RFC 8017 OAEP limit for this key and the fixed SHA-256 hash."""
    modulus_bytes = (key.key_size + 7) // 8
    return modulus_bytes - (2 * OAEP_HASH.digest_size) - 2


def _validate_rsa_key(key: object) -> rsa.RSAPublicKey | rsa.RSAPrivateKey:
    if not isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        raise InvalidRSAKey

    public_key = key.public_key() if isinstance(key, rsa.RSAPrivateKey) else key
    if key.key_size != RSA_KEY_SIZE or public_key.public_numbers().e != RSA_PUBLIC_EXPONENT:
        raise InvalidRSAKey
    return key


def _passphrase_bytes(passphrase: str | None, *, allow_empty: bool) -> bytes | None:
    if passphrase is None:
        return None
    try:
        encoded = passphrase.encode("utf-8")
    except UnicodeEncodeError as error:
        raise InvalidRSAKey from error

    if len(encoded) > MAX_PASSWORD_BYTES or (not allow_empty and not passphrase.strip()):
        raise InvalidRSAKey
    return encoded or None


def generate_key_pair(passphrase: str | None = None) -> GeneratedKeyPair:
    """Generate an RSA-2048 pair and serialize it as standard PEM files."""
    passphrase_bytes = _passphrase_bytes(passphrase, allow_empty=False)
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )
    encryption = (
        serialization.BestAvailableEncryption(passphrase_bytes)
        if passphrase_bytes is not None
        else serialization.NoEncryption()
    )
    return GeneratedKeyPair(
        public_pem=private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        private_pem=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        ),
    )


def load_public_key(pem: bytes) -> rsa.RSAPublicKey:
    """Load a PEM public key and enforce CipherForge's RSA-2048 policy."""
    if not isinstance(pem, bytes) or not pem or len(pem) > MAX_RSA_KEY_BYTES:
        raise InvalidRSAKey
    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError, UnsupportedAlgorithm) as error:
        raise InvalidRSAKey from error
    validated = _validate_rsa_key(key)
    if not isinstance(validated, rsa.RSAPublicKey):
        raise InvalidRSAKey
    return validated


def load_private_key(pem: bytes, passphrase: str | None = None) -> rsa.RSAPrivateKey:
    """Load a PEM private key, using a passphrase only when one was supplied."""
    if not isinstance(pem, bytes) or not pem or len(pem) > MAX_RSA_KEY_BYTES:
        raise InvalidRSAKey
    passphrase_bytes = _passphrase_bytes(passphrase, allow_empty=True)
    try:
        key = serialization.load_pem_private_key(pem, password=passphrase_bytes)
    except (TypeError, ValueError, UnsupportedAlgorithm) as error:
        raise InvalidRSAKey from error
    validated = _validate_rsa_key(key)
    if not isinstance(validated, rsa.RSAPrivateKey):
        raise InvalidRSAKey
    return validated


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise InvalidRSAEncryptedFile
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidRSAEncryptedFile from error


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate envelope field")
        result[key] = value
    return result


def _validated_envelope(
    package: bytes, private_key: rsa.RSAPrivateKey
) -> tuple[dict[str, object], bytes]:
    if not package or len(package) > MAX_RSA_ENCRYPTED_FILE_BYTES:
        raise InvalidRSAEncryptedFile
    try:
        envelope = json.loads(package.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise InvalidRSAEncryptedFile from error

    if not isinstance(envelope, dict) or set(envelope) != _PACKAGE_FIELDS:
        raise InvalidRSAEncryptedFile
    if (
        type(envelope["format_version"]) is not int
        or envelope["format_version"] != FORMAT_VERSION
        or envelope["algorithm"] != ALGORITHM_ID
        or type(envelope["key_size"]) is not int
        or envelope["key_size"] != private_key.key_size
    ):
        raise InvalidRSAEncryptedFile

    filename = envelope["original_filename"]
    mime_type = envelope["mime_type"]
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise InvalidRSAEncryptedFile
    if mime_type is not None and (
        not isinstance(mime_type, str)
        or len(mime_type) > 255
        or not _MIME_TYPE.fullmatch(mime_type)
    ):
        raise InvalidRSAEncryptedFile

    ciphertext = _decode(envelope["ciphertext"])
    if len(ciphertext) != (private_key.key_size + 7) // 8:
        raise InvalidRSAEncryptedFile
    return envelope, ciphertext


def encrypt_bytes(
    plaintext: bytes,
    public_key: rsa.RSAPublicKey,
    original_filename: str,
    mime_type: str | None = None,
) -> bytes:
    """Encrypt one small file using direct RSA-OAEP and package its safe metadata."""
    key = _validate_rsa_key(public_key)
    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidRSAKey
    maximum_plaintext = oaep_plaintext_limit(key)
    if not isinstance(plaintext, bytes) or not plaintext or len(plaintext) > maximum_plaintext:
        raise ValueError("RSA plaintext exceeds the OAEP limit")
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

    ciphertext = key.encrypt(plaintext, _oaep_padding())
    envelope: dict[str, object] = {
        "format_version": FORMAT_VERSION,
        "algorithm": ALGORITHM_ID,
        "key_size": key.key_size,
        "original_filename": original_filename,
        "mime_type": mime_type or mimetypes.guess_type(original_filename)[0],
        "ciphertext": _encode(ciphertext),
    }
    return json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def decrypt_package(
    package: bytes,
    private_key: rsa.RSAPrivateKey,
) -> DecryptedFile:
    """Decrypt a validated CipherForge RSA envelope without exposing error detail."""
    try:
        key = _validate_rsa_key(private_key)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise InvalidRSAKey
        envelope, ciphertext = _validated_envelope(package, key)
        plaintext = key.decrypt(ciphertext, _oaep_padding())
    except (InvalidRSAKey, InvalidRSAEncryptedFile) as error:
        raise InvalidRSAEncryptedFile from error
    except (ValueError, TypeError) as error:
        raise InvalidRSAEncryptedFile from error

    if not plaintext or len(plaintext) > oaep_plaintext_limit(key):
        raise InvalidRSAEncryptedFile
    return DecryptedFile(
        contents=plaintext,
        original_filename=envelope["original_filename"],
        mime_type=envelope["mime_type"],
    )


def encrypted_download_name(original_filename: str) -> str:
    """Append `.encrypt` before CipherForge's RSA envelope extension."""
    return f"{Path(original_filename).stem}.encrypt.rsaenc"


def decrypted_download_name(original_filename: str) -> str:
    """Append `.decrypt` before the recovered file's original extension."""
    path = Path(original_filename)
    return f"{path.stem}.decrypt{path.suffix}"
