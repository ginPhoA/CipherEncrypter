"""Tests for AES-CBC package creation, authentication, and decryption."""

import base64
import hashlib
import hmac
import json

import pytest

from app.services import aes_cbc_service as aes

PASSCODE = "correct horse battery staple"
PNG_SAMPLE = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/iH0AAAAASUVORK5CYII="
)


def _manifest(package: bytes) -> dict:
    return json.loads(package.decode("utf-8"))


def _package(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _replace_hmac(manifest: dict, passcode: str) -> dict:
    unsigned = dict(manifest)
    unsigned.pop("hmac", None)
    salt = base64.b64decode(unsigned["salt"])
    _, authentication_key = aes._derive_keys(passcode, salt)
    canonical = aes._canonical_manifest(unsigned)
    manifest["hmac"] = base64.b64encode(
        hmac.new(authentication_key, canonical, hashlib.sha256).digest()
    ).decode("ascii")
    return manifest


@pytest.mark.parametrize(
    ("contents", "filename", "mime_type"),
    [
        ("CipherForge text sample — café".encode(), "notes.txt", "text/plain"),
        (PNG_SAMPLE, "photo.png", "image/png"),
        (bytes(range(256)) * 4, "sample.bin", "application/octet-stream"),
    ],
)
def test_encrypt_decrypt_round_trip(contents, filename, mime_type):
    package = aes.encrypt_bytes(contents, PASSCODE, filename, mime_type)
    recovered = aes.decrypt_package(package, PASSCODE)

    assert recovered.contents == contents
    assert recovered.original_filename == filename
    assert recovered.mime_type == mime_type


def test_each_encryption_uses_a_fresh_salt_and_iv():
    first = _manifest(aes.encrypt_bytes(PNG_SAMPLE, PASSCODE, "photo.png", "image/png"))
    second = _manifest(aes.encrypt_bytes(PNG_SAMPLE, PASSCODE, "photo.png", "image/png"))

    assert first["salt"] != second["salt"]
    assert first["iv"] != second["iv"]


def test_wrong_passcode_is_rejected():
    package = aes.encrypt_bytes(PNG_SAMPLE, PASSCODE, "photo.png", "image/png")

    with pytest.raises(aes.InvalidEncryptedPackage):
        aes.decrypt_package(package, "not the passcode")


def test_modified_ciphertext_is_rejected():
    manifest = _manifest(aes.encrypt_bytes(PNG_SAMPLE, PASSCODE, "photo.png", "image/png"))
    ciphertext = bytearray(base64.b64decode(manifest["ciphertext"]))
    ciphertext[0] ^= 0x01
    manifest["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")

    with pytest.raises(aes.InvalidEncryptedPackage):
        aes.decrypt_package(_package(manifest), PASSCODE)


def test_modified_metadata_is_rejected():
    manifest = _manifest(aes.encrypt_bytes(PNG_SAMPLE, PASSCODE, "photo.png", "image/png"))
    manifest["original_filename"] = "changed.png"

    with pytest.raises(aes.InvalidEncryptedPackage):
        aes.decrypt_package(_package(manifest), PASSCODE)


def test_invalid_padding_is_rejected_after_authentication():
    manifest = _manifest(aes.encrypt_bytes(b"123456789012345", PASSCODE, "file.bin"))
    iv = bytearray(base64.b64decode(manifest["iv"]))
    iv[-1] ^= 0x01  # Turn the one-byte PKCS7 pad into an invalid zero byte.
    manifest["iv"] = base64.b64encode(iv).decode("ascii")
    _replace_hmac(manifest, PASSCODE)

    with pytest.raises(aes.InvalidEncryptedPackage):
        aes.decrypt_package(_package(manifest), PASSCODE)


@pytest.mark.parametrize("package", [b"", b"not-json", b"{}", b"[]"])
def test_malformed_package_is_rejected(package):
    with pytest.raises(aes.InvalidEncryptedPackage):
        aes.decrypt_package(package, PASSCODE)


def test_download_names_keep_original_type_and_add_operation():
    assert aes.encrypted_download_name("photo.png") == "photo.encrypt.aescbc"
    assert aes.decrypted_download_name("photo.png") == "photo.decrypt.png"
