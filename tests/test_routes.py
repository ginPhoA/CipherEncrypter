"""Tests for the Day 1 Flask page and AES-CBC endpoints."""

import io
import json
import zipfile

import pytest

from app import create_app
from app.constants import MAX_FILE_BYTES
from app.services import rsa_service

PNG_SAMPLE = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
)
PASSCODE = "correct horse battery staple"


@pytest.fixture
def client():
    application = create_app({"TESTING": True})
    with application.test_client() as test_client:
        yield test_client


@pytest.fixture(scope="module")
def rsa_key_pair():
    return rsa_service.generate_key_pair()


def _error_payload(response):
    return json.loads(response.data.decode("utf-8"))["error"]


def test_home_page_and_assets_are_served(client):
    page = client.get("/")
    stylesheet = client.get("/static/css/styles.css")
    script = client.get("/static/js/app.js")

    assert page.status_code == 200
    assert b"A quick note before you begin" in page.data
    assert stylesheet.status_code == 200
    assert script.status_code == 200


def test_algorithms_marks_aes_and_rsa_active(client):
    response = client.get("/api/algorithms")
    algorithms = response.get_json()["algorithms"]

    assert response.status_code == 200
    assert algorithms[0]["id"] == "aes-cbc"
    assert algorithms[0]["status"] == "active"
    assert algorithms[1]["id"] == "rsa"
    assert algorithms[1]["status"] == "active"
    assert algorithms[1]["supports"] == ["rsa-2048-oaep-small-files"]


@pytest.mark.parametrize(
    ("contents", "filename"),
    [
        (PNG_SAMPLE, "photo.png"),
        ("CipherForge route text — café".encode(), "notes.txt"),
        (bytes(range(256)), "sample.bin"),
    ],
)
def test_encrypt_and_decrypt_file_round_trip(client, contents, filename):
    filename_stem, filename_extension = filename.rsplit(".", 1)
    encrypted = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(contents), filename),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
            "password_confirmation": PASSCODE,
        },
        content_type="multipart/form-data",
    )

    assert encrypted.status_code == 200
    assert encrypted.headers["X-Download-Filename"] == f"{filename_stem}.encrypt.aescbc"
    assert encrypted.headers["Cache-Control"] == "no-store, max-age=0"

    decrypted = client.post(
        "/api/decrypt",
        data={
            "file": (io.BytesIO(encrypted.data), f"{filename_stem}.encrypt.aescbc"),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
        },
        content_type="multipart/form-data",
    )

    assert decrypted.status_code == 200
    assert (
        decrypted.headers["X-Download-Filename"] == f"{filename_stem}.decrypt.{filename_extension}"
    )
    assert decrypted.data == contents


def test_encrypt_requires_file_password_and_matching_confirmation(client):
    missing_file = client.post(
        "/api/encrypt",
        data={
            "algorithm": "aes-cbc",
            "password": PASSCODE,
            "password_confirmation": PASSCODE,
        },
    )
    mismatch = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(PNG_SAMPLE), "photo.png"),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
            "password_confirmation": "another passcode",
        },
        content_type="multipart/form-data",
    )

    assert missing_file.status_code == 400
    assert _error_payload(missing_file)["code"] == "MISSING_FILE"
    assert mismatch.status_code == 400
    assert _error_payload(mismatch)["code"] == "PASSWORD_MISMATCH"


def test_rejects_empty_oversized_and_unsupported_uploads(client):
    empty = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(b""), "empty.png"),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
            "password_confirmation": PASSCODE,
        },
        content_type="multipart/form-data",
    )
    oversized = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(b"x" * (MAX_FILE_BYTES + 1)), "large.bin"),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
            "password_confirmation": PASSCODE,
        },
        content_type="multipart/form-data",
    )
    missing_rsa_key = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(PNG_SAMPLE), "photo.png"),
            "algorithm": "rsa",
        },
        content_type="multipart/form-data",
    )

    assert empty.status_code == 400
    assert _error_payload(empty)["code"] == "EMPTY_FILE"
    assert oversized.status_code == 413
    assert _error_payload(oversized)["code"] == "FILE_TOO_LARGE"
    assert missing_rsa_key.status_code == 400
    assert _error_payload(missing_rsa_key)["code"] == "MISSING_RSA_PUBLIC_KEY"


def test_decryption_errors_are_generic_and_sensitive_values_are_not_logged(client, caplog):
    encrypted = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(PNG_SAMPLE), "private-photo.png"),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
            "password_confirmation": PASSCODE,
        },
        content_type="multipart/form-data",
    )

    caplog.clear()
    response = client.post(
        "/api/decrypt",
        data={
            "file": (io.BytesIO(encrypted.data), "photo.encrypt.aescbc"),
            "algorithm": "aes-cbc",
            "password": "wrong private passcode",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert _error_payload(response)["code"] == "DECRYPTION_FAILED"
    assert "wrong private passcode" not in caplog.text
    assert "private-photo.png" not in caplog.text
    assert "PNG_SAMPLE" not in caplog.text


def test_rsa_key_endpoint_returns_a_passphrase_protected_pem_zip(client):
    response = client.post(
        "/api/keys/rsa",
        data={
            "key_size": "2048",
            "passphrase": "test key passphrase",
            "passphrase_confirmation": "test key passphrase",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert response.headers["X-Download-Filename"] == "cipherforge-rsa-2048-key-pair.zip"
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert set(archive.namelist()) == {
            "cipherforge-rsa-2048-private.pem",
            "cipherforge-rsa-2048-public.pem",
        }
        public_key = rsa_service.load_public_key(archive.read("cipherforge-rsa-2048-public.pem"))
        private_key = rsa_service.load_private_key(
            archive.read("cipherforge-rsa-2048-private.pem"), "test key passphrase"
        )
    assert public_key.key_size == private_key.key_size == 2048


@pytest.mark.parametrize(
    ("contents", "filename"),
    [
        (b"small route text", "notes.txt"),
        (bytes(range(128)), "sample.bin"),
    ],
)
def test_rsa_encrypt_decrypt_round_trip(client, rsa_key_pair, contents, filename):
    filename_stem, filename_extension = filename.rsplit(".", 1)
    encrypted = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(contents), filename),
            "algorithm": "rsa",
            "rsa_public_key": (io.BytesIO(rsa_key_pair.public_pem), "public.pem"),
        },
        content_type="multipart/form-data",
    )

    assert encrypted.status_code == 200
    assert encrypted.headers["X-Download-Filename"] == f"{filename_stem}.encrypt.rsaenc"
    decrypted = client.post(
        "/api/decrypt",
        data={
            "file": (io.BytesIO(encrypted.data), "message.encrypt.rsaenc"),
            "algorithm": "rsa",
            "rsa_private_key": (io.BytesIO(rsa_key_pair.private_pem), "private.pem"),
        },
        content_type="multipart/form-data",
    )

    assert decrypted.status_code == 200
    assert decrypted.headers["X-Download-Filename"] == (
        f"{filename_stem}.decrypt.{filename_extension}"
    )
    assert decrypted.data == contents


def test_rsa_rejects_oversized_wrong_key_and_malformed_inputs(client, rsa_key_pair, caplog):
    public_key = rsa_service.load_public_key(rsa_key_pair.public_pem)
    oversized = client.post(
        "/api/encrypt",
        data={
            "file": (
                io.BytesIO(b"x" * (rsa_service.oaep_plaintext_limit(public_key) + 1)),
                "too-large.bin",
            ),
            "algorithm": "rsa",
            "rsa_public_key": (io.BytesIO(rsa_key_pair.public_pem), "public.pem"),
        },
        content_type="multipart/form-data",
    )
    encrypted = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(b"private route text"), "private-message.txt"),
            "algorithm": "rsa",
            "rsa_public_key": (io.BytesIO(rsa_key_pair.public_pem), "public.pem"),
        },
        content_type="multipart/form-data",
    )
    wrong_pair = rsa_service.generate_key_pair()

    caplog.clear()
    wrong_key = client.post(
        "/api/decrypt",
        data={
            "file": (io.BytesIO(encrypted.data), "message.encrypt.rsaenc"),
            "algorithm": "rsa",
            "rsa_private_key": (io.BytesIO(wrong_pair.private_pem), "wrong-private.pem"),
        },
        content_type="multipart/form-data",
    )
    malformed = client.post(
        "/api/decrypt",
        data={
            "file": (io.BytesIO(b"not a CipherForge RSA envelope"), "broken.rsaenc"),
            "algorithm": "rsa",
            "rsa_private_key": (io.BytesIO(rsa_key_pair.private_pem), "private.pem"),
        },
        content_type="multipart/form-data",
    )
    invalid_public_key = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(b"tiny text"), "notes.txt"),
            "algorithm": "rsa",
            "rsa_public_key": (io.BytesIO(b"not a public pem"), "public.pem"),
        },
        content_type="multipart/form-data",
    )

    assert oversized.status_code == 413
    assert _error_payload(oversized)["code"] == "FILE_TOO_LARGE"
    assert "190 bytes" in _error_payload(oversized)["message"]
    assert encrypted.status_code == 200
    assert wrong_key.status_code == malformed.status_code == 400
    assert _error_payload(wrong_key) == _error_payload(malformed)
    assert _error_payload(wrong_key)["code"] == "DECRYPTION_FAILED"
    assert invalid_public_key.status_code == 400
    assert _error_payload(invalid_public_key)["code"] == "INVALID_RSA_PUBLIC_KEY"
    assert "private route text" not in caplog.text
    assert "wrong-private.pem" not in caplog.text
