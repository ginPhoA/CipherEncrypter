"""Tests for the Day 1 Flask page and AES-CBC endpoints."""

import io
import json

import pytest

from app import create_app
from app.constants import MAX_FILE_BYTES

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


def test_algorithms_marks_aes_active_and_rsa_planned(client):
    response = client.get("/api/algorithms")
    algorithms = response.get_json()["algorithms"]

    assert response.status_code == 200
    assert algorithms[0]["id"] == "aes-cbc"
    assert algorithms[0]["status"] == "active"
    assert algorithms[1]["id"] == "rsa"
    assert algorithms[1]["status"] == "planned"


def test_encrypt_and_decrypt_image_round_trip(client):
    encrypted = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(PNG_SAMPLE), "photo.png"),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
            "password_confirmation": PASSCODE,
        },
        content_type="multipart/form-data",
    )

    assert encrypted.status_code == 200
    assert encrypted.headers["X-Download-Filename"] == "photo.encrypt.aescbc"
    assert encrypted.headers["Cache-Control"] == "no-store, max-age=0"

    decrypted = client.post(
        "/api/decrypt",
        data={
            "file": (io.BytesIO(encrypted.data), "photo.encrypt.aescbc"),
            "algorithm": "aes-cbc",
            "password": PASSCODE,
        },
        content_type="multipart/form-data",
    )

    assert decrypted.status_code == 200
    assert decrypted.headers["X-Download-Filename"] == "photo.decrypt.png"
    assert decrypted.data == PNG_SAMPLE


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
    unsupported = client.post(
        "/api/encrypt",
        data={
            "file": (io.BytesIO(PNG_SAMPLE), "photo.png"),
            "algorithm": "rsa",
            "password": PASSCODE,
            "password_confirmation": PASSCODE,
        },
        content_type="multipart/form-data",
    )

    assert empty.status_code == 400
    assert _error_payload(empty)["code"] == "EMPTY_FILE"
    assert oversized.status_code == 413
    assert _error_payload(oversized)["code"] == "FILE_TOO_LARGE"
    assert unsupported.status_code == 400
    assert _error_payload(unsupported)["code"] == "UNSUPPORTED_ALGORITHM"


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
