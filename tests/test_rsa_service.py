"""Tests for direct RSA-OAEP encryption and PEM key handling."""

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.constants import RSA_KEY_SIZE
from app.services import rsa_service as rsa_service


@pytest.fixture(scope="module")
def generated_pair():
    return rsa_service.generate_key_pair()


@pytest.fixture(scope="module")
def loaded_keys(generated_pair):
    return (
        rsa_service.load_public_key(generated_pair.public_pem),
        rsa_service.load_private_key(generated_pair.private_pem),
    )


def test_generated_pem_round_trip_without_a_passphrase(generated_pair):
    public_key = rsa_service.load_public_key(generated_pair.public_pem)
    private_key = rsa_service.load_private_key(generated_pair.private_pem)

    assert public_key.key_size == RSA_KEY_SIZE
    assert private_key.key_size == RSA_KEY_SIZE
    assert generated_pair.public_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    assert generated_pair.private_pem.startswith(b"-----BEGIN PRIVATE KEY-----")


def test_generated_pem_round_trip_with_a_passphrase():
    pair = rsa_service.generate_key_pair("temporary test passphrase")

    loaded = rsa_service.load_private_key(pair.private_pem, "temporary test passphrase")

    assert pair.private_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    assert loaded.key_size == RSA_KEY_SIZE
    with pytest.raises(rsa_service.InvalidRSAKey):
        rsa_service.load_private_key(pair.private_pem, "wrong passphrase")


@pytest.mark.parametrize(
    ("contents", "filename", "mime_type"),
    [
        ("CipherForge RSA text sample — café".encode(), "notes.txt", "text/plain"),
        (bytes(range(190)), "sample.bin", "application/octet-stream"),
    ],
)
def test_encrypt_decrypt_round_trip(loaded_keys, contents, filename, mime_type):
    public_key, private_key = loaded_keys

    package = rsa_service.encrypt_bytes(contents, public_key, filename, mime_type)
    recovered = rsa_service.decrypt_package(package, private_key)

    assert recovered.contents == contents
    assert recovered.original_filename == filename
    assert recovered.mime_type == mime_type


def test_plaintext_limit_is_derived_from_the_key(loaded_keys):
    public_key, _private_key = loaded_keys
    maximum = rsa_service.oaep_plaintext_limit(public_key)

    assert maximum == 190
    with pytest.raises(ValueError):
        rsa_service.encrypt_bytes(b"x" * (maximum + 1), public_key, "too-large.bin")


def test_wrong_private_key_and_malformed_package_are_rejected(loaded_keys):
    public_key, private_key = loaded_keys
    package = rsa_service.encrypt_bytes(b"tiny message", public_key, "message.txt")
    wrong_pair = rsa_service.generate_key_pair()
    wrong_private_key = rsa_service.load_private_key(wrong_pair.private_pem)

    with pytest.raises(rsa_service.InvalidRSAEncryptedFile):
        rsa_service.decrypt_package(package, wrong_private_key)
    with pytest.raises(rsa_service.InvalidRSAEncryptedFile):
        rsa_service.decrypt_package(b"not a CipherForge RSA envelope", wrong_private_key)

    malformed = json.loads(package)
    malformed["ciphertext"] = "not base64"
    with pytest.raises(rsa_service.InvalidRSAEncryptedFile):
        rsa_service.decrypt_package(json.dumps(malformed).encode(), private_key)


def test_only_rsa_2048_with_the_standard_exponent_is_accepted():
    smaller_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    smaller_private_pem = smaller_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    smaller_public_pem = smaller_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with pytest.raises(rsa_service.InvalidRSAKey):
        rsa_service.load_private_key(smaller_private_pem)
    with pytest.raises(rsa_service.InvalidRSAKey):
        rsa_service.load_public_key(smaller_public_pem)


def test_download_names_preserve_the_operation_and_file_extension():
    assert rsa_service.encrypted_download_name("photo.png") == "photo.encrypt.rsaenc"
    assert rsa_service.decrypted_download_name("photo.png") == "photo.decrypt.png"
