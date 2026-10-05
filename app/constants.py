"""Shared request, package, and cryptographic limits for CipherForge."""

MAX_FILE_BYTES = 20 * 1024 * 1024
AES_BLOCK_BYTES = 16

# Base64 expands the padded ciphertext by roughly one third. Leave room for the
# JSON manifest as well as multipart request headers.
MAX_PACKAGE_BYTES = ((MAX_FILE_BYTES + AES_BLOCK_BYTES + 2) // 3) * 4 + 64 * 1024
MAX_REQUEST_BYTES = MAX_PACKAGE_BYTES + 1024 * 1024
MAX_PASSWORD_BYTES = 1024

# Direct RSA is intentionally limited to a single small OAEP message. The
# maximum plaintext is derived from the imported key at runtime; these values
# constrain accepted key material and the small JSON envelope around ciphertext.
RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537
MAX_RSA_KEY_BYTES = 64 * 1024
MAX_RSA_ENCRYPTED_FILE_BYTES = 64 * 1024
