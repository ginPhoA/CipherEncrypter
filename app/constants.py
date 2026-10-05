"""Shared request and package limits for the Day 1 application."""

MAX_FILE_BYTES = 20 * 1024 * 1024
AES_BLOCK_BYTES = 16

# Base64 expands the padded ciphertext by roughly one third. Leave room for the
# JSON manifest as well as multipart request headers.
MAX_PACKAGE_BYTES = ((MAX_FILE_BYTES + AES_BLOCK_BYTES + 2) // 3) * 4 + 64 * 1024
MAX_REQUEST_BYTES = MAX_PACKAGE_BYTES + 1024 * 1024
MAX_PASSWORD_BYTES = 1024
