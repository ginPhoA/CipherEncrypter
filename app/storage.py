"""Bounded reads for Werkzeug's request-scoped upload streams.

Flask/Werkzeug own and close their upload streams when a request ends. The
application keeps cryptographic material and output bytes in memory, so it
does not leave uploads, plaintext, or keys in the source tree or in persistent
application storage.
"""

from werkzeug.datastructures import FileStorage


class UploadTooLargeError(Exception):
    """Raised when an upload exceeds its operation-specific byte limit."""


def read_upload_bytes(upload: FileStorage, maximum_bytes: int) -> bytes:
    """Read at most one byte beyond the configured limit to detect overflow."""
    contents = upload.stream.read(maximum_bytes + 1)
    if len(contents) > maximum_bytes:
        raise UploadTooLargeError
    return contents
