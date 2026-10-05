"""Read uploads with explicit size limits.

Werkzeug closes each stream when the request ends, and the app doesn't store
files or keys between requests.
"""

from werkzeug.datastructures import FileStorage


class UploadTooLargeError(Exception):
    pass


def read_upload_bytes(upload: FileStorage, maximum_bytes: int) -> bytes:
    """Read at most one byte beyond the configured limit to detect overflow."""
    contents = upload.stream.read(maximum_bytes + 1)
    if len(contents) > maximum_bytes:
        raise UploadTooLargeError
    return contents
