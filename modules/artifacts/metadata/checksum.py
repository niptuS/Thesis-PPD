from __future__ import annotations

import hashlib
from pathlib import Path

_CHUNK_SIZE = 65536
_CSV_ENCODING = "utf-8"


def compute_file_checksum(path: str | Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK_SIZE), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_row_checksum(payload: str) -> str:
    return hashlib.sha256(payload.encode(_CSV_ENCODING)).hexdigest()[:16]


def verify_file_checksum(path: str | Path, expected: str, algorithm: str = "sha256") -> bool:
    return compute_file_checksum(path, algorithm) == expected
