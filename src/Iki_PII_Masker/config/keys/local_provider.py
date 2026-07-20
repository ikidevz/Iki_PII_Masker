from __future__ import annotations

from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .base import BaseKeyProvider


class LocalKeyProvider(BaseKeyProvider):
    """Derive a per-column key from a single master secret."""

    def __init__(self, master_secret: str) -> None:
        self.master_secret = master_secret.encode("utf-8")

    def get_key(self, column: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=column.encode("utf-8"),
        )
        return hkdf.derive(self.master_secret)

    def rotate(self, column: str) -> bytes:
        # Rotation is context-specific; derive a new key from an updated master secret.
        raise NotImplementedError(
            "LocalKeyProvider rotation requires a new master secret."
        )
