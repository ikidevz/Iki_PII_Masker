from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class SaltedHashStrategy(BaseMaskingStrategy):
    """
    Salted hash using either a secret key or a salt.

    This supports deterministic, one-way hashing for stable joins while
    preventing plain-value collisions across datasets.
    """

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        key = None
        if getattr(ctx, 'key', None):
            key = ctx.key if isinstance(
                ctx.key, (bytes, bytearray)) else str(ctx.key).encode('utf-8')
        elif ctx.salt:
            key = ctx.salt.encode('utf-8')

        if not key:
            raise ValueError(
                "SaltedHashStrategy requires a secret or salt. "
                "Use --key or --salt."
            )

        if getattr(ctx, 'key', None):
            digest = hmac.new(key, value.encode('utf-8'),
                              hashlib.sha256).hexdigest()
        else:
            digest = hashlib.sha256(key + value.encode('utf-8')).hexdigest()

        return f"SALT:{digest[:16]}"
