from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class HMACStrategy(BaseMaskingStrategy):
    """
    Keyed hash using HMAC-SHA256.

    This strategy is useful when a stable keyed hash is required for
    privacy-preserving identifiers and analytics joins.
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
                "HMACStrategy requires a secret key or salt. "
                "Use --key or --salt."
            )

        digest = hmac.new(key, value.encode('utf-8'),
                          hashlib.sha256).hexdigest()
        return f"HMAC:{digest[:16]}"
