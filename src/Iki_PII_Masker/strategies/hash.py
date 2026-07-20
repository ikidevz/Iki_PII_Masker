from typing import Optional
import hashlib
import hmac

from .base import BaseMaskingStrategy, MaskingContext
from ..config import PIIType


class HashStrategy(BaseMaskingStrategy):
    """
    Hashes the value using HMAC-SHA256 with a secret key.
    Much stronger than the previous plain SHA256(salt + value).
    """

    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> str:
        key: bytes | None = None
        if hasattr(ctx, 'key') and ctx.key:
            key = ctx.key if isinstance(
                ctx.key, bytes) else ctx.key.encode('utf-8')
        elif ctx.salt:
            key = ctx.salt.encode('utf-8')

        if not key:
            digest = hashlib.sha256(value.encode('utf-8')).hexdigest()
            return f"SHA:{digest[:16]}"

        # HMAC-SHA256(key, value) — this is the proper way
        digest = hmac.new(key, value.encode('utf-8'),
                          hashlib.sha256).hexdigest()

        return f"SHA:{digest[:16]}"
