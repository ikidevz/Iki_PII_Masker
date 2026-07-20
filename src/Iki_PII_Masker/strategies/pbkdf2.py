from typing import Optional
import hashlib

from .base import BaseMaskingStrategy, MaskingContext
from ..config import PIIType


class PBKDF2Strategy(BaseMaskingStrategy):
    """
    Derive a strong one-way hash via PBKDF2-HMAC-SHA256.

    This is useful when you want a stronger, key-stretched hash than
    plain SHA256 and a clear semantic difference from the existing
    HMAC-SHA256 `Strategy.hash` implementation.
    """

    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> str:
        key: bytes | None = None
        if getattr(ctx, 'key', None):
            key = ctx.key if isinstance(
                ctx.key, (bytes, bytearray)) else str(ctx.key).encode('utf-8')
        elif ctx.salt:
            key = ctx.salt.encode('utf-8')

        if not key:
            raise ValueError(
                "PBKDF2Strategy requires a secret key or salt for security. "
                "Use --key <secret> or --salt <strong-salt>."
            )

        digest = hashlib.pbkdf2_hmac(
            'sha256',
            value.encode('utf-8'),
            key,
            ctx.pbkdf2_iterations,
        )
        return f"PBKDF2:{digest.hex()[:32]}"
