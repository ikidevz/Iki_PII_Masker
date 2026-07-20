"""
strategies/tokenize.py
======================
TokenizeStrategy — replaces each value with a stable, opaque token.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class TokenizeStrategy(BaseMaskingStrategy):
    """
    Replaces each unique value with a stable token (``TOK-<hex>``).

    Same input → same token **within the lifetime of this instance**
    when using the same secret key.
    """

    PREFIX = "TOK-"

    def __init__(self) -> None:
        self.token_table: dict[str, str] = {}      # value → token
        self._reverse_table: dict[str, str] = {}   # token → value

    # ── internal ──────────────────────────────────────────────────────────────

    def _make_token(self, value: str, ctx: MaskingContext) -> str:
        """Derive token using HMAC with a secret key (much stronger than before)."""
        key = getattr(ctx, 'key_bytes', None)
        if not key and ctx.salt:
            key = ctx.salt.encode('utf-8')

        if key is None:
            key = b""  # stable fallback when no secret or salt is provided

        digest = hmac.new(
            key,
            value.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()[:16]

        return self.PREFIX + digest

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        if value in self.token_table:
            return self.token_table[value]

        token = self._make_token(value, ctx)

        # Collision guard (still useful even with HMAC, though very rare)
        if token in self._reverse_table and self._reverse_table[token] != value:
            token = self.PREFIX + secrets.token_hex(8)

        self.token_table[value] = token
        self._reverse_table[token] = value
        return token

    # ── public helpers ────────────────────────────────────────────────────────

    def detokenize(self, token: str) -> Optional[str]:
        """Return the original value for *token*, or ``None`` if unknown."""
        return self._reverse_table.get(token)

    def clear(self) -> None:
        """Wipe both lookup tables."""
        self.token_table.clear()
        self._reverse_table.clear()
