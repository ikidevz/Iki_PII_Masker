"""
strategies/tokenize.py
======================
TokenizeStrategy — replaces each value with a stable, opaque token.

The same input value always produces the same token within a run
(deterministic by default). Tokens are stored in an in-memory lookup
table on the strategy instance so the original can be recovered via
``TokenizeStrategy.detokenize(token)``.

For cross-run persistence, dump ``.token_table`` to a file yourself
and reload it before the next run — keeping storage concerns outside
the strategy.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class TokenizeStrategy(BaseMaskingStrategy):
    """
    Replaces each unique value with a stable token (``TOK-<hex>``).

    Same input → same token within the lifetime of this instance.
    Recover originals via ``detokenize(token)`` or inspect ``.token_table``.
    """

    PREFIX = "TOK-"

    def __init__(self) -> None:
        # value → token
        self.token_table:    dict[str, str] = {}
        # token → value  (reverse lookup)
        self._reverse_table: dict[str, str] = {}

    # ── internal ──────────────────────────────────────────────────────────────

    def _make_token(self, value: str) -> str:
        """Derive a short deterministic hex token from the value + a fixed salt."""
        digest = hashlib.sha256(("TOK:" + value).encode()).hexdigest()[:16]
        return self.PREFIX + digest

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        if value in self.token_table:
            return self.token_table[value]

        token = self._make_token(value)

        # Collision guard: if two distinct values hash to the same token,
        # append random suffix to the later one.
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
        """Wipe both lookup tables (start a fresh token space)."""
        self.token_table.clear()
        self._reverse_table.clear()
