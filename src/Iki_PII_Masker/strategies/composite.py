from __future__ import annotations

import dataclasses
from typing import Any, Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType
from ..config.crypto import encrypt_value


class CompositeStrategy(BaseMaskingStrategy):
    """
    Chain multiple strategies in order and optionally encrypt the final output.

    This supports a portable composition model that applies several lightweight
    masking strategies in sequence, then applies reversible encryption only once
    if requested.
    """

    _skip_encryption = True

    def __init__(self, strategies: list[BaseMaskingStrategy]) -> None:
        self.strategies = strategies

    def mask(self, value: Any, pii_type: Optional[PIIType], ctx: MaskingContext) -> Any:
        if value is None:
            return None

        result = value
        for strategy in self.strategies:
            sub_ctx = dataclasses.replace(ctx, reversible=False, key_bytes=b"")
            result = strategy.mask(result, pii_type, sub_ctx)
            if result is None:
                return None

        result = str(result)
        if ctx.reversible and ctx.key_bytes:
            return encrypt_value(result, ctx.key_bytes,
                                 getattr(ctx, 'reversible_cipher', 'aesgcm'))

        return result

    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> Any:
        raise NotImplementedError(
            "CompositeStrategy uses custom mask() logic.")
