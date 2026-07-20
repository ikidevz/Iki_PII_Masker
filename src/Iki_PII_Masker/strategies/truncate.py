from __future__ import annotations
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class TruncateStrategy(BaseMaskingStrategy):
    """
    Truncate the value to a fixed prefix and discard the rest.
    """

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        keep = getattr(ctx, 'truncate_keep', None)
        if keep is None:
            keep = ctx.partial_keep
        if keep < 0:
            keep = 0
        return value if len(value) <= keep else value[:keep]
