from typing import Any, Optional
from .base import BaseMaskingStrategy, MaskingContext
from ..config import PIIType


class PartialStrategy(BaseMaskingStrategy):
    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> str:
        n = ctx.partial_keep
        if len(value) <= n:
            return value
        if ctx.partial_side == "right":
            return "*" * (len(value) - n) + value[-n:]
        return value[:n] + "*" * (len(value) - n)
