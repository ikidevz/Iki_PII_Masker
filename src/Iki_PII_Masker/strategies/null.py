from typing import Optional
from .base import BaseMaskingStrategy, MaskingContext
from ..config import PIIType


class NullStrategy(BaseMaskingStrategy):
    _skip_encryption = True

    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> None:
        return None
