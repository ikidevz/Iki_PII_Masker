from typing import Any, Optional
from .base import BaseMaskingStrategy, MaskingContext
from ..config import PIIType


class KeepStrategy(BaseMaskingStrategy):
    _skip_encryption = True

    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> str:
        return value
