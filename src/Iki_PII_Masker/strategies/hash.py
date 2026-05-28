from typing import Optional
from .base import BaseMaskingStrategy, MaskingContext
from ..config import PIIType
import hashlib


class HashStrategy(BaseMaskingStrategy):
    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> str:
        digest = hashlib.sha256((ctx.salt + value).encode()).hexdigest()
        return f"SHA:{digest[:16]}"
