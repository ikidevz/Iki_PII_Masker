from typing import Optional
from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class RedactStrategy(BaseMaskingStrategy):
    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> str:
        return pii_type.redact_label if pii_type else "[REDACTED]"
