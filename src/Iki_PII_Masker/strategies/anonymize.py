from __future__ import annotations

from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class AnonymizeStrategy(BaseMaskingStrategy):
    """
    Replace values with simple anonymous placeholders.
    """

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self.counter = 0

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        if value in self.mapping:
            return self.mapping[value]

        self.counter += 1
        prefix = getattr(ctx, 'anonymize_prefix', 'ANON')
        token = f"{prefix}-{self.counter:04d}"
        self.mapping[value] = token
        return token

    def clear(self) -> None:
        self.mapping.clear()
        self.counter = 0
