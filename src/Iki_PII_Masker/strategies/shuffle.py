from __future__ import annotations

import random
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class ShuffleStrategy(BaseMaskingStrategy):
    """
    Replace values with stable random tokens to de-identify while preserving
    the value distribution shape and uniqueness within a run.
    """

    PREFIX = "SHF-"

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self._rng: Optional[random.Random] = None

    def _get_rng(self, ctx: MaskingContext) -> random.Random:
        if self._rng is None:
            self._rng = random.Random(ctx.seed)
        return self._rng

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        if value in self.mapping:
            return self.mapping[value]

        rng = self._get_rng(ctx)
        token = f"{self.PREFIX}{rng.getrandbits(64):016x}"
        while token in self.mapping.values():
            token = f"{self.PREFIX}{rng.getrandbits(64):016x}"

        self.mapping[value] = token
        return token

    def clear(self) -> None:
        self.mapping.clear()
        self._rng = None
