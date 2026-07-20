from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class PerturbStrategy(BaseMaskingStrategy):
    """
    Slightly alter numeric and date values to preserve analytics utility.
    """

    def __init__(self) -> None:
        self._rng: Optional[random.Random] = None

    def _get_rng(self, ctx: MaskingContext) -> random.Random:
        if self._rng is None:
            self._rng = random.Random(ctx.seed)
        return self._rng

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        rng = self._get_rng(ctx)
        scale = getattr(ctx, 'perturbation_scale', 0.1)
        if scale < 0:
            scale = 0.1

        try:
            if "." in value:
                number = float(value)
                delta = number * scale
                perturbed = number + rng.uniform(-delta, delta)
                return f"{perturbed:.2f}" if '.' in value else str(int(round(perturbed)))
            number = int(value)
            delta = max(1, int(abs(number) * scale))
            return str(number + rng.randint(-delta, delta))
        except ValueError:
            pass

        try:
            date = datetime.fromisoformat(value).date()
            days = getattr(ctx, 'perturbation_days', 7)
            if days <= 0:
                days = 7
            shift = rng.randint(-days, days)
            return (date + timedelta(days=shift)).isoformat()
        except ValueError:
            pass

        return value
