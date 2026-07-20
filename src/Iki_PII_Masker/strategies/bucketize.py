from __future__ import annotations

from datetime import datetime
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class BucketizeStrategy(BaseMaskingStrategy):
    """
    Bucketize numeric and date values into simple ranges.
    """

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        step = getattr(ctx, 'bucket_step', 10)
        if step <= 0:
            step = 10

        try:
            if "." in value:
                number = float(value)
            else:
                number = int(value)
            low = int(number // step * step)
            high = low + step
            return f"{low}-{high}"
        except ValueError:
            pass

        try:
            date = datetime.fromisoformat(value)
            precision = getattr(ctx, 'date_precision', 'year')
            if precision == 'month':
                return date.strftime('%Y-%m')
            return date.strftime('%Y')
        except ValueError:
            pass

        return value
