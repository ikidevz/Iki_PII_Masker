"""
strategies/generalize.py
========================
GeneralizeStrategy — replace precise values with broader ranges/buckets.

Handles three value types automatically:

  Numeric  →  bucket into configurable-width ranges
               34        →  "30-40"
               4_999.99  →  "4000-5000"

  Date     →  truncate to year or year+month
               "1990-07-15"  →  "1990"  (default)
               "1990-07-15"  →  "1990-07"  (precision="month")

  String   →  keep first N characters and mask the rest with *
               "90210"  →  "902**"   (geo truncation)
               "SW1A2AA" →  "SW1****"

Context options (pass via ``MaskingContext`` extra fields or use defaults):
  generalize_numeric_step : int   bucket width for numbers   (default 10)
  generalize_date_precision: str  "year" | "month"           (default "year")
  generalize_string_keep   : int  chars to keep for strings  (default 3)
"""

from __future__ import annotations

import re
from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


# ── helpers ───────────────────────────────────────────────────────────────────

_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
_YEAR_RE = re.compile(r"^(\d{4})$")
_NUM_RE = re.compile(r"^-?[\d,_]+(\.\d+)?$")


def _parse_number(value: str) -> Optional[float]:
    clean = value.replace(",", "").replace("_", "")
    try:
        return float(clean)
    except ValueError:
        return None


def _generalize_numeric(value: str, step: int) -> str:
    num = _parse_number(value)
    if num is None:
        return value
    lo = int(num // step) * step
    return f"{lo}-{lo + step}"


def _generalize_date(value: str, precision: str) -> str:
    m = _DATE_RE.match(value)
    if m:
        return m.group(1) if precision == "year" else f"{m.group(1)}-{m.group(2)}"
    if _YEAR_RE.match(value):
        return value
    return value


def _generalize_string(value: str, keep: int) -> str:
    if len(value) <= keep:
        return value
    return value[:keep] + "*" * (len(value) - keep)


# ── strategy ──────────────────────────────────────────────────────────────────

class GeneralizeStrategy(BaseMaskingStrategy):
    """
    Replace precise values with coarser buckets / ranges.

    Numeric → range bucket  |  Date → year or year-month  |  String → prefix mask
    """

    def __init__(
        self,
        numeric_step:    int = 10,
        date_precision:  str = "year",
        string_keep:     int = 3,
    ) -> None:
        self.numeric_step = numeric_step
        self.date_precision = date_precision
        self.string_keep = string_keep

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        # 1. Date check first (dates can look numeric)
        if _DATE_RE.match(value) or _YEAR_RE.match(value):
            return _generalize_date(value, self.date_precision)

        # 2. Numeric
        if _NUM_RE.match(value.replace(",", "").replace("_", "")):
            return _generalize_numeric(value, self.numeric_step)

        # 3. String fallback
        return _generalize_string(value, self.string_keep)
