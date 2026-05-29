"""
strategies/mask_format.py
=========================
MaskFormatStrategy — preserve the *shape* of a value while masking its content.

Every alphanumeric character in the value is replaced with a mask character
(default ``*``), while non-alphanumeric characters (spaces, dashes, dots,
``@``, ``/``, etc.) are kept in place.

Examples
--------
    john@example.com     →  xxxx@xxxxxxx.xxx
    4111-1111-1111-1234  →  ****-****-****-1234  (last 4 kept when partial_keep set)
    +1 (555) 867-5309    →  +* (***) ***-****
    192.168.1.105        →  ***.***.*.*

Why this is different from ``partial``
---------------------------------------
``partial`` keeps N chars from one side.  ``mask_format`` keeps the
structural separators (``-``, ``.``, ``@``, spaces) so the masked value
looks like a real value of that type — useful for format-sensitive
downstream systems.

Configuration
-------------
  mask_char : str   character to replace alphanumeric chars with  (default ``*``)
  keep_last : int   keep the last N alphanumeric chars unmasked    (default 0)
"""

from __future__ import annotations

from typing import Optional

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class MaskFormatStrategy(BaseMaskingStrategy):
    """
    Replace alphanumeric characters with *mask_char* while preserving
    structural separators (``-``, ``.``, ``@``, spaces, brackets, …).
    """

    def __init__(self, mask_char: str = "*", keep_last: int = 0) -> None:
        self.mask_char = mask_char[0] if mask_char else "*"
        self.keep_last = max(0, keep_last)

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        # Collect indices of alphanumeric characters in order
        alnum_indices = [i for i, ch in enumerate(value) if ch.isalnum()]

        if not alnum_indices:
            return value

        # How many to keep (from the end of the alnum list)
        keep_count = min(self.keep_last, len(alnum_indices))
        keep_set = set(alnum_indices[-keep_count:]) if keep_count else set()

        result = []
        for i, ch in enumerate(value):
            if ch.isalnum() and i not in keep_set:
                result.append(self.mask_char)
            else:
                result.append(ch)
        return "".join(result)
