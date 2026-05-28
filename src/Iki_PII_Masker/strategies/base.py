from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional
from ..config import PIIType, encrypt_value


@dataclass
class MaskingContext:
    """
    Immutable configuration bundle passed to every masking strategy.
    Adding a new option means adding one field here — nothing else changes.
    """
    reversible:   bool = False
    key_bytes:    bytes = field(default_factory=bytes)
    salt:         str = ""
    seed:         Optional[int] = None
    partial_keep: int = 4
    partial_side: str = "right"


class BaseMaskingStrategy(ABC):
    """
    Template Method Pattern — defines the invariant masking skeleton:
      1. Pass None straight through.
      2. If reversible, AES-encrypt and return early.
      3. Otherwise delegate to the concrete _apply().
    """

    _skip_encryption: bool = False  # set True on Keep / Null

    def mask(self, value: Any, pii_type: Optional[PIIType], ctx: MaskingContext) -> Any:
        if value is None:
            return None
        str_value = str(value)
        if ctx.reversible and ctx.key_bytes and not self._skip_encryption:
            return encrypt_value(str_value, ctx.key_bytes)
        return self._apply(str_value, pii_type, ctx)

    @abstractmethod
    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> Any:
        """Core transformation — receives a non-None string value."""
