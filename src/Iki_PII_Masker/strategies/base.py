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
    reversible:         bool = False
    key_bytes:          Any = field(default_factory=bytes)
    key:                bytes | str | None = None
    salt:               str = ""
    pbkdf2_iterations:  int = 100_000
    seed:               Optional[int] = None
    partial_keep:       int = 4
    partial_side:       str = "right"
    truncate_keep:      int = 4
    bucket_step:        int = 10
    date_precision:     str = "year"
    anonymize_prefix:   str = "ANON"
    perturbation_scale: float = 0.1
    perturbation_days:  int = 7
    reversible_cipher:  str = "aesgcm"
    kms_provider:       str | None = None
    kms_region:         str | None = None
    kms_key_id:         str | None = None
    kms_encryption_context: dict[str, str] | None = None
    token_vault:        Any | None = None
    vault_namespace:    str = "default"
    key_provider:       Any | None = None


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
        if ctx.reversible and not self._skip_encryption:
            return encrypt_value(
                str_value,
                ctx.key_bytes,
                ctx.reversible_cipher,
                kms_key_id=ctx.kms_key_id,
                kms_provider=ctx.kms_provider,
                kms_region=ctx.kms_region,
                kms_encryption_context=ctx.kms_encryption_context,
            )
        return self._apply(str_value, pii_type, ctx)

    @abstractmethod
    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> Any:
        """Core transformation — receives a non-None string value."""
