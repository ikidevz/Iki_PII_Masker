"""
strategies/pseudonymize.py
==========================
PseudonymizeStrategy — consistent fake replacement.

Unlike ``FakeStrategy`` (which generates a fresh random value per row),
this strategy maps the same input to the same fake output for the
entire run.  This preserves referential integrity across tables — the
same real name always becomes the same fake name — while still hiding
the original value.

Example
-------
    Alice Smith  →  Barbara Clark   (always the same fake name)
    Bob Jones    →  David Miller    (always the same fake name)
    Alice Smith  →  Barbara Clark   ← same mapping reused ✓
"""

from __future__ import annotations

from typing import Optional

from faker import Faker

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType


class PseudonymizeStrategy(BaseMaskingStrategy):
    """
    Consistent fake replacement: same input → same fake output.

    Internally keeps a ``mapping`` dict so cross-table joins still work
    after masking.
    """

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}
        self._faker: Optional[Faker] = None
        self.token_vault = None

    # ── internal ──────────────────────────────────────────────────────────────

    def _get_faker(self, seed: Optional[int]) -> Faker:
        if self._faker is None:
            self._faker = Faker()
            if seed is not None:
                Faker.seed(seed)
        return self._faker

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        if ctx.token_vault is not None:
            namespace = (
                f"{ctx.vault_namespace}:{getattr(pii_type, 'name', 'default')}"
                if ctx.vault_namespace else getattr(pii_type, 'name', 'default')
            )
            token = ctx.token_vault.get_or_create(
                value,
                namespace=namespace,
                token_factory=lambda original: self._make_fake(
                    original, ctx, pii_type),
            )
            return token

        if value in self.mapping:
            return self.mapping[value]

        fake = self._make_fake(value, ctx, pii_type)
        self.mapping[value] = fake
        return fake

    def _make_fake(self, value: str, ctx: MaskingContext,
                   pii_type: Optional[PIIType]) -> str:
        faker = self._get_faker(ctx.seed)
        method = pii_type.faker_method if pii_type else "word"
        try:
            result = getattr(faker, method)()
            return str(result)
        except Exception:
            return faker.word()

    def reverse(self, fake_value: str, namespace: str | None = None) -> Optional[str]:
        """Return the original value for a given fake, or ``None`` if unknown."""
        if namespace is not None and getattr(self, "token_vault", None):
            return self.token_vault.reverse(fake_value, namespace)
        rev = {v: k for k, v in self.mapping.items()}
        return rev.get(fake_value)

    def clear(self) -> None:
        """Reset the mapping (new consistent fake space on next run)."""
        self.mapping.clear()
        self._faker = None
