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

    # ── internal ──────────────────────────────────────────────────────────────

    def _get_faker(self, seed: Optional[int]) -> Faker:
        if self._faker is None:
            self._faker = Faker()
            if seed is not None:
                Faker.seed(seed)
        return self._faker

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        if value in self.mapping:
            return self.mapping[value]

        faker = self._get_faker(ctx.seed)
        method = pii_type.faker_method if pii_type else "word"
        try:
            result = getattr(faker, method)()
            fake = str(result) if not isinstance(result, str) else result
        except Exception:
            fake = faker.word()

        self.mapping[value] = fake
        return fake

    # ── public helpers ────────────────────────────────────────────────────────

    def reverse(self, fake_value: str) -> Optional[str]:
        """Return the original value for a given fake, or ``None`` if unknown."""
        rev = {v: k for k, v in self.mapping.items()}
        return rev.get(fake_value)

    def clear(self) -> None:
        """Reset the mapping (new consistent fake space on next run)."""
        self.mapping.clear()
        self._faker = None
