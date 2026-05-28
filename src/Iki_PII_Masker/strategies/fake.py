from typing import Any, Optional
from .base import BaseMaskingStrategy, MaskingContext
from ..config import PIIType

from faker import Faker


class FakeStrategy(BaseMaskingStrategy):
    def __init__(self) -> None:
        self._faker: Any = None

    def _get_faker(self, seed: Optional[int]) -> Any:
        if self._faker is None:
            self._faker = Faker()
            if seed is not None:
                Faker.seed(seed)
        return self._faker

    def _apply(self, value: str, pii_type: Optional[PIIType], ctx: MaskingContext) -> str:
        faker = self._get_faker(ctx.seed)
        method = pii_type.faker_method if pii_type else "word"
        try:
            result = getattr(faker, method)()
            return str(result) if not isinstance(result, str) else result
        except Exception:
            return faker.word()
