from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional
from ..strategies.base import BaseMaskingStrategy, MaskingContext
from ..config.enums import FileFormat
from ..config.registry import PIIType


class BaseDataFrameAdapter(ABC):
    """
    Adapter Pattern — uniform interface over Polars, Pandas, and DuckDB.
    Adding a new engine = one new subclass, zero changes elsewhere.
    """

    @abstractmethod
    def load(self, source: Any, fmt: FileFormat) -> None: ...

    @abstractmethod
    def save(self, dest: Any, fmt: FileFormat) -> None: ...

    @property
    @abstractmethod
    def columns(self) -> list[str]: ...

    @abstractmethod
    def row_count(self) -> int: ...

    @abstractmethod
    def apply_mask(self, col: str, strategy: BaseMaskingStrategy,
                   pii_type: Optional[PIIType], ctx: MaskingContext) -> None: ...

    @abstractmethod
    def apply_unmask(self, col: str, key_bytes: bytes) -> None: ...

    @abstractmethod
    def sample_values(self, col: str, n: int = 3) -> list[Any]: ...
