import sys
from pathlib import Path
from typing import ClassVar
from ..config import Strategy, FileFormat, exit_error
from .keep import KeepStrategy
from .null import NullStrategy
from .redact import RedactStrategy
from .hash import HashStrategy
from .fake import FakeStrategy
from .partial import PartialStrategy
from .base import BaseMaskingStrategy


class StrategyFactory:
    """Maps Strategy enum values to singleton strategy instances."""

    _registry: ClassVar[dict[Strategy, BaseMaskingStrategy]] = {}

    @classmethod
    def create(cls, strategy: Strategy) -> BaseMaskingStrategy:
        if not cls._registry:
            cls._registry = {
                Strategy.keep:    KeepStrategy(),
                Strategy.null:    NullStrategy(),
                Strategy.redact:  RedactStrategy(),
                Strategy.hash:    HashStrategy(),
                Strategy.fake:    FakeStrategy(),
                Strategy.partial: PartialStrategy(),
            }
        return cls._registry[strategy]


class FormatRegistry:
    """Maps file extensions to FileFormat values."""

    _ext_map: ClassVar[dict[str, FileFormat]] = {
        ".csv":     FileFormat.csv,
        ".parquet": FileFormat.parquet,
        ".json":    FileFormat.json,
        ".ndjson":  FileFormat.ndjson,
        ".jsonl":   FileFormat.ndjson,
        ".xlsx":    FileFormat.excel,
        ".xls":     FileFormat.excel,
    }

    @classmethod
    def detect(cls, path: Path) -> FileFormat:
        fmt = cls._ext_map.get(path.suffix.lower())
        if fmt is None:
            exit_error(
                f"Cannot infer format from extension '{path.suffix}'. Use --format."
            )
        return fmt
