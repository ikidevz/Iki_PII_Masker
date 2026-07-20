from typing import ClassVar, Dict
from pathlib import Path

from ..config.enums import Strategy, FileFormat
from ..config.utils import exit_error

from .anonymize import AnonymizeStrategy
from .bucketize import BucketizeStrategy
from .fake import FakeStrategy
from .generalize import GeneralizeStrategy
from .hmac import HMACStrategy
from .hash import HashStrategy
from .keep import KeepStrategy
from .mask_format import MaskFormatStrategy
from .null import NullStrategy
from .pbkdf2 import PBKDF2Strategy
from .perturb import PerturbStrategy
from .partial import PartialStrategy
from .redact import RedactStrategy
from .shuffle import ShuffleStrategy
from .salted_hash import SaltedHashStrategy
from .tokenize import TokenizeStrategy
from .truncate import TruncateStrategy
from .pseudonymize import PseudonymizeStrategy
from .ner_redact import NERRedactStrategy
from .base import BaseMaskingStrategy


class StrategyFactory:
    """
    Creates masking strategy instances.

    Stateless strategies are cached as singletons for performance.
    Stateful strategies (Tokenize, Pseudonymize, etc.) return fresh instances by default
    to prevent cross-job leakage and memory bloat.
    """

    _stateless_registry: ClassVar[Dict[Strategy, BaseMaskingStrategy]] = {}

    @classmethod
    def create(cls, strategy: Strategy, *, fresh: bool = False) -> BaseMaskingStrategy:
        """
        Args:
            strategy: The strategy type to create.
            fresh: If True, always returns a new instance (important for stateful strategies).
        """
        STATEFUL_STRATEGIES = {
            Strategy.tokenize,
            Strategy.pseudonymize,
            Strategy.shuffle,
            Strategy.anonymize,
        }

        if strategy in STATEFUL_STRATEGIES:
            return cls._instantiate(strategy)

        # Stateless strategies — cache as singleton
        if strategy not in cls._stateless_registry:
            cls._stateless_registry[strategy] = cls._instantiate(strategy)

        return cls._stateless_registry[strategy]

    @staticmethod
    def _instantiate(strategy: Strategy) -> BaseMaskingStrategy:
        """Central place to create new instances."""
        mapping = {
            Strategy.keep:         KeepStrategy,
            Strategy.null:         NullStrategy,
            Strategy.redact:       RedactStrategy,
            Strategy.hash:         HashStrategy,
            Strategy.pbkdf2:       PBKDF2Strategy,
            Strategy.salted_hash:  SaltedHashStrategy,
            Strategy.hmac:         HMACStrategy,
            Strategy.fake:         FakeStrategy,
            Strategy.partial:      PartialStrategy,
            Strategy.truncate:     TruncateStrategy,
            Strategy.tokenize:     TokenizeStrategy,
            Strategy.pseudonymize: PseudonymizeStrategy,
            Strategy.shuffle:      ShuffleStrategy,
            Strategy.anonymize:    AnonymizeStrategy,
            Strategy.perturb:      PerturbStrategy,
            Strategy.bucketize:    BucketizeStrategy,
            Strategy.generalize:   GeneralizeStrategy,
            Strategy.mask_format:  MaskFormatStrategy,
            Strategy.ner_redact:   NERRedactStrategy,
        }

        strategy_class = mapping.get(strategy)
        if strategy_class is None:
            raise ValueError(f"Unknown strategy: {strategy}")

        return strategy_class()   # Always instantiate fresh

    @classmethod
    def reset(cls) -> None:
        """Clear all cached stateless instances and optionally clear stateful ones if needed."""
        cls._stateless_registry.clear()


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
        ".xml":     FileFormat.xml,
    }

    @classmethod
    def detect(cls, path: Path) -> FileFormat:
        fmt = cls._ext_map.get(path.suffix.lower())
        if fmt is None:
            exit_error(
                f"Cannot infer format from extension '{path.suffix}'. Use --format."
            )
        return fmt
