from .base import BaseDataFrameAdapter
from ..config import FileFormat, PIIType, decrypt_value
from ..strategies import BaseMaskingStrategy, MaskingContext
from typing import Any, Optional


class PandasAdapter(BaseDataFrameAdapter):

    def __init__(self) -> None:
        self._df: Any = None

    def load(self, source: Any, fmt: FileFormat) -> None:
        import pandas as pd
        readers = {
            FileFormat.csv:     pd.read_csv,
            FileFormat.parquet: pd.read_parquet,
            FileFormat.json: lambda s: pd.read_json(s, lines=False),
            FileFormat.ndjson: lambda s: pd.read_json(s, lines=True),
            FileFormat.excel:   pd.read_excel,
        }
        self._df = readers[fmt](source)

    def save(self, dest: Any, fmt: FileFormat) -> None:
        writers = {
            FileFormat.csv: lambda d: self._df.to_csv(d, index=False),
            FileFormat.parquet: lambda d: self._df.to_parquet(d, index=False),
            FileFormat.json: lambda d: self._df.to_json(d, orient="records", indent=2),
            FileFormat.ndjson: lambda d: self._df.to_json(d, orient="records", lines=True),
            FileFormat.excel: lambda d: self._df.to_excel(d, index=False),
        }
        writers[fmt](dest)

    @property
    def columns(self) -> list[str]:
        return list(self._df.columns)

    def row_count(self) -> int:
        return len(self._df)

    def apply_mask(self, col: str, strategy: BaseMaskingStrategy,
                   pii_type: Optional[PIIType], ctx: MaskingContext) -> None:
        self._df[col] = self._df[col].map(
            lambda v: strategy.mask(v, pii_type, ctx))

    def apply_unmask(self, col: str, key_bytes: bytes) -> None:
        self._df[col] = self._df[col].map(
            lambda v: decrypt_value(str(v), key_bytes))

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        return self._df[col].dropna().tolist()[:n]
