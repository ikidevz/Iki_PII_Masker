from .base import BaseDataFrameAdapter
from ..config import FileFormat, PIIType, decrypt_value
from ..strategies import BaseMaskingStrategy, MaskingContext
from typing import Any, Optional


class PolarsAdapter(BaseDataFrameAdapter):

    def __init__(self) -> None:
        self._df: Any = None

    def load(self, source: Any, fmt: FileFormat) -> None:
        import polars as pl
        readers = {
            FileFormat.csv:     pl.read_csv,
            FileFormat.parquet: pl.read_parquet,
            FileFormat.json:    pl.read_json,
            FileFormat.ndjson:  pl.read_ndjson,
            FileFormat.excel:   pl.read_excel,
        }
        self._df = readers[fmt](source)

    def save(self, dest: Any, fmt: FileFormat) -> None:
        writers = {
            FileFormat.csv: lambda d: self._df.write_csv(d),
            FileFormat.parquet: lambda d: self._df.write_parquet(d),
            FileFormat.json: lambda d: self._df.write_json(d),
            FileFormat.ndjson: lambda d: self._df.write_ndjson(d),
            FileFormat.excel: lambda d: self._df.write_excel(d),
        }
        writers[fmt](dest)

    @property
    def columns(self) -> list[str]:
        return list(self._df.columns)

    def row_count(self) -> int:
        return len(self._df)

    def apply_mask(self, col: str, strategy: BaseMaskingStrategy,
                   pii_type: Optional[PIIType], ctx: MaskingContext) -> None:
        import polars as pl
        self._df = self._df.with_columns(
            pl.Series(col, [strategy.mask(v, pii_type, ctx)
                      for v in self._df[col].to_list()])
        )

    def apply_unmask(
        self,
        col: str,
        key_bytes: bytes,
        kms_provider: str | None = None,
        kms_region: str | None = None,
        kms_encryption_context: dict[str, str] | None = None,
    ) -> None:
        import polars as pl
        self._df = self._df.with_columns(
            pl.Series(col, [
                decrypt_value(
                    str(v),
                    key_bytes,
                    kms_provider=kms_provider,
                    kms_region=kms_region,
                    kms_encryption_context=kms_encryption_context,
                )
                for v in self._df[col].to_list()
            ])
        )

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        return self._df[col].drop_nulls().to_list()[:n]
