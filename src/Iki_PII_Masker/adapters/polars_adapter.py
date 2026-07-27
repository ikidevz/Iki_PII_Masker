from .base import BaseDataFrameAdapter
from ..config import FileFormat, PIIType, decrypt_value
from ..config.vault.base import BaseTokenVault
from ..strategies import BaseMaskingStrategy, MaskingContext
from typing import Any, Optional


# Formats Polars can read/write natively. See:
# https://docs.pola.rs/api/python/stable/reference/io.html
#
# Polars has no ORC, pickle, HTML, fixed-width, HDF5, Stata, SPSS or SAS
# I/O — those are pandas-only (see pandas_adapter.py). ODS is read-only in
# Polars (there's a reader, no writer).
_POLARS_UNSUPPORTED = {
    FileFormat.orc, FileFormat.pickle, FileFormat.html, FileFormat.fwf,
    FileFormat.hdf5, FileFormat.stata, FileFormat.spss, FileFormat.sas,
}
_POLARS_READ_ONLY = {FileFormat.ods}


class PolarsAdapter(BaseDataFrameAdapter):

    def __init__(self) -> None:
        self._df: Any = None

    def load(self, source: Any, fmt: FileFormat) -> None:
        import polars as pl

        if fmt in _POLARS_UNSUPPORTED:
            raise NotImplementedError(
                f"'{fmt.value}' has no Polars reader — it's a pandas-native "
                f"format (see pandas_adapter.py / "
                f"https://pandas.pydata.org/docs/user_guide/io.html). "
                f"Use Engine.pandas for this file."
            )

        readers = {
            FileFormat.csv:       pl.read_csv,
            FileFormat.parquet:   pl.read_parquet,
            FileFormat.json:      pl.read_json,
            FileFormat.ndjson:    pl.read_ndjson,
            FileFormat.excel:     pl.read_excel,
            FileFormat.feather:   pl.read_ipc,
            FileFormat.avro:      pl.read_avro,
            FileFormat.delta:     pl.read_delta,
            FileFormat.ods:       pl.read_ods,
            FileFormat.clipboard: lambda _s: pl.read_clipboard(),
        }
        reader = readers.get(fmt)
        if reader is None:
            raise NotImplementedError(
                f"Polars adapter has no reader for '{fmt.value}'.")
        self._df = reader(source)

    def save(self, dest: Any, fmt: FileFormat) -> None:
        if fmt in _POLARS_UNSUPPORTED:
            raise NotImplementedError(
                f"'{fmt.value}' has no Polars writer — it's a pandas-native "
                f"format. Use Engine.pandas for this file."
            )
        if fmt in _POLARS_READ_ONLY:
            raise NotImplementedError(
                f"'{fmt.value}' is read-only in Polars — there is no "
                f"DataFrame.write_{fmt.value}(). See "
                f"https://docs.pola.rs/api/python/stable/reference/io.html"
            )

        writers = {
            FileFormat.csv: lambda d: self._df.write_csv(d),
            FileFormat.parquet: lambda d: self._df.write_parquet(d),
            FileFormat.json: lambda d: self._df.write_json(d),
            FileFormat.ndjson: lambda d: self._df.write_ndjson(d),
            FileFormat.excel: lambda d: self._df.write_excel(d),
            FileFormat.feather: lambda d: self._df.write_ipc(d),
            FileFormat.avro: lambda d: self._df.write_avro(d),
            FileFormat.delta: lambda d: self._df.write_delta(d),
            FileFormat.clipboard: lambda _d: self._df.write_clipboard(),
        }
        writer = writers.get(fmt)
        if writer is None:
            raise NotImplementedError(
                f"Polars adapter has no writer for '{fmt.value}'.")
        writer(dest)

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

    def apply_vault_reverse(
        self,
        col: str,
        token_vault: BaseTokenVault,
        namespace: str,
    ) -> None:
        import polars as pl
        self._df = self._df.with_columns(
            pl.Series(col, [
                token_vault.reverse(
                    str(v), namespace) if v is not None else None
                for v in self._df[col].to_list()
            ])
        )

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        return self._df[col].drop_nulls().to_list()[:n]
