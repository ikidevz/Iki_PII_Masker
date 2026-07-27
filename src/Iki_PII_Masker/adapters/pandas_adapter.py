from .base import BaseDataFrameAdapter
from ..config import FileFormat, PIIType, decrypt_value
from ..config.vault.base import BaseTokenVault
from ..strategies import BaseMaskingStrategy, MaskingContext
from typing import Any, Optional


_PANDAS_READ_ONLY = {FileFormat.fwf, FileFormat.spss, FileFormat.sas}
_PANDAS_UNSUPPORTED = {FileFormat.avro, FileFormat.delta}


class PandasAdapter(BaseDataFrameAdapter):

    def __init__(self) -> None:
        self._df: Any = None

    def load(self, source: Any, fmt: FileFormat) -> None:
        import pandas as pd

        if fmt in _PANDAS_UNSUPPORTED:
            raise NotImplementedError(
                f"'{fmt.value}' has no pandas reader — it's a Polars-native "
                f"format (see polars_adapter.py / "
                f"https://docs.pola.rs/api/python/stable/reference/io.html). "
                f"Use Engine.polars for this file."
            )

        readers = {
            FileFormat.csv:       pd.read_csv,
            FileFormat.parquet:   pd.read_parquet,
            FileFormat.json: lambda s: pd.read_json(s, lines=False),
            FileFormat.ndjson: lambda s: pd.read_json(s, lines=True),
            FileFormat.excel:     pd.read_excel,
            FileFormat.feather:   pd.read_feather,
            FileFormat.orc:       pd.read_orc,
            FileFormat.pickle:    pd.read_pickle,
            FileFormat.html: lambda s: pd.read_html(s)[0],
            FileFormat.fwf:       pd.read_fwf,
            FileFormat.hdf5: lambda s: pd.read_hdf(s, key="data"),
            FileFormat.stata:     pd.read_stata,
            FileFormat.spss:      pd.read_spss,
            FileFormat.sas:       pd.read_sas,
            FileFormat.clipboard: lambda _s: pd.read_clipboard(),
        }
        reader = readers.get(fmt)
        if reader is None:
            raise NotImplementedError(
                f"pandas adapter has no reader for '{fmt.value}'.")
        self._df = reader(source)

    def save(self, dest: Any, fmt: FileFormat) -> None:
        if fmt in _PANDAS_UNSUPPORTED:
            raise NotImplementedError(
                f"'{fmt.value}' has no pandas writer — it's a Polars-native "
                f"format. Use Engine.polars for this file."
            )
        if fmt in _PANDAS_READ_ONLY:
            raise NotImplementedError(
                f"'{fmt.value}' is read-only in pandas — there is no "
                f"DataFrame.to_{fmt.value}(). See "
                f"https://pandas.pydata.org/docs/user_guide/io.html"
            )

        writers = {
            FileFormat.csv: lambda d: self._df.to_csv(d, index=False),
            FileFormat.parquet: lambda d: self._df.to_parquet(d, index=False),
            FileFormat.json: lambda d: self._df.to_json(d, orient="records", indent=2),
            FileFormat.ndjson: lambda d: self._df.to_json(d, orient="records", lines=True),
            FileFormat.excel: lambda d: self._df.to_excel(d, index=False),
            FileFormat.feather: lambda d: self._df.to_feather(d),
            FileFormat.orc: lambda d: self._df.to_orc(d),
            FileFormat.pickle: lambda d: self._df.to_pickle(d),
            FileFormat.html: lambda d: self._df.to_html(d, index=False),
            FileFormat.hdf5: lambda d: self._df.to_hdf(d, key="data", mode="w"),
            FileFormat.stata: lambda d: self._df.to_stata(d, write_index=False),
            FileFormat.clipboard: lambda _d: self._df.to_clipboard(index=False),
        }
        writer = writers.get(fmt)
        if writer is None:
            raise NotImplementedError(
                f"pandas adapter has no writer for '{fmt.value}'.")
        writer(dest)

    @property
    def columns(self) -> list[str]:
        return list(self._df.columns)

    def row_count(self) -> int:
        return len(self._df)

    def apply_mask(self, col: str, strategy: BaseMaskingStrategy,
                   pii_type: Optional[PIIType], ctx: MaskingContext) -> None:
        self._df[col] = self._df[col].map(
            lambda v: strategy.mask(v, pii_type, ctx))

    def apply_unmask(
        self,
        col: str,
        key_bytes: bytes,
        kms_provider: str | None = None,
        kms_region: str | None = None,
        kms_encryption_context: dict[str, str] | None = None,
    ) -> None:
        self._df[col] = self._df[col].map(
            lambda v: decrypt_value(
                str(v),
                key_bytes,
                kms_provider=kms_provider,
                kms_region=kms_region,
                kms_encryption_context=kms_encryption_context,
            ))

    def apply_vault_reverse(
        self,
        col: str,
        token_vault: BaseTokenVault,
        namespace: str,
    ) -> None:
        self._df[col] = self._df[col].map(
            lambda v: token_vault.reverse(
                str(v), namespace) if v is not None else None
        )

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        return self._df[col].dropna().tolist()[:n]
