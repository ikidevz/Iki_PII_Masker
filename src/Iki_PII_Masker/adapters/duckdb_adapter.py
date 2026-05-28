from typing import Any, Optional
from .base import BaseDataFrameAdapter
from ..config import FileFormat, PIIType, decrypt_value, exit_error
from ..strategies import BaseMaskingStrategy, MaskingContext

import io


class DuckDBAdapter(BaseDataFrameAdapter):
    """
    Adapter over DuckDB — handles files larger than RAM via streaming scans.
    Excel is not supported by DuckDB; use --engine pandas for .xlsx files.
    """

    def __init__(self) -> None:
        self._rel: Any = None
        self._con: Any = None

    def _conn(self) -> Any:
        if self._con is None:
            import duckdb
            self._con = duckdb.connect()
        return self._con

    def _to_arrow(self) -> Any:
        """Materialise the current relation to a pyarrow.Table."""
        result = self._rel.arrow()
        if hasattr(result, "read_all"):   # DuckDB may return RecordBatchReader
            result = result.read_all()
        return result

    def load(self, source: Any, fmt: FileFormat) -> None:
        if fmt == FileFormat.excel:
            exit_error(
                "DuckDB does not support Excel. Use --engine pandas for .xlsx files.")
        con = self._conn()
        if isinstance(source, (bytes, io.BytesIO)):
            import polars as pl
            buf = source if isinstance(
                source, io.BytesIO) else io.BytesIO(source)
            readers = {
                FileFormat.csv:     pl.read_csv,
                FileFormat.parquet: pl.read_parquet,
                FileFormat.json:    pl.read_json,
                FileFormat.ndjson:  pl.read_ndjson,
            }
            self._rel = con.from_arrow(readers[fmt](buf).to_arrow())
        else:
            path = str(source)
            loaders = {
                FileFormat.csv: lambda p: con.read_csv(p),
                FileFormat.parquet: lambda p: con.read_parquet(p),
                FileFormat.json: lambda p: con.read_json(p),
                FileFormat.ndjson: lambda p: con.read_json(p),
            }
            self._rel = loaders[fmt](path)

    def save(self, dest: Any, fmt: FileFormat) -> None:
        if fmt == FileFormat.excel:
            exit_error(
                "DuckDB does not support Excel output. Use --engine pandas.")
        import polars as pl
        df = pl.from_arrow(self._to_arrow())
        writers = {
            FileFormat.csv: lambda d: df.write_csv(d),
            FileFormat.parquet: lambda d: df.write_parquet(d),
            FileFormat.json: lambda d: df.write_json(d),
            FileFormat.ndjson: lambda d: df.write_ndjson(d),
        }
        writers[fmt](dest)

    @property
    def columns(self) -> list[str]:
        return list(self._rel.columns)

    def row_count(self) -> int:
        return self._rel.count("*").fetchone()[0]

    def apply_mask(self, col: str, strategy: BaseMaskingStrategy,
                   pii_type: Optional[PIIType], ctx: MaskingContext) -> None:
        import pyarrow as pa
        values = self._rel.select(col).fetchall()
        masked = [strategy.mask(row[0], pii_type, ctx) for row in values]
        arrow_tbl = self._to_arrow()
        idx = list(self._rel.columns).index(col)
        arrays = [
            pa.array(masked) if i == idx else arrow_tbl.column(i)
            for i in range(arrow_tbl.num_columns)
        ]
        new_table = pa.table({arrow_tbl.schema.field(i).name: arrays[i]
                              for i in range(arrow_tbl.num_columns)})
        self._rel = self._conn().from_arrow(new_table)

    def apply_unmask(self, col: str, key_bytes: bytes) -> None:
        import pyarrow as pa
        arrow_tbl = self._to_arrow()
        idx = list(self._rel.columns).index(col)
        values = arrow_tbl.column(idx).to_pylist()
        decrypted = [decrypt_value(str(v), key_bytes) for v in values]
        arrays = [
            pa.array(decrypted) if i == idx else arrow_tbl.column(i)
            for i in range(arrow_tbl.num_columns)
        ]
        new_table = pa.table({arrow_tbl.schema.field(i).name: arrays[i]
                              for i in range(arrow_tbl.num_columns)})
        self._rel = self._conn().from_arrow(new_table)

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        rows = self._rel.select(col).limit(n * 3).fetchall()
        return [row[0] for row in rows if row[0] is not None][:n]
