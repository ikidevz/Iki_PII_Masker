"""
adapters/sqlalchemy_adapter.py
==============================
SQLAlchemyAdapter — mask PII in-place in a live relational database.

Supports any SQLAlchemy-compatible database: PostgreSQL, MySQL, SQLite,
MariaDB, MS SQL Server, Oracle, etc.

Install extra dependency:
    pip install sqlalchemy

For specific databases you also need the driver:
    pip install psycopg2-binary     # PostgreSQL
    pip install pymysql             # MySQL / MariaDB
    # SQLite ships with Python — no extra driver needed

Usage
-----
    from Iki_PII_Masker.facade import create_sql_adapter

    adapter = create_sql_adapter(
        url="postgresql+psycopg2://user:pass@localhost/mydb",
        table="users",
        id_column="id",        # primary key for UPDATE statements
        chunk_size=500,        # rows per commit batch
    )
    mask_dataframe(adapter, "email:phone", Strategy.fake)
    # rows are updated directly in the database — no save_data() needed

Notes
-----
- ``load()`` fetches all rows into memory as a list of dicts.
- ``save()`` issues batched UPDATE statements — one per changed row.
- ``FileFormat`` is ignored by both ``load`` and ``save``; pass any value.
- For very large tables, prefer DuckDB with an exported CSV/Parquet.
"""

from __future__ import annotations

from typing import Any, Optional

from .base import BaseDataFrameAdapter
from ..config.crypto import decrypt_value
from ..config.enums import FileFormat
from ..config.registry import PIIType
from ..strategies import BaseMaskingStrategy, MaskingContext


class SQLAlchemyAdapter(BaseDataFrameAdapter):
    """
    Adapter that reads from / writes back to a relational database table
    via SQLAlchemy Core.

    Parameters
    ----------
    url        : SQLAlchemy connection URL
    table      : table name to operate on
    id_column  : primary-key column used in UPDATE WHERE clause
    chunk_size : number of rows committed per batch  (default 500)
    """

    def __init__(
        self,
        url:        str,
        table:      str,
        id_column:  str = "id",
        chunk_size: int = 500,
    ) -> None:
        self._url = url
        self._table = table
        self._id_column = id_column
        self._chunk_size = chunk_size

        # internal state
        self._rows:    list[dict[str, Any]] = []
        self._columns: list[str] = []
        self._engine:  Any = None

    # ── lazy engine ────────────────────────────────────────────────────────────

    def _get_engine(self) -> Any:
        if self._engine is None:
            try:
                from sqlalchemy import create_engine
            except ImportError:
                raise ImportError(
                    "SQLAlchemy is required for SQLAlchemyAdapter.\n"
                    "Install it with:  pip install sqlalchemy"
                )
            self._engine = create_engine(self._url)
        return self._engine

    # ── BaseDataFrameAdapter interface ─────────────────────────────────────────

    def load(self, source: Any = None, fmt: FileFormat = FileFormat.csv) -> None:
        """
        Fetch all rows from ``self._table`` into memory.

        *source* and *fmt* are ignored — the connection URL and table name
        supplied at construction time are used instead.
        """
        from sqlalchemy import text
        engine = self._get_engine()
        with engine.connect() as conn:
            result = conn.execute(text(f"SELECT * FROM {self._table}"))
            self._columns = list(result.keys())
            self._rows = [dict(row._mapping) for row in result]

    def save(self, dest: Any = None, fmt: FileFormat = FileFormat.csv) -> None:
        """
        Write modified rows back to the database with batched UPDATEs.

        *dest* and *fmt* are ignored.
        """
        from sqlalchemy import text
        if not self._rows:
            return

        engine = self._get_engine()
        non_id = [c for c in self._columns if c != self._id_column]
        set_clause = ", ".join(f"{c} = :{c}" for c in non_id)
        sql = text(
            f"UPDATE {self._table} "
            f"SET {set_clause} "
            f"WHERE {self._id_column} = :{self._id_column}"
        )

        with engine.begin() as conn:
            for i in range(0, len(self._rows), self._chunk_size):
                batch = self._rows[i: i + self._chunk_size]
                conn.execute(sql, batch)

    @property
    def columns(self) -> list[str]:
        return list(self._columns)

    def row_count(self) -> int:
        return len(self._rows)

    def apply_mask(
        self,
        col:      str,
        strategy: BaseMaskingStrategy,
        pii_type: Optional[PIIType],
        ctx:      MaskingContext,
    ) -> None:
        for row in self._rows:
            row[col] = strategy.mask(row[col], pii_type, ctx)

    def apply_unmask(
        self,
        col: str,
        key_bytes: bytes,
        kms_provider: str | None = None,
        kms_region: str | None = None,
        kms_encryption_context: dict[str, str] | None = None,
    ) -> None:
        for row in self._rows:
            if row[col] is not None:
                row[col] = decrypt_value(
                    str(row[col]),
                    key_bytes,
                    kms_provider=kms_provider,
                    kms_region=kms_region,
                    kms_encryption_context=kms_encryption_context,
                )

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        return [r[col] for r in self._rows if r.get(col) is not None][:n]
