"""
config/vault/sqlalchemy_vault.py
===============================
SQLAlchemy-backed persistent token vault.

This backend is optional and only imported when explicitly requested.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .base import BaseTokenVault
from ..crypto import decrypt_value, encrypt_value
from .sqlite_vault import DEFAULT_TABLE


class SQLAlchemyTokenVault(BaseTokenVault):
    def __init__(
        self,
        url: str,
        table: str = DEFAULT_TABLE,
        master_key: bytes | None = None,
        **engine_kwargs: Any,
    ) -> None:
        try:
            from sqlalchemy import create_engine, MetaData, Table, Column, String, LargeBinary, TIMESTAMP
            from sqlalchemy.exc import OperationalError
            from sqlalchemy.sql import func
        except ImportError as exc:
            raise ImportError(
                "Database-backed vault requires: pip install iki-pii-masker[db]"
            ) from exc

        self.url = url
        self.table = table
        self.master_key = master_key or b""
        self.engine = create_engine(self.url, connect_args={
                                    "timeout": 30}, **engine_kwargs)

        metadata = MetaData()
        self._table = Table(
            self.table,
            metadata,
            Column("namespace", String, primary_key=True),
            Column("original_hash", String, primary_key=True),
            Column("original_enc", String, nullable=False),
            Column("token", String, nullable=False, unique=True),
            Column("created_at", TIMESTAMP,
                   server_default=func.current_timestamp()),
        )
        try:
            metadata.create_all(self.engine)
        except OperationalError:
            # Another process/thread may have created the table concurrently.
            pass

    def _hash_original(self, original: str) -> str:
        return hashlib.sha256(original.encode("utf-8")).hexdigest()

    def _encrypt_original(self, original: str) -> str:
        if not self.master_key:
            raise ValueError(
                "Vault master key is required to encrypt originals.")
        encrypted = encrypt_value(
            original,
            self.master_key,
            cipher="aesgcm",
        )
        return encrypted

    def get_or_create(
        self,
        original: str,
        namespace: str,
        token_factory: Any | None = None,
    ) -> str:
        try:
            from sqlalchemy import select
            from sqlalchemy.exc import IntegrityError
        except ImportError as exc:
            raise ImportError(
                "Database-backed vault requires: pip install iki-pii-masker[db]"
            ) from exc

        original_hash = self._hash_original(original)
        insert_stmt = self._table.insert()
        token = token_factory(
            original) if token_factory else self._default_token(original)
        original_enc = self._encrypt_original(original)

        with self.engine.begin() as conn:
            row = conn.execute(
                select(self._table.c.token)
                .where(self._table.c.namespace == namespace)
                .where(self._table.c.original_hash == original_hash)
            ).fetchone()
            if row:
                return row[0]

            try:
                conn.execute(
                    insert_stmt,
                    {
                        "namespace": namespace,
                        "original_hash": original_hash,
                        "original_enc": original_enc,
                        "token": token,
                    },
                )
            except IntegrityError:
                row = conn.execute(
                    select(self._table.c.token)
                    .where(self._table.c.namespace == namespace)
                    .where(self._table.c.original_hash == original_hash)
                ).fetchone()
                if row:
                    return row[0]
                raise

        return token

    def reverse(self, token: str, namespace: str) -> str | None:
        try:
            from sqlalchemy import select
        except ImportError as exc:
            raise ImportError(
                "Database-backed vault requires: pip install iki-pii-masker[db]"
            ) from exc

        with self.engine.connect() as conn:
            row = conn.execute(
                select(self._table.c.original_enc)
                .where(self._table.c.namespace == namespace)
                .where(self._table.c.token == token)
            ).fetchone()
            if not row:
                return None
            return decrypt_value(row[0], self.master_key)

    def close(self) -> None:
        if self.engine is not None:
            self.engine.dispose()

    def _default_token(self, original: str) -> str:
        return hashlib.sha256(original.encode("utf-8")).hexdigest()[:16]
