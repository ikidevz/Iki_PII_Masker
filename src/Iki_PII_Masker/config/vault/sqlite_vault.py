from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Optional

from .base import BaseTokenVault
from ..crypto import decrypt_value, encrypt_value, derive_key


DEFAULT_VAULT_PATH = Path.home() / ".pii_masker" / "vault.db"
DEFAULT_TABLE = "pii_tokens"


class SQLiteTokenVault(BaseTokenVault):
    def __init__(
        self,
        path: str | Path | None = None,
        table: str = DEFAULT_TABLE,
        master_key: bytes | None = None,
    ) -> None:
        self.table = table
        self.path = Path(path) if path is not None else DEFAULT_VAULT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=30.0
        )
        self._ensure_schema()
        self.master_key = master_key or b""

    def _ensure_schema(self) -> None:
        self.conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table} (
                namespace TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                original_enc BLOB NOT NULL,
                token TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (namespace, original_hash)
            );
            """
        )
        self.conn.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS idx_token_{self.table} "
            f"ON {self.table}(namespace, token);"
        )
        self.conn.commit()

    def _hash_original(self, original: str) -> str:
        return hashlib.sha256(original.encode("utf-8")).hexdigest()

    def _encrypt_original(self, original: str) -> bytes:
        if not self.master_key:
            raise ValueError(
                "Vault master key is required to encrypt originals.")
        encrypted = encrypt_value(
            original,
            self.master_key,
            cipher="aesgcm",
        )
        return encrypted.encode("utf-8")

    def get_or_create(
        self,
        original: str,
        namespace: str,
        token_factory: TokenFactory | None = None,
    ) -> str:
        original_hash = self._hash_original(original)
        row = self.conn.execute(
            f"SELECT token FROM {self.table} WHERE namespace = ? AND original_hash = ?",
            (namespace, original_hash),
        ).fetchone()
        if row:
            return row[0]

        token = token_factory(
            original) if token_factory else self._default_token(original)
        original_enc = self._encrypt_original(original)
        self.conn.execute(
            f"INSERT INTO {self.table} (namespace, original_hash, original_enc, token) VALUES (?, ?, ?, ?)",
            (namespace, original_hash, original_enc, token),
        )
        self.conn.commit()
        return token

    def reverse(self, token: str, namespace: str) -> str | None:
        row = self.conn.execute(
            f"SELECT original_enc FROM {self.table} WHERE namespace = ? AND token = ?",
            (namespace, token),
        ).fetchone()
        if not row:
            return None
        encrypted = row[0].decode("utf-8")
        cipher_name = "aesgcm"
        prefix = "ENC:"
        if not encrypted.startswith(prefix):
            raise ValueError("Invalid encrypted token format in vault.")
        return decrypt_value(encrypted, self.master_key)

    def close(self) -> None:
        self.conn.close()

    def _default_token(self, original: str) -> str:
        return hashlib.sha256(original.encode("utf-8")).hexdigest()[:16]
