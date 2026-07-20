from __future__ import annotations

from typing import Any

from .base import BaseTokenVault
from .sqlite_vault import SQLiteTokenVault


def create_vault(
    backend: str = "sqlite",
    *,
    path: str | None = None,
    url: str | None = None,
    table: str = "pii_tokens",
    master_key: bytes | None = None,
) -> BaseTokenVault:
    normalized = backend.lower()
    if normalized == "sqlite":
        return SQLiteTokenVault(path=path, table=table, master_key=master_key)

    if normalized == "sqlalchemy":
        try:
            from .sqlalchemy_vault import SQLAlchemyTokenVault
        except ImportError as exc:
            raise ImportError(
                "SQLAlchemy-backed vault requires: pip install iki-pii-masker[db]"
            ) from exc

        vault_url = url or path
        if not vault_url:
            raise ValueError(
                "--vault-url is required for the sqlalchemy vault backend."
            )
        return SQLAlchemyTokenVault(
            url=vault_url,
            table=table,
            master_key=master_key,
        )

    raise ValueError(
        f"Unsupported vault backend '{backend}'. Supported: sqlite, sqlalchemy."
    )
