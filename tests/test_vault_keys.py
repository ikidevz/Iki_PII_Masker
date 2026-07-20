"""
test_vault_keys.py — unit tests for token vault and key provider features.
"""

import csv
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from Iki_PII_Masker.facade import (
    create_adapter,
    load_data,
    mask_dataframe,
    unmask_dataframe,
    make_context,
    make_reversible_context,
    Strategy,
    Engine,
    FileFormat,
    derive_encryption_key,
)
from Iki_PII_Masker.config.vault.factory import create_vault
from Iki_PII_Masker.config.keys.local_provider import LocalKeyProvider


def test_local_key_provider_derives_unique_keys() -> None:
    provider = LocalKeyProvider("master-secret")
    key_a = provider.get_key("email")
    key_b = provider.get_key("phone")
    assert isinstance(key_a, bytes)
    assert isinstance(key_b, bytes)
    assert key_a == provider.get_key("email")
    assert key_a != key_b


def test_token_vault_persistence(tmp_path: Path) -> None:
    master_key = derive_encryption_key("vault-secret")
    path = tmp_path / "vault.db"
    vault_one = create_vault("sqlite", path=str(
        path), table="pii_tokens", master_key=master_key)
    token_one = vault_one.get_or_create(
        "alice@example.com",
        namespace="email",
    )
    vault_one.close()

    vault_two = create_vault("sqlite", path=str(
        path), table="pii_tokens", master_key=master_key)
    token_two = vault_two.get_or_create(
        "alice@example.com",
        namespace="email",
    )
    assert token_one == token_two
    assert vault_two.reverse(token_two, "email") == "alice@example.com"
    vault_two.close()


def test_sqlalchemy_vault_persistence(tmp_path: Path) -> None:
    pytest.importorskip("sqlalchemy")
    master_key = derive_encryption_key("vault-secret")
    vault_path = tmp_path / "vault_sqlalchemy.db"
    vault_url = f"sqlite:///{vault_path}"

    vault_one = create_vault(
        "sqlalchemy",
        url=vault_url,
        table="pii_tokens",
        master_key=master_key,
    )
    token_one = vault_one.get_or_create(
        "alice@example.com",
        namespace="email",
    )
    vault_one.close()

    vault_two = create_vault(
        "sqlalchemy",
        url=vault_url,
        table="pii_tokens",
        master_key=master_key,
    )
    token_two = vault_two.get_or_create(
        "alice@example.com",
        namespace="email",
    )
    assert token_one == token_two
    assert vault_two.reverse(token_two, "email") == "alice@example.com"
    vault_two.close()


def test_sqlite_vault_encrypts_originals_at_rest(tmp_path: Path) -> None:
    master_key = derive_encryption_key("vault-secret")
    path = tmp_path / "vault.db"
    vault = create_vault("sqlite", path=str(
        path), table="pii_tokens", master_key=master_key)
    token = vault.get_or_create("alice@example.com", namespace="email")
    vault.close()

    conn = sqlite3.connect(str(path))
    row = conn.execute(
        "SELECT original_enc FROM pii_tokens WHERE namespace = ? AND token = ?",
        ("email", token),
    ).fetchone()
    conn.close()

    assert row is not None
    original_enc = row[0].decode("utf-8")
    assert "alice@example.com" not in original_enc
    assert original_enc.startswith("ENC:")


def test_sqlite_vault_concurrent_get_or_create(tmp_path: Path) -> None:
    master_key = derive_encryption_key("vault-secret")
    path = tmp_path / "vault.db"
    original = "alice@example.com"
    namespace = "email"

    def worker() -> str:
        vault = create_vault("sqlite", path=str(
            path), table="pii_tokens", master_key=master_key)
        try:
            return vault.get_or_create(original, namespace=namespace)
        finally:
            vault.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        tokens = [future.result() for future in [executor.submit(worker)
                                                 for _ in range(4)]]

    assert len(set(tokens)) == 1


def test_sqlalchemy_vault_encrypts_originals_at_rest(tmp_path: Path) -> None:
    pytest.importorskip("sqlalchemy")
    from sqlalchemy import create_engine, text

    master_key = derive_encryption_key("vault-secret")
    vault_path = tmp_path / "vault_sqlalchemy.db"
    vault_url = f"sqlite:///{vault_path}"

    vault = create_vault(
        "sqlalchemy",
        url=vault_url,
        table="pii_tokens",
        master_key=master_key,
    )
    token = vault.get_or_create("alice@example.com", namespace="email")
    vault.close()

    engine = create_engine(vault_url)
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT original_enc FROM pii_tokens WHERE namespace = :ns AND token = :token"),
            {"ns": "email", "token": token},
        ).fetchone()

    assert row is not None
    original_enc = row[0]
    assert "alice@example.com" not in original_enc
    assert original_enc.startswith("ENC:")


def test_sqlalchemy_vault_concurrent_get_or_create(tmp_path: Path) -> None:
    pytest.importorskip("sqlalchemy")
    master_key = derive_encryption_key("vault-secret")
    vault_path = tmp_path / "vault_sqlalchemy.db"
    vault_url = f"sqlite:///{vault_path}"
    original = "alice@example.com"
    namespace = "email"

    def worker() -> str:
        vault = create_vault(
            "sqlalchemy",
            url=vault_url,
            table="pii_tokens",
            master_key=master_key,
        )
        try:
            return vault.get_or_create(original, namespace=namespace)
        finally:
            vault.close()

    with ThreadPoolExecutor(max_workers=4) as executor:
        tokens = [future.result() for future in [executor.submit(worker)
                                                 for _ in range(4)]]

    assert len(set(tokens)) == 1


def test_token_vault_namespace_isolated(tmp_path: Path) -> None:
    master_key = derive_encryption_key("vault-secret")
    path = tmp_path / "vault.db"
    vault = create_vault("sqlite", path=str(
        path), table="pii_tokens", master_key=master_key)

    def token_factory_default(original: str) -> str:
        return f"default-{original}"

    def token_factory_prod(original: str) -> str:
        return f"prod-{original}"

    token_default = vault.get_or_create(
        "alice@example.com",
        namespace="default:email",
        token_factory=token_factory_default,
    )
    token_other = vault.get_or_create(
        "alice@example.com",
        namespace="prod:email",
        token_factory=token_factory_prod,
    )

    assert token_default == "default-alice@example.com"
    assert token_other == "prod-alice@example.com"
    assert vault.reverse(token_default, "default:email") == "alice@example.com"
    assert vault.reverse(token_other, "prod:email") == "alice@example.com"
    assert vault.reverse(token_default, "prod:email") is None
    assert vault.reverse(token_other, "default:email") is None
    vault.close()


def test_reversible_mask_unmask_with_local_key_provider(csv_file, tmp_path: Path) -> None:
    adapter = create_adapter(Engine.polars)
    load_data(adapter, csv_file, FileFormat.csv)
    original_emails = [row["email"] for row in csv.DictReader(csv_file.open())]
    original_phones = [row["phone"] for row in csv.DictReader(csv_file.open())]

    secret = "secret123"
    ctx = make_reversible_context(secret)
    ctx.key_provider = LocalKeyProvider(secret)

    mask_dataframe(adapter, "email:phone", Strategy.redact, ctx)
    assert all(str(v).startswith("ENC:")
               for v in adapter.sample_values("email", 5))
    assert all(str(v).startswith("ENC:")
               for v in adapter.sample_values("phone", 5))

    unmask_dataframe(
        adapter,
        ["email"],
        ctx.key_provider.get_key("email"),
    )
    unmask_dataframe(
        adapter,
        ["phone"],
        ctx.key_provider.get_key("phone"),
    )

    assert adapter.sample_values("email", 5) == original_emails
    assert adapter.sample_values("phone", 5) == original_phones
