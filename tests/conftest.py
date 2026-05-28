"""
conftest.py — Shared pytest fixtures for pii_masker tests.
"""

from Iki_PII_Masker import (
    AdapterFactory,
    Engine,
    FileFormat,
    MaskingContext,
    derive_key
)

from pathlib import Path

import pytest


# ── Sample data ───────────────────────────────────────────────────────────────

CSV_CONTENT = (
    "id,full_name,email,phone,credit_card,revenue,user_id\n"
    "1,Alice Smith,alice@example.com,+1-555-0100,4111111111111234,1200.5,usr_abc123\n"
    "2,Bob Jones,bob@corp.org,+1-555-0101,5500005555555559,980.0,usr_def456\n"
    "3,Carol White,carol@test.net,+1-555-0102,340000000000009,750.0,usr_ghi789\n"
    "4,Dave Brown,dave@email.com,+1-555-0103,30000000000004,2100.0,usr_jkl012\n"
    "5,Eve Davis,eve@sample.io,+1-555-0104,6011111111111117,550.0,usr_mno345\n"
)

PII_COLUMNS = ["full_name", "email", "phone", "credit_card", "user_id"]
NON_PII_COLUMNS = ["id", "revenue"]


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def csv_file(tmp_path: Path) -> Path:
    """Write sample CSV to a temp file and return its path."""
    p = tmp_path / "data.csv"
    p.write_text(CSV_CONTENT)
    return p


@pytest.fixture
def csv_bytes() -> bytes:
    return CSV_CONTENT.encode()


@pytest.fixture
def default_ctx() -> MaskingContext:
    return MaskingContext()


@pytest.fixture
def reversible_ctx() -> MaskingContext:
    return MaskingContext(reversible=True, key_bytes=derive_key("testsecret"))


@pytest.fixture
def polars_adapter(csv_file: Path):
    adapter = AdapterFactory.create(Engine.polars)
    adapter.load(csv_file, FileFormat.csv)
    return adapter


@pytest.fixture
def pandas_adapter(csv_file: Path):
    adapter = AdapterFactory.create(Engine.pandas)
    adapter.load(csv_file, FileFormat.csv)
    return adapter


@pytest.fixture
def duckdb_adapter(csv_file: Path):
    adapter = AdapterFactory.create(Engine.duckdb)
    adapter.load(csv_file, FileFormat.csv)
    return adapter
