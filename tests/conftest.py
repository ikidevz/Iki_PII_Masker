"""
conftest.py — Shared pytest fixtures for pii_masker tests.
"""

import pytest
from pathlib import Path

from Iki_PII_Masker.facade import (
    create_adapter, load_data,
    make_context, make_reversible_context,
    Engine, FileFormat, MaskingContext,
    derive_encryption_key,
)

# ── Sample data ───────────────────────────────────────────────────────────────

CSV_CONTENT = (
    "id,full_name,email,phone,credit_card,revenue,user_id,ssn,dob,age,password\n"
    "1,Alice Smith,alice@example.com,+1-555-0100,4111111111111234,1200.5,usr_abc123,123-45-6789,1990-07-15,34,secret1\n"
    "2,Bob Jones,bob@corp.org,+1-555-0101,5500005555555559,980.0,usr_def456,234-56-7890,1985-03-22,39,secret2\n"
    "3,Carol White,carol@test.net,+1-555-0102,340000000000009,750.0,usr_ghi789,345-67-8901,1978-11-30,45,secret3\n"
    "4,Dave Brown,dave@email.com,+1-555-0103,30000000000004,2100.0,usr_jkl012,456-78-9012,1995-01-05,29,secret4\n"
    "5,Eve Davis,eve@sample.io,+1-555-0104,6011111111111117,550.0,usr_mno345,567-89-0123,2000-08-19,24,secret5\n"
)

PII_COLUMNS = ["full_name", "email", "phone",
               "credit_card", "user_id", "ssn", "dob", "password"]
NON_PII_COLUMNS = ["id", "revenue", "age"]

XML_CONTENT = """<?xml version="1.0"?>
<users>
  <user><email>alice@example.com</email><phone>+1-555-0100</phone><name>Alice Smith</name></user>
  <user><email>bob@corp.org</email><phone>+1-555-0101</phone><name>Bob Jones</name></user>
  <user><email>carol@test.net</email><phone>+1-555-0102</phone><name>Carol White</name></user>
</users>"""

JSON_CONTENT = {
    "users": [
        {"id": 1, "contact": {"email": "alice@example.com", "phone": "+1-555-0100"}},
        {"id": 2, "contact": {"email": "bob@corp.org",      "phone": "+1-555-0101"}},
        {"id": 3, "contact": {"email": "carol@test.net",    "phone": "+1-555-0102"}},
    ]
}

# ── File fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def csv_file(tmp_path: Path) -> Path:
    p = tmp_path / "data.csv"
    p.write_text(CSV_CONTENT)
    return p


@pytest.fixture
def csv_bytes() -> bytes:
    return CSV_CONTENT.encode()


@pytest.fixture
def xml_file(tmp_path: Path) -> Path:
    p = tmp_path / "users.xml"
    p.write_text(XML_CONTENT, encoding="utf-8")
    return p


@pytest.fixture
def json_file(tmp_path: Path) -> Path:
    import json
    p = tmp_path / "users.json"
    p.write_text(json.dumps(JSON_CONTENT, indent=2), encoding="utf-8")
    return p


# ── Context fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def default_ctx() -> MaskingContext:
    return make_context()


@pytest.fixture
def reversible_ctx() -> MaskingContext:
    return make_reversible_context("testsecret")


@pytest.fixture
def reversible_key() -> bytes:
    return derive_encryption_key("testsecret")


# ── Adapter fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def polars_adapter(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    return a


@pytest.fixture
def pandas_adapter(csv_file):
    a = create_adapter(Engine.pandas)
    load_data(a, csv_file, FileFormat.csv)
    return a


@pytest.fixture
def duckdb_adapter(csv_file):
    a = create_adapter(Engine.duckdb)
    load_data(a, csv_file, FileFormat.csv)
    return a
