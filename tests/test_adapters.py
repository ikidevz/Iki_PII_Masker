"""
test_adapters.py — Integration tests for all adapters:
    Polars, Pandas, DuckDB, SQLAlchemy, XML, JSONPath.
"""

import io
import json
import pytest

from Iki_PII_Masker.facade import (
    create_adapter, create_sql_adapter, create_xml_adapter, create_jsonpath_adapter,
    load_data, save_data, derive_encryption_key,
    Engine, FileFormat, PIIRegistry, Strategy,
    MaskingContext,
)
from Iki_PII_Masker.strategies.factory import StrategyFactory
from Iki_PII_Masker.adapters.json_adapter import JSONPathAdapter


ENGINES = [Engine.polars, Engine.pandas, Engine.duckdb]
ENGINES_IDS = ["polars", "pandas", "duckdb"]


def _redact(): return StrategyFactory.create(Strategy.redact)
def _null(): return StrategyFactory.create(Strategy.null)
def _partial(): return StrategyFactory.create(Strategy.partial)
def _fake(): return StrategyFactory.create(Strategy.fake)


# ══════════════════════════════════════════════════════════════════════════════
# columns & row_count — Polars / Pandas / DuckDB
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_columns(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    assert "email" in a.columns
    assert "full_name" in a.columns
    assert "id" in a.columns


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_row_count(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    assert a.row_count() == 5


# ══════════════════════════════════════════════════════════════════════════════
# apply_mask — Polars / Pandas / DuckDB
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_mask_redact(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    assert all(v == "[EMAIL]" for v in a.sample_values("email", 5))


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_mask_null(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    a.apply_mask("email", _null(), PIIRegistry.get("email"), MaskingContext())
    assert a.sample_values("email", 5) == []


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_mask_partial(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    ctx = MaskingContext(partial_keep=4, partial_side="right")
    a.apply_mask("credit_card", _partial(),
                 PIIRegistry.get("credit_card"), ctx)
    assert all("*" in str(v) for v in a.sample_values("credit_card", 5))


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_non_pii_columns_untouched(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    original = a.sample_values("id", 5)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    assert a.sample_values("id", 5) == original


# ══════════════════════════════════════════════════════════════════════════════
# apply_unmask — reversible round-trip
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_unmask_round_trip(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    key = derive_encryption_key("testsecret")
    ctx = MaskingContext(reversible=True, key_bytes=key)
    originals = a.sample_values("email", 5)

    a.apply_mask("email", _redact(), PIIRegistry.get("email"), ctx)
    assert all(str(v).startswith("ENC:") for v in a.sample_values("email", 5))

    a.apply_unmask("email", key)
    assert a.sample_values("email", 5) == originals


# ══════════════════════════════════════════════════════════════════════════════
# sample_values
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_sample_values_count(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    assert len(a.sample_values("email", 3)) == 3


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_sample_values_excludes_nulls(engine, csv_file):
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    a.apply_mask("email", _null(), PIIRegistry.get("email"), MaskingContext())
    assert all(v is not None for v in a.sample_values("email", 5))


# ══════════════════════════════════════════════════════════════════════════════
# save / load round-trip — CSV and Parquet
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_save_csv_round_trip(engine, csv_file, tmp_path):
    out = tmp_path / "out.csv"
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    save_data(a, out, FileFormat.csv)

    assert out.exists()
    content = out.read_text()
    assert "[EMAIL]" in content
    assert "alice@example.com" not in content


@pytest.mark.parametrize("engine", [Engine.polars, Engine.pandas], ids=["polars", "pandas"])
def test_save_parquet_round_trip(engine, csv_file, tmp_path):
    out = tmp_path / "out.parquet"
    a = create_adapter(engine)
    load_data(a, csv_file, FileFormat.csv)
    save_data(a, out, FileFormat.parquet)

    a2 = create_adapter(engine)
    load_data(a2, out, FileFormat.parquet)
    assert "email" in a2.columns
    assert a2.row_count() == 5


# ══════════════════════════════════════════════════════════════════════════════
# BytesIO pipe — Polars
# ══════════════════════════════════════════════════════════════════════════════

def test_bytesio_load_save_round_trip(csv_file):
    buf_in = io.BytesIO(csv_file.read_bytes())
    a = create_adapter(Engine.polars)
    load_data(a, buf_in, FileFormat.csv)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())

    buf_out = io.BytesIO()
    save_data(a, buf_out, FileFormat.csv)
    content = buf_out.getvalue().decode()
    assert "[EMAIL]" in content
    assert "alice@example.com" not in content


# ══════════════════════════════════════════════════════════════════════════════
# DuckDB guards
# ══════════════════════════════════════════════════════════════════════════════

def test_duckdb_rejects_excel_load(tmp_path):
    fake_xlsx = tmp_path / "data.xlsx"
    fake_xlsx.write_bytes(b"fake")
    with pytest.raises(SystemExit):
        create_adapter(Engine.duckdb).load(fake_xlsx, FileFormat.excel)


def test_duckdb_rejects_excel_save(csv_file, tmp_path):
    a = create_adapter(Engine.duckdb)
    load_data(a, csv_file, FileFormat.csv)
    with pytest.raises(SystemExit):
        save_data(a, tmp_path / "out.xlsx", FileFormat.excel)


# ══════════════════════════════════════════════════════════════════════════════
# SQLAlchemyAdapter
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def sqlite_db(tmp_path, csv_file):
    """Create a populated SQLite db and return its path."""
    pytest.importorskip("sqlalchemy")
    import sqlite3
    import csv as csv_mod

    db = tmp_path / "test.db"
    con = sqlite3.connect(str(db))
    con.execute(
        "CREATE TABLE users "
        "(id INTEGER PRIMARY KEY, email TEXT, phone TEXT, full_name TEXT)"
    )
    with open(csv_file) as f:
        for i, row in enumerate(csv_mod.DictReader(f)):
            con.execute(
                "INSERT INTO users VALUES (?,?,?,?)",
                (i + 1, row["email"], row["phone"], row["full_name"]),
            )
    con.commit()
    con.close()
    return db


def _sql_load(url, table):
    """Helper: create + load a SQLAlchemy adapter (source=None is valid for SQL)."""
    a = create_sql_adapter(url, table)
    a.load()   # SQLAlchemyAdapter.load ignores source
    return a


def test_sql_adapter_load_row_count(sqlite_db):
    a = _sql_load(f"sqlite:///{sqlite_db}", "users")
    assert a.row_count() == 5


def test_sql_adapter_columns(sqlite_db):
    a = _sql_load(f"sqlite:///{sqlite_db}", "users")
    assert "email" in a.columns
    assert "phone" in a.columns


def test_sql_adapter_mask_and_save(sqlite_db):
    import sqlite3

    a = _sql_load(f"sqlite:///{sqlite_db}", "users")
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    a.save()   # SQLAlchemyAdapter.save ignores dest

    con = sqlite3.connect(str(sqlite_db))
    rows = con.execute("SELECT email FROM users").fetchall()
    con.close()
    assert all(r[0] == "[EMAIL]" for r in rows)


def test_sql_adapter_sample_values(sqlite_db):
    a = _sql_load(f"sqlite:///{sqlite_db}", "users")
    samples = a.sample_values("email", 3)
    assert len(samples) == 3
    assert all("@" in s for s in samples)


def test_sql_adapter_unmask_round_trip(sqlite_db):
    key = derive_encryption_key("secret")
    ctx = MaskingContext(reversible=True, key_bytes=key)

    a = _sql_load(f"sqlite:///{sqlite_db}", "users")
    originals = a.sample_values("email", 5)
    a.apply_mask("email", _redact(), PIIRegistry.get("email"), ctx)
    a.save()

    a2 = _sql_load(f"sqlite:///{sqlite_db}", "users")
    assert all(str(v).startswith("ENC:") for v in a2.sample_values("email", 5))
    a2.apply_unmask("email", key)
    assert a2.sample_values("email", 5) == originals


def test_sql_adapter_missing_sqlalchemy(monkeypatch):
    """Ensure a helpful ImportError is raised when sqlalchemy is absent."""
    import builtins
    import importlib
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "sqlalchemy":
            raise ImportError("mocked missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    from Iki_PII_Masker.adapters.sqlalchemy_adapter import SQLAlchemyAdapter
    a = SQLAlchemyAdapter("sqlite:///x.db", "t")
    a._engine = None          # force lazy re-init
    with pytest.raises(ImportError, match="sqlalchemy"):
        a._get_engine()


# ══════════════════════════════════════════════════════════════════════════════
# XMLAdapter
# ══════════════════════════════════════════════════════════════════════════════

def test_xml_adapter_load_row_count(xml_file):
    a = create_xml_adapter("//user", ["email", "phone", "name"])
    load_data(a, xml_file)
    assert a.row_count() == 3


def test_xml_adapter_columns(xml_file):
    a = create_xml_adapter("//user", ["email", "phone", "name"])
    load_data(a, xml_file)
    assert a.columns == ["email", "phone", "name"]


def test_xml_adapter_sample_values(xml_file):
    a = create_xml_adapter("//user", ["email"])
    load_data(a, xml_file)
    samples = a.sample_values("email", 3)
    assert len(samples) == 3
    assert all("@" in s for s in samples)


def test_xml_adapter_mask_redact(xml_file):
    a = create_xml_adapter("//user", ["email", "phone"])
    load_data(a, xml_file)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    assert all(v == "[EMAIL]" for v in a.sample_values("email", 3))


def test_xml_adapter_mask_fake(xml_file):
    a = create_xml_adapter("//user", ["email"])
    load_data(a, xml_file)
    originals = a.sample_values("email", 3)
    a.apply_mask("email", _fake(), PIIRegistry.get(
        "email"), MaskingContext(seed=1))
    after = a.sample_values("email", 3)
    assert after != originals


def test_xml_adapter_save_round_trip(xml_file, tmp_path):
    out = tmp_path / "masked.xml"
    a = create_xml_adapter("//user", ["email"])
    load_data(a, xml_file)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    save_data(a, out)

    assert out.exists()
    content = out.read_bytes().decode("utf-8", errors="replace")
    assert "[EMAIL]" in content
    assert "alice@example.com" not in content


def test_xml_adapter_unmask_round_trip(xml_file):
    key = derive_encryption_key("xmlsecret")
    ctx = MaskingContext(reversible=True, key_bytes=key)

    a = create_xml_adapter("//user", ["email"])
    load_data(a, xml_file)
    originals = a.sample_values("email", 3)

    a.apply_mask("email", _redact(), PIIRegistry.get("email"), ctx)
    assert all(str(v).startswith("ENC:") for v in a.sample_values("email", 3))

    a.apply_unmask("email", key)
    assert a.sample_values("email", 3) == originals


def test_xml_adapter_bytesio(xml_file):
    buf = io.BytesIO(xml_file.read_bytes())
    a = create_xml_adapter("//user", ["email"])
    a.load(buf)   # BytesIO — call adapter directly, not load_data()
    assert a.row_count() == 3


# ══════════════════════════════════════════════════════════════════════════════
# JSONPathAdapter
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(autouse=False)
def _jsonpath_ng(request):
    """Skip tests in this class if jsonpath-ng is not installed."""
    pytest.importorskip("jsonpath_ng")


def test_jsonpath_adapter_load_row_count(json_file):
    pytest.importorskip("jsonpath_ng")
    a = create_jsonpath_adapter({
        "email": "$.users[*].contact.email",
        "phone": "$.users[*].contact.phone",
    })
    load_data(a, json_file)
    assert a.row_count() == 3


def test_jsonpath_adapter_columns(json_file):
    pytest.importorskip("jsonpath_ng")
    a = create_jsonpath_adapter({
        "email": "$.users[*].contact.email",
        "phone": "$.users[*].contact.phone",
    })
    load_data(a, json_file)
    assert a.columns == ["email", "phone"]


def test_jsonpath_adapter_sample_values(json_file):
    pytest.importorskip("jsonpath_ng")
    a = create_jsonpath_adapter({"email": "$.users[*].contact.email"})
    load_data(a, json_file)
    samples = a.sample_values("email", 3)
    assert len(samples) == 3
    assert all("@" in s for s in samples)


def test_jsonpath_adapter_mask_redact(json_file):
    pytest.importorskip("jsonpath_ng")
    a = create_jsonpath_adapter({"email": "$.users[*].contact.email"})
    load_data(a, json_file)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    assert all(v == "[EMAIL]" for v in a.sample_values("email", 3))


def test_jsonpath_adapter_save_round_trip(json_file, tmp_path):
    pytest.importorskip("jsonpath_ng")
    out = tmp_path / "masked.json"
    a = create_jsonpath_adapter({"email": "$.users[*].contact.email"})
    load_data(a, json_file)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    save_data(a, out)

    data = json.loads(out.read_text(encoding="utf-8"))
    emails = [u["contact"]["email"] for u in data["users"]]
    assert all(e == "[EMAIL]" for e in emails)
    assert out.exists()


def test_jsonpath_adapter_nested_structure_preserved(json_file, tmp_path):
    pytest.importorskip("jsonpath_ng")
    out = tmp_path / "out.json"
    a = create_jsonpath_adapter({"email": "$.users[*].contact.email"})
    load_data(a, json_file)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    save_data(a, out)

    data = json.loads(out.read_text(encoding="utf-8"))
    # id and phone must remain untouched
    assert all("id" in u for u in data["users"])
    assert all(u["contact"].get("phone") for u in data["users"])


def test_jsonpath_adapter_unmask_round_trip(json_file):
    pytest.importorskip("jsonpath_ng")
    key = derive_encryption_key("jsonsecret")
    ctx = MaskingContext(reversible=True, key_bytes=key)

    a = create_jsonpath_adapter({"email": "$.users[*].contact.email"})
    load_data(a, json_file)
    originals = a.sample_values("email", 3)

    a.apply_mask("email", _redact(), PIIRegistry.get("email"), ctx)
    assert all(str(v).startswith("ENC:") for v in a.sample_values("email", 3))

    a.apply_unmask("email", key)
    assert a.sample_values("email", 3) == originals


def test_jsonpath_adapter_bytesio(json_file):
    pytest.importorskip("jsonpath_ng")
    buf = io.BytesIO(json_file.read_bytes())
    a = create_jsonpath_adapter({"email": "$.users[*].contact.email"})
    a.load(buf)   # BytesIO — call adapter directly, not load_data()
    assert a.row_count() == 3


def test_jsonpath_adapter_empty_paths_raises():
    pytest.importorskip("jsonpath_ng")
    with pytest.raises(ValueError, match="paths"):
        create_jsonpath_adapter({})


def test_jsonpath_adapter_missing_jsonpath_ng(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "jsonpath_ng" in name:
            raise ImportError("mocked missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    a = JSONPathAdapter({"email": "$.users[*].email"})
    a._document = {"users": [{"email": "test@test.com"}]}
    with pytest.raises(ImportError, match="jsonpath-ng"):
        a.apply_mask("email", _redact(), PIIRegistry.get(
            "email"), MaskingContext())
