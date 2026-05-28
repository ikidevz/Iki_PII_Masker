"""
test_adapters.py — Integration tests for Polars, Pandas, and DuckDB adapters.
"""

from Iki_PII_Masker import (
    AdapterFactory, Engine, FileFormat,
    MaskingContext, PIIRegistry, Strategy, StrategyFactory,
    derive_key,
)

import pytest


ENGINES = [Engine.polars, Engine.pandas, Engine.duckdb]
ENGINES_IDS = ["polars", "pandas", "duckdb"]


def _redact():
    return StrategyFactory.create(Strategy.redact)


def _null():
    return StrategyFactory.create(Strategy.null)


def _partial():
    return StrategyFactory.create(Strategy.partial)


# ── columns & row_count ───────────────────────────────────────────────────────

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_columns(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    assert "email" in a.columns
    assert "full_name" in a.columns
    assert "id" in a.columns


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_row_count(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    assert a.row_count() == 5


# ── apply_mask ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_mask_redact(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    assert all(v == "[EMAIL]" for v in a.sample_values("email", 5))


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_mask_null(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    a.apply_mask("email", _null(), PIIRegistry.get("email"), MaskingContext())
    assert a.sample_values("email", 5) == []   # drop_nulls → empty


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_mask_partial(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    ctx = MaskingContext(partial_keep=4, partial_side="right")
    a.apply_mask("credit_card", _partial(),
                 PIIRegistry.get("credit_card"), ctx)
    assert all("*" in str(v) for v in a.sample_values("credit_card", 5))


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_non_pii_columns_untouched(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    original_ids = a.sample_values("id", 5)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    assert a.sample_values("id", 5) == original_ids


# ── apply_unmask (reversible round-trip) ─────────────────────────────────────

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_apply_unmask_round_trip(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    key_bytes = derive_key("testsecret")
    ctx = MaskingContext(reversible=True, key_bytes=key_bytes)

    originals = a.sample_values("email", 5)
    a.apply_mask("email", _redact(), PIIRegistry.get("email"), ctx)
    assert all(str(v).startswith("ENC:") for v in a.sample_values("email", 5))

    a.apply_unmask("email", key_bytes)
    assert a.sample_values("email", 5) == originals


# ── sample_values ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_sample_values_count(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    assert len(a.sample_values("email", 3)) == 3


@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_sample_values_excludes_nulls(engine, csv_file):
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    a.apply_mask("email", _null(), PIIRegistry.get("email"), MaskingContext())
    assert all(v is not None for v in a.sample_values("email", 5))


# ── save / load round-trip ────────────────────────────────────────────────────

@pytest.mark.parametrize("engine", ENGINES, ids=ENGINES_IDS)
def test_save_csv_round_trip(engine, csv_file, tmp_path):
    out = tmp_path / "out.csv"
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    a.apply_mask("email", _redact(), PIIRegistry.get(
        "email"), MaskingContext())
    a.save(out, FileFormat.csv)
    assert out.exists()
    content = out.read_text()
    assert "[EMAIL]" in content
    assert "alice@example.com" not in content


@pytest.mark.parametrize("engine", [Engine.polars, Engine.pandas], ids=["polars", "pandas"])
def test_save_parquet_round_trip(engine, csv_file, tmp_path):
    out = tmp_path / "out.parquet"
    a = AdapterFactory.create(engine)
    a.load(csv_file, FileFormat.csv)
    a.save(out, FileFormat.parquet)
    a2 = AdapterFactory.create(engine)
    a2.load(out, FileFormat.parquet)
    assert "email" in a2.columns


# ── DuckDB Excel guard ────────────────────────────────────────────────────────

def test_duckdb_rejects_excel_load(tmp_path):
    fake_xlsx = tmp_path / "data.xlsx"
    fake_xlsx.write_bytes(b"fake")
    with pytest.raises(SystemExit):
        AdapterFactory.create(Engine.duckdb).load(fake_xlsx, FileFormat.excel)


def test_duckdb_rejects_excel_save(csv_file, tmp_path):
    a = AdapterFactory.create(Engine.duckdb)
    a.load(csv_file, FileFormat.csv)
    with pytest.raises(SystemExit):
        a.save(tmp_path / "out.xlsx", FileFormat.excel)
