"""
test_service.py — Unit tests for MaskingService.
"""

from Iki_PII_Masker import (
    AdapterFactory, Engine, FileFormat,
    MaskingContext, MaskingService, Strategy,
)

import pytest


@pytest.fixture
def svc(csv_file):
    adapter = AdapterFactory.create(Engine.polars)
    adapter.load(csv_file, FileFormat.csv)
    return MaskingService(adapter, Strategy.redact, MaskingContext())


# ── resolve_columns ───────────────────────────────────────────────────────────

def test_resolve_explicit(svc):
    col_map = svc.resolve_columns("email:full_name", auto=False)
    assert "email" in col_map
    assert "full_name" in col_map
    assert "id" not in col_map


def test_resolve_auto(svc):
    col_map = svc.resolve_columns(None, auto=True)
    assert "email" in col_map
    assert "phone" in col_map
    assert "id" not in col_map
    assert "revenue" not in col_map


def test_resolve_auto_plus_explicit(svc):
    col_map = svc.resolve_columns("revenue", auto=True)
    assert "email" in col_map     # auto
    assert "revenue" in col_map     # explicit


def test_resolve_unknown_column_exits(svc):
    with pytest.raises(SystemExit):
        svc.resolve_columns("does_not_exist", auto=False)


def test_resolve_pii_type_attached(svc):
    col_map = svc.resolve_columns("email", auto=False)
    assert col_map["email"] is not None
    assert col_map["email"].name == "email"


def test_resolve_non_pii_explicit_gets_none_type(svc):
    col_map = svc.resolve_columns("revenue", auto=False)
    assert "revenue" in col_map
    assert col_map["revenue"] is None


# ── run ───────────────────────────────────────────────────────────────────────

def test_run_returns_elapsed(svc):
    col_map = svc.resolve_columns("email", auto=False)
    elapsed = svc.run(col_map, dry_run=False, progress=False)
    assert elapsed >= 0.0


def test_run_dry_run_does_not_mutate(csv_file):
    adapter = AdapterFactory.create(Engine.polars)
    adapter.load(csv_file, FileFormat.csv)
    svc = MaskingService(adapter, Strategy.redact, MaskingContext())
    col_map = svc.resolve_columns("email", auto=False)
    before = adapter.sample_values("email", 5)
    svc.run(col_map, dry_run=True, progress=False)
    assert adapter.sample_values("email", 5) == before


def test_run_applies_masking(csv_file):
    adapter = AdapterFactory.create(Engine.polars)
    adapter.load(csv_file, FileFormat.csv)
    svc = MaskingService(adapter, Strategy.redact, MaskingContext())
    svc.run(svc.resolve_columns("email", auto=False),
            dry_run=False, progress=False)
    assert all(v == "[EMAIL]" for v in adapter.sample_values("email", 5))


def test_run_multiple_columns(csv_file):
    adapter = AdapterFactory.create(Engine.polars)
    adapter.load(csv_file, FileFormat.csv)
    svc = MaskingService(adapter, Strategy.redact, MaskingContext())
    svc.run(svc.resolve_columns("email:full_name:phone", auto=False),
            dry_run=False, progress=False)
    assert all(v == "[EMAIL]" for v in adapter.sample_values("email",     5))
    assert all(v == "[NAME]" for v in adapter.sample_values("full_name", 5))
    assert all(v == "[PHONE]" for v in adapter.sample_values("phone",     5))
    assert adapter.sample_values("id", 1)[0] == 1   # untouched
