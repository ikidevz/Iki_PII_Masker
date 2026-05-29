"""
test_service.py — Unit tests for MaskingService.
"""

import pytest

from Iki_PII_Masker.facade import (
    create_adapter, load_data,
    make_context, make_reversible_context,
    mask_dataframe, derive_encryption_key,
    Engine, FileFormat, Strategy,
)
from Iki_PII_Masker.service import MaskingService


@pytest.fixture
def svc(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    return MaskingService(a, Strategy.redact, make_context())


# ══════════════════════════════════════════════════════════════════════════════
# resolve_columns
# ══════════════════════════════════════════════════════════════════════════════

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
    assert "email" in col_map   # auto
    assert "revenue" in col_map   # explicit


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


# ══════════════════════════════════════════════════════════════════════════════
# run
# ══════════════════════════════════════════════════════════════════════════════

def test_run_returns_elapsed(svc):
    col_map = svc.resolve_columns("email", auto=False)
    elapsed = svc.run(col_map, dry_run=False, progress=False)
    assert elapsed >= 0.0


def test_run_dry_run_does_not_mutate(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    svc = MaskingService(a, Strategy.redact, make_context())
    col_map = svc.resolve_columns("email", auto=False)
    before = a.sample_values("email", 5)
    svc.run(col_map, dry_run=True, progress=False)
    assert a.sample_values("email", 5) == before


def test_run_applies_masking(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    svc = MaskingService(a, Strategy.redact, make_context())
    svc.run(svc.resolve_columns("email", auto=False),
            dry_run=False, progress=False)
    assert all(v == "[EMAIL]" for v in a.sample_values("email", 5))


def test_run_multiple_columns(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    svc = MaskingService(a, Strategy.redact, make_context())
    svc.run(svc.resolve_columns("email:full_name:phone", auto=False),
            dry_run=False, progress=False)
    assert all(v == "[EMAIL]" for v in a.sample_values("email",     5))
    assert all(v == "[NAME]" for v in a.sample_values("full_name", 5))
    assert all(v == "[PHONE]" for v in a.sample_values("phone",     5))
    assert a.sample_values("id", 1)[0] == 1   # untouched


# ══════════════════════════════════════════════════════════════════════════════
# facade.mask_dataframe convenience wrapper
# ══════════════════════════════════════════════════════════════════════════════

def test_facade_mask_dataframe_returns_elapsed(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    elapsed = mask_dataframe(a, "email", Strategy.redact)
    assert elapsed >= 0.0


def test_facade_mask_dataframe_auto(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    mask_dataframe(a, None, Strategy.redact, auto=True)
    assert all(v == "[EMAIL]" for v in a.sample_values("email", 5))


def test_facade_mask_dataframe_dry_run(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    before = a.sample_values("email", 5)
    mask_dataframe(a, "email", Strategy.redact, dry_run=True)
    assert a.sample_values("email", 5) == before


# ══════════════════════════════════════════════════════════════════════════════
# new strategies via MaskingService
# ══════════════════════════════════════════════════════════════════════════════

def test_service_tokenize(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    mask_dataframe(a, "user_id", Strategy.tokenize)
    assert all(str(v).startswith("TOK-")
               for v in a.sample_values("user_id", 5))


def test_service_pseudonymize_consistent(csv_file):
    """Same email value in different rows must map to the same fake."""
    # Build a CSV where two rows share an email
    import io as _io
    content = (
        "id,email\n"
        "1,shared@example.com\n"
        "2,other@example.com\n"
        "3,shared@example.com\n"
    )
    a = create_adapter(Engine.polars)
    a.load(_io.BytesIO(content.encode()), FileFormat.csv)
    mask_dataframe(a, "email", Strategy.pseudonymize, make_context(seed=1))
    values = a.sample_values("email", 3)
    # rows 0 and 2 shared the same original → must share the same fake
    assert values[0] == values[2]
    assert values[0] != values[1]


def test_service_generalize_numeric(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    mask_dataframe(a, "age", Strategy.generalize)
    for v in a.sample_values("age", 5):
        assert "-" in str(v)


def test_service_mask_format_email(csv_file):
    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    mask_dataframe(a, "email", Strategy.mask_format)
    for v in a.sample_values("email", 5):
        assert "@" in str(v)
        assert "*" in str(v)


def test_service_reversible_full_pipeline(csv_file):
    from Iki_PII_Masker.facade import unmask_dataframe, save_data, load_data

    SECRET = "pipeline-secret"
    key = derive_encryption_key(SECRET)

    a = create_adapter(Engine.polars)
    load_data(a, csv_file, FileFormat.csv)
    originals = a.sample_values("email", 5)

    mask_dataframe(a, "email", Strategy.redact,
                   make_reversible_context(SECRET))
    assert all(str(v).startswith("ENC:") for v in a.sample_values("email", 5))

    unmask_dataframe(a, ["email"], key)
    assert a.sample_values("email", 5) == originals
