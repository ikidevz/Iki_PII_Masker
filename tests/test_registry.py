"""
test_registry.py — Unit tests for PIIRegistry and FormatRegistry.
"""

from Iki_PII_Masker import FileFormat, FormatRegistry, PIIRegistry, PIIType

from pathlib import Path
import pytest


# ── PIIRegistry.detect ────────────────────────────────────────────────────────

def test_detect_email_columns():
    result = PIIRegistry.detect(["email", "email_address", "e_mail", "mail"])
    assert all(col in result for col in [
               "email", "email_address", "e_mail", "mail"])
    assert all(r.name == "email" for r in result.values())


def test_detect_phone_columns():
    result = PIIRegistry.detect(["phone", "mobile", "cell", "telephone"])
    assert all(col in result for col in [
               "phone", "mobile", "cell", "telephone"])


def test_detect_name_columns():
    result = PIIRegistry.detect(
        ["full_name", "first_name", "last_name", "username"])
    assert all(col in result for col in [
               "full_name", "first_name", "last_name", "username"])


def test_detect_mixed_columns():
    detected = PIIRegistry.detect(
        ["id", "email", "revenue", "phone", "created_at"])
    assert "email" in detected
    assert "phone" in detected
    assert "id" not in detected
    assert "revenue" not in detected
    assert "created_at" not in detected


def test_detect_no_pii():
    assert PIIRegistry.detect(
        ["product_id", "quantity", "price", "category"]) == {}


def test_detect_all_ten_types():
    cols = ["email", "phone", "full_name", "address", "ssn",
            "dob", "ip_address", "credit_card", "user_id", "password"]
    assert len(PIIRegistry.detect(cols)) == 10


def test_detect_case_insensitive():
    assert len(PIIRegistry.detect(["EMAIL", "Phone", "FULL_NAME"])) == 3


# ── PIIRegistry.guess ─────────────────────────────────────────────────────────

def test_guess_known_column():
    pii = PIIRegistry.guess("email")
    assert pii is not None and pii.name == "email"


def test_guess_unknown_column():
    assert PIIRegistry.guess("revenue") is None


def test_guess_partial_match():
    # email_address matches the \bemail_address\b pattern in the registry
    pii = PIIRegistry.guess("email_address")
    assert pii is not None and pii.name == "email"


# ── PIIRegistry.register ──────────────────────────────────────────────────────

def test_register_custom_type():
    custom = PIIType(
        name="passport",
        patterns=[r"\bpassport\b", r"\bpassport_number\b"],
        redact_label="[PASSPORT]",
        faker_method="bothify",
    )
    PIIRegistry.register(custom)
    detected = PIIRegistry.detect(["passport_number", "issued_country"])
    assert "passport_number" in detected
    assert detected["passport_number"].name == "passport"
    # cleanup
    PIIRegistry._types = [
        t for t in PIIRegistry._types if t.name != "passport"]
    PIIRegistry._by_name.pop("passport", None)


# ── FormatRegistry.detect ─────────────────────────────────────────────────────

@pytest.mark.parametrize("filename,expected", [
    ("data.csv",     FileFormat.csv),
    ("data.CSV",     FileFormat.csv),
    ("data.parquet", FileFormat.parquet),
    ("data.json",    FileFormat.json),
    ("data.ndjson",  FileFormat.ndjson),
    ("data.jsonl",   FileFormat.ndjson),
    ("data.xlsx",    FileFormat.excel),
    ("data.xls",     FileFormat.excel),
])
def test_format_detection(filename, expected):
    assert FormatRegistry.detect(Path(filename)) == expected


def test_format_unknown_extension_exits():
    with pytest.raises(SystemExit):
        FormatRegistry.detect(Path("data.txt"))
