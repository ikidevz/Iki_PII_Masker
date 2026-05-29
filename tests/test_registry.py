"""
test_registry.py — Unit tests for PIIRegistry, FormatRegistry, and ValuePatternDetector.
"""

import pytest
from pathlib import Path

from Iki_PII_Masker.facade import PIIRegistry, PIIType, FileFormat
from Iki_PII_Masker.strategies.factory import FormatRegistry
from Iki_PII_Masker.config.value_detector import ValuePatternDetector


# ══════════════════════════════════════════════════════════════════════════════
# PIIRegistry.detect  (column-name based)
# ══════════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════════
# PIIRegistry.guess
# ══════════════════════════════════════════════════════════════════════════════

def test_guess_known_column():
    pii = PIIRegistry.guess("email")
    assert pii is not None and pii.name == "email"


def test_guess_unknown_column():
    assert PIIRegistry.guess("revenue") is None


def test_guess_partial_match():
    pii = PIIRegistry.guess("email_address")
    assert pii is not None and pii.name == "email"


# ══════════════════════════════════════════════════════════════════════════════
# PIIRegistry.register  (custom types)
# ══════════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════════
# FormatRegistry.detect
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("filename,expected", [
    ("data.csv",     FileFormat.csv),
    ("data.CSV",     FileFormat.csv),
    ("data.parquet", FileFormat.parquet),
    ("data.json",    FileFormat.json),
    ("data.ndjson",  FileFormat.ndjson),
    ("data.jsonl",   FileFormat.ndjson),
    ("data.xlsx",    FileFormat.excel),
    ("data.xls",     FileFormat.excel),
    ("data.xml",     FileFormat.xml),
])
def test_format_detection(filename, expected):
    assert FormatRegistry.detect(Path(filename)) == expected


def test_format_unknown_extension_exits():
    with pytest.raises(SystemExit):
        FormatRegistry.detect(Path("data.txt"))


# ══════════════════════════════════════════════════════════════════════════════
# ValuePatternDetector
# ══════════════════════════════════════════════════════════════════════════════

def _make_sample_fn(data: dict[str, list]):
    """Build a sample_fn that mimics adapter.sample_values for test data."""
    def sample_fn(col: str, n: int):
        return data.get(col, [])[:n]
    return sample_fn


def test_value_detector_finds_email_by_value():
    data = {"col_7": ["alice@example.com", "bob@corp.org", "carol@test.net"]}
    det = ValuePatternDetector(sample_rows=10, threshold=0.5)
    found = det.detect(["col_7"], _make_sample_fn(data))
    assert "col_7" in found
    assert found["col_7"].name == "email"


def test_value_detector_finds_ssn_by_value():
    data = {"col_x": ["123-45-6789", "234-56-7890", "345-67-8901"]}
    det = ValuePatternDetector(sample_rows=10, threshold=0.5)
    found = det.detect(["col_x"], _make_sample_fn(data))
    assert "col_x" in found
    assert found["col_x"].name == "ssn"


def test_value_detector_finds_credit_card_by_value():
    data = {"field_1": ["4111111111111234",
                        "5500005555555559", "6011111111111117"]}
    det = ValuePatternDetector(sample_rows=10, threshold=0.5)
    found = det.detect(["field_1"], _make_sample_fn(data))
    assert "field_1" in found
    assert found["field_1"].name == "credit_card"


def test_value_detector_skips_already_detected():
    data = {"email": ["alice@example.com"], "col_7": ["123-45-6789"]}
    existing = {"email": PIIRegistry.get("email")}
    det = ValuePatternDetector(sample_rows=10, threshold=0.3)
    found = det.detect(["email", "col_7"],
                       _make_sample_fn(data), existing=existing)
    assert "email" not in found   # already detected — skipped
    assert "col_7" in found


def test_value_detector_below_threshold_not_flagged():
    # Only 1 of 5 values matches — 20% < default 30% threshold
    data = {"col_a": ["alice@example.com", "not_email",
                      "not_email", "not_email", "not_email"]}
    det = ValuePatternDetector(sample_rows=10, threshold=0.5)
    found = det.detect(["col_a"], _make_sample_fn(data))
    assert "col_a" not in found


def test_value_detector_empty_column_skipped():
    data = {"empty_col": []}
    det = ValuePatternDetector(sample_rows=10, threshold=0.3)
    found = det.detect(["empty_col"], _make_sample_fn(data))
    assert "empty_col" not in found


def test_value_detector_finds_ip_address():
    data = {"col_ip": ["192.168.1.1", "10.0.0.1", "172.16.0.1"]}
    det = ValuePatternDetector(sample_rows=10, threshold=0.5)
    found = det.detect(["col_ip"], _make_sample_fn(data))
    assert "col_ip" in found
    assert found["col_ip"].name == "ip"
