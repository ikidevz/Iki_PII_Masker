"""
test_strategies.py — Unit tests for all masking strategy classes.

Tests each strategy in isolation — no file I/O, no CLI, no adapters.
"""

import hashlib
import pytest

from Iki_PII_Masker.facade import (
    Strategy, MaskingContext, PIIRegistry,
    derive_encryption_key,
)
from Iki_PII_Masker.config.crypto import decrypt_value
from Iki_PII_Masker.strategies.factory import StrategyFactory
from Iki_PII_Masker.strategies.fake import FakeStrategy
from Iki_PII_Masker.strategies.redact import RedactStrategy
from Iki_PII_Masker.strategies.tokenize import TokenizeStrategy
from Iki_PII_Masker.strategies.pseudonymize import PseudonymizeStrategy
from Iki_PII_Masker.strategies.generalize import GeneralizeStrategy
from Iki_PII_Masker.strategies.mask_format import MaskFormatStrategy


# ── helper ────────────────────────────────────────────────────────────────────

def _mask(strategy: Strategy, value, pii_type_name: str = "email",
          ctx: MaskingContext = None):
    ctx = ctx or MaskingContext()
    pii = PIIRegistry.get(pii_type_name)
    return StrategyFactory.create(strategy).mask(value, pii, ctx)


# ══════════════════════════════════════════════════════════════════════════════
# None passthrough — every strategy
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("strategy", list(Strategy))
def test_none_passthrough(strategy):
    assert _mask(strategy, None) is None


# ══════════════════════════════════════════════════════════════════════════════
# keep
# ══════════════════════════════════════════════════════════════════════════════

def test_keep_returns_original():
    assert _mask(Strategy.keep, "alice@example.com") == "alice@example.com"


def test_keep_ignores_reversible():
    ctx = MaskingContext(reversible=True, key_bytes=derive_encryption_key("s"))
    result = _mask(Strategy.keep, "alice@example.com", ctx=ctx)
    assert result == "alice@example.com"
    assert not str(result).startswith("ENC:")


# ══════════════════════════════════════════════════════════════════════════════
# null
# ══════════════════════════════════════════════════════════════════════════════

def test_null_returns_none():
    assert _mask(Strategy.null, "alice@example.com") is None


def test_null_ignores_reversible():
    ctx = MaskingContext(reversible=True, key_bytes=derive_encryption_key("s"))
    assert _mask(Strategy.null, "alice@example.com", ctx=ctx) is None


# ══════════════════════════════════════════════════════════════════════════════
# redact
# ══════════════════════════════════════════════════════════════════════════════

def test_redact_typed_labels():
    assert _mask(Strategy.redact, "alice@example.com", "email") == "[EMAIL]"
    assert _mask(Strategy.redact, "Alice Smith",        "name") == "[NAME]"
    assert _mask(Strategy.redact, "+1-555-0100",        "phone") == "[PHONE]"
    assert _mask(Strategy.redact, "4111111111111234",
                 "credit_card") == "[CARD]"
    assert _mask(Strategy.redact, "usr_abc123",         "user_id") == "[ID]"


def test_redact_generic_fallback():
    result = RedactStrategy().mask("some value", None, MaskingContext())
    assert result == "[REDACTED]"


# ══════════════════════════════════════════════════════════════════════════════
# hash
# ══════════════════════════════════════════════════════════════════════════════

def test_hash_format():
    result = _mask(Strategy.hash, "alice@example.com")
    assert result.startswith("SHA:")
    assert len(result) == 4 + 16


def test_hash_deterministic():
    ctx = MaskingContext(salt="pepper")
    assert _mask(Strategy.hash, "alice@example.com", ctx=ctx) == \
        _mask(Strategy.hash, "alice@example.com", ctx=ctx)


def test_hash_different_values_differ():
    assert _mask(Strategy.hash, "alice@example.com") != \
        _mask(Strategy.hash, "bob@example.com")


def test_hash_salt_changes_output():
    r1 = _mask(Strategy.hash, "alice@example.com",
               ctx=MaskingContext(salt="s1"))
    r2 = _mask(Strategy.hash, "alice@example.com",
               ctx=MaskingContext(salt="s2"))
    assert r1 != r2


def test_hash_no_salt_matches_sha256():
    value = "alice@example.com"
    expected = "SHA:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    assert _mask(Strategy.hash, value) == expected


# ══════════════════════════════════════════════════════════════════════════════
# fake
# ══════════════════════════════════════════════════════════════════════════════

def test_fake_returns_nonempty_string():
    result = _mask(Strategy.fake, "alice@example.com", "email")
    assert isinstance(result, str) and len(result) > 0


def test_fake_does_not_return_original():
    assert _mask(Strategy.fake, "alice@example.com",
                 "email") != "alice@example.com"


def test_fake_reproducible_with_seed():
    s1, s2 = FakeStrategy(), FakeStrategy()
    pii = PIIRegistry.get("email")
    ctx = MaskingContext(seed=42)
    assert s1.mask("alice@example.com", pii, ctx) == \
        s2.mask("alice@example.com", pii, ctx)


def test_fake_all_pii_types_return_strings():
    for pii_type in ["email", "phone", "name", "address", "ssn",
                     "dob", "ip", "credit_card", "user_id", "password"]:
        result = _mask(Strategy.fake, "placeholder", pii_type)
        assert isinstance(result, str) and result, f"failed for {pii_type}"


# ══════════════════════════════════════════════════════════════════════════════
# partial
# ══════════════════════════════════════════════════════════════════════════════

def test_partial_keep_right():
    ctx = MaskingContext(partial_keep=4, partial_side="right")
    result = _mask(Strategy.partial, "4111111111111234", ctx=ctx)
    assert result.endswith("1234")
    assert "*" in result
    assert len(result) == 16


def test_partial_keep_left():
    ctx = MaskingContext(partial_keep=4, partial_side="left")
    result = _mask(Strategy.partial, "4111111111111234", ctx=ctx)
    assert result.startswith("4111")
    assert result.endswith("*")


def test_partial_short_value_unchanged():
    assert _mask(Strategy.partial, "short",
                 ctx=MaskingContext(partial_keep=10)) == "short"


def test_partial_star_count():
    ctx = MaskingContext(partial_keep=4, partial_side="right")
    result = _mask(Strategy.partial, "1234567890", ctx=ctx)
    assert result.count("*") == 6


# ══════════════════════════════════════════════════════════════════════════════
# reversible (AES-256-GCM)
# ══════════════════════════════════════════════════════════════════════════════

def test_reversible_produces_enc_token():
    ctx = MaskingContext(
        reversible=True, key_bytes=derive_encryption_key("secret"))
    assert str(_mask(Strategy.redact, "alice@example.com", ctx=ctx)
               ).startswith("ENC:")


def test_reversible_round_trip():
    key = derive_encryption_key("mysecret")
    ctx = MaskingContext(reversible=True, key_bytes=key)
    encrypted = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    assert decrypt_value(str(encrypted), key) == "alice@example.com"


def test_reversible_unique_tokens():
    key = derive_encryption_key("secret")
    ctx = MaskingContext(reversible=True, key_bytes=key)
    r1 = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    r2 = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    assert r1 != r2   # different nonces each time


def test_decrypt_non_enc_passthrough():
    assert decrypt_value(
        "plain_value", derive_encryption_key("s")) == "plain_value"


def test_wrong_key_raises():
    key = derive_encryption_key("correct_key")
    wrong = derive_encryption_key("wrong_key")
    ctx = MaskingContext(reversible=True, key_bytes=key)
    enc = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    with pytest.raises(Exception):
        decrypt_value(str(enc), wrong)


# ══════════════════════════════════════════════════════════════════════════════
# tokenize
# ══════════════════════════════════════════════════════════════════════════════

def test_tokenize_produces_tok_prefix():
    result = _mask(Strategy.tokenize, "alice@example.com")
    assert str(result).startswith("TOK-")


def test_tokenize_stable_same_instance():
    """Same input → same token within one strategy instance."""
    s = TokenizeStrategy()
    pii = PIIRegistry.get("email")
    ctx = MaskingContext()
    r1 = s.mask("alice@example.com", pii, ctx)
    r2 = s.mask("alice@example.com", pii, ctx)
    assert r1 == r2


def test_tokenize_different_values_get_different_tokens():
    s = TokenizeStrategy()
    pii = PIIRegistry.get("email")
    ctx = MaskingContext()
    t1 = s.mask("alice@example.com", pii, ctx)
    t2 = s.mask("bob@example.com",   pii, ctx)
    assert t1 != t2


def test_tokenize_detokenize_round_trip():
    s = TokenizeStrategy()
    pii = PIIRegistry.get("email")
    ctx = MaskingContext()
    tok = s.mask("alice@example.com", pii, ctx)
    assert s.detokenize(str(tok)) == "alice@example.com"


def test_tokenize_clear_resets_table():
    s = TokenizeStrategy()
    pii = PIIRegistry.get("email")
    ctx = MaskingContext()
    s.mask("alice@example.com", pii, ctx)
    s.clear()
    assert s.token_table == {}
    assert s.detokenize("any-token") is None


# ══════════════════════════════════════════════════════════════════════════════
# pseudonymize
# ══════════════════════════════════════════════════════════════════════════════

def test_pseudonymize_consistent_same_input():
    s = PseudonymizeStrategy()
    pii = PIIRegistry.get("name")
    ctx = MaskingContext(seed=42)
    r1 = s.mask("Alice Smith", pii, ctx)
    r2 = s.mask("Alice Smith", pii, ctx)
    assert r1 == r2


def test_pseudonymize_different_inputs_different_outputs():
    s = PseudonymizeStrategy()
    pii = PIIRegistry.get("name")
    ctx = MaskingContext(seed=42)
    r1 = s.mask("Alice Smith", pii, ctx)
    r2 = s.mask("Bob Jones",   pii, ctx)
    assert r1 != r2


def test_pseudonymize_does_not_return_original():
    s = PseudonymizeStrategy()
    pii = PIIRegistry.get("email")
    ctx = MaskingContext(seed=42)
    result = s.mask("alice@example.com", pii, ctx)
    assert result != "alice@example.com"


def test_pseudonymize_returns_string():
    result = _mask(Strategy.pseudonymize, "Alice Smith", "name")
    assert isinstance(result, str) and result


def test_pseudonymize_mapping_populated():
    s = PseudonymizeStrategy()
    pii = PIIRegistry.get("name")
    ctx = MaskingContext(seed=1)
    s.mask("Alice Smith", pii, ctx)
    assert "Alice Smith" in s.mapping


def test_pseudonymize_clear_resets_mapping():
    s = PseudonymizeStrategy()
    pii = PIIRegistry.get("name")
    ctx = MaskingContext(seed=1)
    s.mask("Alice Smith", pii, ctx)
    s.clear()
    assert s.mapping == {}


# ══════════════════════════════════════════════════════════════════════════════
# generalize
# ══════════════════════════════════════════════════════════════════════════════

def test_generalize_numeric_range():
    s = GeneralizeStrategy(numeric_step=10)
    ctx = MaskingContext()
    assert s._apply("34",  None, ctx) == "30-40"
    assert s._apply("10",  None, ctx) == "10-20"
    assert s._apply("0",   None, ctx) == "0-10"
    assert s._apply("100", None, ctx) == "100-110"


def test_generalize_numeric_decimal():
    s = GeneralizeStrategy(numeric_step=1000)
    ctx = MaskingContext()
    assert s._apply("4999.99", None, ctx) == "4000-5000"


def test_generalize_date_year():
    s = GeneralizeStrategy(date_precision="year")
    ctx = MaskingContext()
    assert s._apply("1990-07-15", None, ctx) == "1990"


def test_generalize_date_month():
    s = GeneralizeStrategy(date_precision="month")
    ctx = MaskingContext()
    assert s._apply("1990-07-15", None, ctx) == "1990-07"


def test_generalize_string_prefix():
    s = GeneralizeStrategy(string_keep=3)
    ctx = MaskingContext()
    result = s._apply("SW1A2AA", None, ctx)   # UK postcode — not numeric
    assert result.startswith("SW1")
    assert "*" in result


def test_generalize_short_string_unchanged():
    s = GeneralizeStrategy(string_keep=10)
    ctx = MaskingContext()
    assert s._apply("abc", None, ctx) == "abc"


def test_generalize_via_strategy_enum():
    result = _mask(Strategy.generalize, "34")
    assert "-" in str(result)    # numeric range produced


# ══════════════════════════════════════════════════════════════════════════════
# mask_format
# ══════════════════════════════════════════════════════════════════════════════

def test_mask_format_email_preserves_at_and_dot():
    s = MaskFormatStrategy()
    ctx = MaskingContext()
    result = s._apply("john@example.com", None, ctx)
    assert "@" in result
    assert "." in result
    assert "j" not in result
    assert "*" in result


def test_mask_format_credit_card_preserves_dashes():
    s = MaskFormatStrategy()
    ctx = MaskingContext()
    result = s._apply("4111-1111-1111-1234", None, ctx)
    assert result.count("-") == 3
    assert "*" in result


def test_mask_format_keep_last_n():
    s = MaskFormatStrategy(keep_last=4)
    ctx = MaskingContext()
    result = s._apply("4111111111111234", None, ctx)
    assert result.endswith("1234")
    assert "*" in result


def test_mask_format_no_alphanum_unchanged():
    s = MaskFormatStrategy()
    ctx = MaskingContext()
    assert s._apply("---", None, ctx) == "---"


def test_mask_format_phone_preserves_plus_and_spaces():
    s = MaskFormatStrategy()
    ctx = MaskingContext()
    result = s._apply("+1 (555) 867-5309", None, ctx)
    assert "+" in result
    assert "(" in result
    assert ")" in result
    assert "*" in result


def test_mask_format_via_strategy_enum():
    result = _mask(Strategy.mask_format, "john@example.com", "email")
    assert "@" in str(result)
    assert "*" in str(result)
