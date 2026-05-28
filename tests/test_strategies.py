"""
test_strategies.py — Unit tests for all masking strategy classes.

Tests each strategy in isolation — no file I/O, no CLI, no adapters.
"""

import hashlib
import pytest

from Iki_PII_Masker import (
    FakeStrategy,
    MaskingContext,
    PIIRegistry,
    Strategy,
    StrategyFactory,
    derive_key,
    decrypt_value,
    RedactStrategy,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _mask(strategy: Strategy, value, pii_type_name: str = "email", ctx: MaskingContext = None):
    ctx = ctx or MaskingContext()
    pii = PIIRegistry.get(pii_type_name)
    return StrategyFactory.create(strategy).mask(value, pii, ctx)


# ── None passthrough ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("strategy", list(Strategy))
def test_none_passthrough(strategy):
    assert _mask(strategy, None) is None


# ── keep ──────────────────────────────────────────────────────────────────────

def test_keep_returns_original():
    assert _mask(Strategy.keep, "alice@example.com") == "alice@example.com"


def test_keep_ignores_reversible():
    ctx = MaskingContext(reversible=True, key_bytes=derive_key("secret"))
    result = _mask(Strategy.keep, "alice@example.com", ctx=ctx)
    assert result == "alice@example.com"
    assert not str(result).startswith("ENC:")


# ── null ──────────────────────────────────────────────────────────────────────

def test_null_returns_none():
    assert _mask(Strategy.null, "alice@example.com") is None


def test_null_ignores_reversible():
    ctx = MaskingContext(reversible=True, key_bytes=derive_key("secret"))
    assert _mask(Strategy.null, "alice@example.com", ctx=ctx) is None


# ── redact ────────────────────────────────────────────────────────────────────

def test_redact_typed_labels():
    assert _mask(Strategy.redact, "alice@example.com",  "email") == "[EMAIL]"
    assert _mask(Strategy.redact, "Alice Smith",         "name") == "[NAME]"
    assert _mask(Strategy.redact, "+1-555-0100",         "phone") == "[PHONE]"
    assert _mask(Strategy.redact, "4111111111111234",
                 "credit_card") == "[CARD]"
    assert _mask(Strategy.redact, "usr_abc123",          "user_id") == "[ID]"


def test_redact_generic_fallback():
    result = RedactStrategy().mask("some value", None, MaskingContext())
    assert result == "[REDACTED]"


# ── hash ──────────────────────────────────────────────────────────────────────

def test_hash_format():
    result = _mask(Strategy.hash, "alice@example.com")
    assert result.startswith("SHA:")
    assert len(result) == 4 + 16


def test_hash_deterministic():
    ctx = MaskingContext(salt="pepper")
    assert _mask(Strategy.hash, "alice@example.com", ctx=ctx) == \
        _mask(Strategy.hash, "alice@example.com", ctx=ctx)


def test_hash_different_values_differ():
    assert _mask(
        Strategy.hash, "alice@example.com") != _mask(Strategy.hash, "bob@example.com")


def test_hash_salt_changes_output():
    r1 = _mask(Strategy.hash, "alice@example.com",
               ctx=MaskingContext(salt="salt1"))
    r2 = _mask(Strategy.hash, "alice@example.com",
               ctx=MaskingContext(salt="salt2"))
    assert r1 != r2


def test_hash_no_salt_matches_sha256():
    value = "alice@example.com"
    expected = "SHA:" + hashlib.sha256(value.encode()).hexdigest()[:16]
    assert _mask(Strategy.hash, value) == expected


# ── fake ──────────────────────────────────────────────────────────────────────

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
    assert s1.mask("alice@example.com", pii,
                   ctx) == s2.mask("alice@example.com", pii, ctx)


def test_fake_all_pii_types_return_strings():
    for pii_type in ["email", "phone", "name", "address", "ssn",
                     "dob", "ip", "credit_card", "user_id", "password"]:
        result = _mask(Strategy.fake, "placeholder", pii_type)
        assert isinstance(
            result, str) and result, f"failed for pii_type={pii_type}"


# ── partial ───────────────────────────────────────────────────────────────────

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
    ctx = MaskingContext(partial_keep=10)
    assert _mask(Strategy.partial, "short", ctx=ctx) == "short"


def test_partial_star_count():
    ctx = MaskingContext(partial_keep=4, partial_side="right")
    result = _mask(Strategy.partial, "1234567890", ctx=ctx)
    assert result.count("*") == 6


# ── reversible ────────────────────────────────────────────────────────────────

def test_reversible_produces_enc_token():
    ctx = MaskingContext(reversible=True, key_bytes=derive_key("secret"))
    assert str(_mask(Strategy.redact, "alice@example.com", ctx=ctx)
               ).startswith("ENC:")


def test_reversible_round_trip():
    key_bytes = derive_key("mysecret")
    ctx = MaskingContext(reversible=True, key_bytes=key_bytes)
    encrypted = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    assert decrypt_value(str(encrypted), key_bytes) == "alice@example.com"


def test_reversible_unique_tokens():
    key_bytes = derive_key("secret")
    ctx = MaskingContext(reversible=True, key_bytes=key_bytes)
    r1 = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    r2 = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    assert r1 != r2   # different nonces each time


def test_decrypt_non_enc_passthrough():
    assert decrypt_value("plain_value", derive_key("secret")) == "plain_value"


def test_wrong_key_raises():
    key_bytes = derive_key("correct_key")
    wrong_bytes = derive_key("wrong_key")
    ctx = MaskingContext(reversible=True, key_bytes=key_bytes)
    encrypted = _mask(Strategy.redact, "alice@example.com", ctx=ctx)
    with pytest.raises(Exception):
        decrypt_value(str(encrypted), wrong_bytes)
