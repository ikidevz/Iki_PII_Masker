import builtins

import pytest

from Iki_PII_Masker.config.crypto import (
    PREFIX_MAP,
    SUPPORTED_REVERSIBLE_CIPHERS,
    _normalize_cipher,
    decrypt_value,
    encrypt_value,
)
from Iki_PII_Masker.facade import derive_encryption_key, unmask_dataframe


@pytest.mark.parametrize(
    "value,expected",
    [
        ("aesgcm", "aesgcm"),
        ("AES-GCM", "aesgcm"),
        ("aes", "aesgcm"),
        ("chacha20-poly1305", "chacha20-poly1305"),
        ("chacha20poly", "chacha20-poly1305"),
        ("ccm", "aes-ccm"),
        ("siv", "aes-siv"),
        ("cbchmac", "aes-cbc-hmac"),
        ("rsa-oaep", "rsa-oaep"),
        ("ff31", "ff3-1"),
        ("kms", "kms-envelope"),
    ],
)
def test_normalize_reversible_cipher_names(value, expected):
    assert _normalize_cipher(value) == expected


@pytest.mark.parametrize(
    "cipher",
    [
        "aesgcm",
        "chacha20-poly1305",
        "aes-ccm",
        "aes-siv",
        "aes-cbc-hmac",
    ],
)
def test_encrypt_decrypt_round_trip(cipher):
    key = derive_encryption_key("roundtrip")
    token = encrypt_value("alice@example.com", key, cipher)
    assert token.startswith(PREFIX_MAP[_normalize_cipher(cipher)])
    assert decrypt_value(token, key) == "alice@example.com"


def test_kms_envelope_round_trip(monkeypatch):
    import Iki_PII_Masker.config.kms as kms_mod

    class FakeKMSClient:
        def generate_data_key(self, KeyId, KeySpec, EncryptionContext):
            assert KeyId == "alias/my-key"
            assert KeySpec == "AES_256"
            return {"Plaintext": b"\x01" * 32, "CiphertextBlob": b"encrypted-key"}

        def decrypt(self, CiphertextBlob, EncryptionContext):
            assert CiphertextBlob == b"encrypted-key"
            return {"Plaintext": b"\x01" * 32}

    class FakeBoto3:
        def client(self, service, region_name=None):
            assert service == "kms"
            return FakeKMSClient()

    monkeypatch.setattr(kms_mod, "_import_boto3", lambda: FakeBoto3())

    token = encrypt_value(
        "secret-value",
        b"",
        cipher="kms-envelope",
        kms_key_id="alias/my-key",
        kms_provider="aws",
        kms_region="us-east-1",
        kms_encryption_context={"purpose": "pii-mask"},
    )
    assert token.startswith("ENC-KMS:")
    assert decrypt_value(
        token,
        b"",
        kms_provider="aws",
        kms_region="us-east-1",
        kms_encryption_context={"purpose": "pii-mask"},
    ) == "secret-value"


def test_unmask_dataframe_passes_kms_arguments():
    class DummyAdapter:
        def __init__(self) -> None:
            self.calls = []

        def apply_unmask(
            self,
            col: str,
            key_bytes: bytes,
            kms_provider: str | None = None,
            kms_region: str | None = None,
            kms_encryption_context: dict[str, str] | None = None,
        ) -> None:
            self.calls.append(
                (col, key_bytes, kms_provider, kms_region, kms_encryption_context)
            )

    adapter = DummyAdapter()
    unmask_dataframe(
        adapter,
        ["email"],
        b"",
        kms_provider="aws",
        kms_region="us-east-1",
        kms_encryption_context={"purpose": "pii-mask"},
    )
    assert adapter.calls == [
        (
            "email",
            b"",
            "aws",
            "us-east-1",
            {"purpose": "pii-mask"},
        )
    ]


@pytest.mark.parametrize(
    "missing_module,cipher",
    [
        ("ecies", "ecies"),
        ("pyffx", "ff1"),
        ("ff3", "ff3-1"),
    ],
)
def test_optional_cipher_missing_dependency_raises(monkeypatch, missing_module, cipher):
    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == missing_module:
            raise ImportError(f"No module named {name}")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    with pytest.raises(ImportError):
        encrypt_value("secret", derive_encryption_key("test"), cipher=cipher)


def test_supported_reversible_ciphers_are_documented():
    assert "aesgcm" in SUPPORTED_REVERSIBLE_CIPHERS
    assert "kms-envelope" in SUPPORTED_REVERSIBLE_CIPHERS
