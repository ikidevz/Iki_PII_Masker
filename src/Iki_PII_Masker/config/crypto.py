import base64
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, hmac, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM,
    AESGCM,
    AESSIV,
    ChaCha20Poly1305,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from .kms import load_kms_provider

SUPPORTED_REVERSIBLE_CIPHERS = [
    "aesgcm",
    "chacha20-poly1305",
    "aes-ccm",
    "aes-siv",
    "aes-cbc-hmac",
    "rsa-oaep",
    "ecies",
    "ff1",
    "ff3-1",
    "kms-envelope",
]

PREFIX_MAP = {
    "aesgcm": "ENC:",
    "chacha20-poly1305": "ENC-CHACHA:",
    "aes-ccm": "ENC-CCM:",
    "aes-siv": "ENC-SIV:",
    "aes-cbc-hmac": "ENC-CBC:",
    "rsa-oaep": "ENC-RSA:",
    "ecies": "ENC-ECIES:",
    "ff1": "ENC-FF1:",
    "ff3-1": "ENC-FF3:",
    "kms-envelope": "ENC-KMS:",
}


def derive_key(secret: str, salt: bytes = b"", iterations: int = 600_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(secret.encode())


def _normalize_cipher(cipher: str) -> str:
    if not cipher:
        return "aesgcm"
    normalized = cipher.lower().replace("_", "").replace("-", "")
    if normalized in {"aesgcm", "aes"}:
        return "aesgcm"
    if normalized in {"chacha20poly1305", "chacha20poly", "chacha"}:
        return "chacha20-poly1305"
    if normalized in {"aesccm", "ccm"}:
        return "aes-ccm"
    if normalized in {"aessiv", "siv"}:
        return "aes-siv"
    if normalized in {"aescbchmac", "cbchmac", "aes-cbc-hmac"}:
        return "aes-cbc-hmac"
    if normalized in {"rsaoaep", "rsa-oaep"}:
        return "rsa-oaep"
    if normalized == "ecies":
        return "ecies"
    if normalized in {"ff1", "formatpreservingencryption"}:
        return "ff1"
    if normalized in {"ff31", "ff3-1"}:
        return "ff3-1"
    if normalized in {"kmsenvelope", "kms-envelope", "kms"}:
        return "kms-envelope"
    raise ValueError(
        f"Unsupported reversible cipher '{cipher}'. "
        f"Supported values: {', '.join(SUPPORTED_REVERSIBLE_CIPHERS)}."
    )


def _split_aes_cbc_hmac_keys(key_bytes: bytes) -> tuple[bytes, bytes]:
    if len(key_bytes) >= 64:
        return key_bytes[:32], key_bytes[32:64]

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"aes-cbc-hmac-key-derivation",
    )
    expanded = hkdf.derive(key_bytes)
    return expanded[:32], expanded[32:]


def _load_rsa_public_key(key_bytes: bytes) -> RSAPublicKey:
    return load_pem_public_key(key_bytes)


def _load_rsa_private_key(key_bytes: bytes) -> RSAPrivateKey:
    return load_pem_private_key(key_bytes, password=None)


def encrypt_value(
    value: str,
    key_bytes: bytes,
    cipher: str = "aesgcm",
    kms_key_id: str | None = None,
    kms_provider: str | None = None,
    kms_region: str | None = None,
    kms_encryption_context: dict[str, str] | None = None,
) -> str:
    cipher_name = _normalize_cipher(cipher)
    prefix = PREFIX_MAP[cipher_name]

    if cipher_name == "aesgcm":
        nonce = os.urandom(12)
        ct = AESGCM(key_bytes).encrypt(nonce, value.encode(), None)
        payload = nonce + ct
    elif cipher_name == "chacha20-poly1305":
        nonce = os.urandom(12)
        ct = ChaCha20Poly1305(key_bytes).encrypt(nonce, value.encode(), None)
        payload = nonce + ct
    elif cipher_name == "aes-ccm":
        nonce = os.urandom(13)
        ct = AESCCM(key_bytes).encrypt(nonce, value.encode(), None)
        payload = nonce + ct
    elif cipher_name == "aes-siv":
        key = key_bytes if len(key_bytes) in {32, 64} else HKDF(
            algorithm=hashes.SHA256(), length=64, salt=None,
            info=b"aes-siv-key-derivation",
        ).derive(key_bytes)
        payload = AESSIV(key).encrypt(value.encode(), [])
    elif cipher_name == "aes-cbc-hmac":
        aes_key, hmac_key = _split_aes_cbc_hmac_keys(key_bytes)
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(value.encode()) + padder.finalize()
        encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        tag = hmac.HMAC(hmac_key, hashes.SHA256())
        tag.update(iv + ct)
        payload = iv + ct + tag.finalize()
    elif cipher_name == "rsa-oaep":
        public_key = _load_rsa_public_key(key_bytes)
        ct = public_key.encrypt(
            value.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        payload = ct
    elif cipher_name == "ecies":
        try:
            import ecies
        except ImportError as exc:
            raise ImportError(
                "ECIES support requires the optional 'ecies' dependency.") from exc
        payload = ecies.encrypt(key_bytes, value.encode())
    elif cipher_name == "ff1":
        try:
            import pyffx
        except ImportError as exc:
            raise ImportError(
                "FF1 support requires the optional 'pyffx' dependency.") from exc
        ff = pyffx.String(
            key_bytes, alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", length=len(value))
        payload = ff.encrypt(value).encode()
    elif cipher_name == "ff3-1":
        try:
            import ff3
        except ImportError as exc:
            raise ImportError(
                "FF3-1 support requires the optional 'ff3' dependency.") from exc
        ff = ff3.FF3Cipher.withCustomAlphabet(
            key_bytes, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        payload = ff.encrypt(value).encode()
    elif cipher_name == "kms-envelope":
        if not kms_key_id:
            raise ValueError(
                "kms-envelope requires a KMS key identifier via kms_key_id.")
        provider = load_kms_provider(kms_provider, kms_region)
        data_key, encrypted_data_key = provider.generate_data_key(
            kms_key_id,
            encryption_context=kms_encryption_context,
        )
        try:
            aead = AESGCM(data_key)
            nonce = os.urandom(12)
            ct = aead.encrypt(nonce, value.encode(), None)
        finally:
            del data_key
        payload = (
            len(encrypted_data_key).to_bytes(4, "big")
            + encrypted_data_key
            + nonce
            + ct
        )
    else:
        raise ValueError(f"Unsupported cipher '{cipher_name}'.")

    return prefix + base64.urlsafe_b64encode(payload).decode()


def decrypt_value(
    token: str,
    key_bytes: bytes,
    kms_provider: str | None = None,
    kms_region: str | None = None,
    kms_encryption_context: dict[str, str] | None = None,
) -> str:
    if token.startswith("ENC-AES:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-AES:"):])
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(key_bytes).decrypt(nonce, ct, None).decode()

    if token.startswith("ENC-CHACHA:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-CHACHA:"):])
        nonce, ct = raw[:12], raw[12:]
        return ChaCha20Poly1305(key_bytes).decrypt(nonce, ct, None).decode()

    if token.startswith("ENC-CCM:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-CCM:"):])
        nonce, ct = raw[:13], raw[13:]
        return AESCCM(key_bytes).decrypt(nonce, ct, None).decode()

    if token.startswith("ENC-SIV:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-SIV:"):])
        key = key_bytes if len(key_bytes) in {32, 64} else HKDF(
            algorithm=hashes.SHA256(), length=64, salt=None,
            info=b"aes-siv-key-derivation",
        ).derive(key_bytes)
        return AESSIV(key).decrypt(raw, []).decode()

    if token.startswith("ENC-CBC:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-CBC:"):])
        aes_key, hmac_key = _split_aes_cbc_hmac_keys(key_bytes)
        iv, rest = raw[:16], raw[16:]
        ct, tag = rest[:-32], rest[-32:]
        verifier = hmac.HMAC(hmac_key, hashes.SHA256())
        verifier.update(iv + ct)
        verifier.verify(tag)
        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode()

    if token.startswith("ENC-RSA:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-RSA:"):])
        private_key = _load_rsa_private_key(key_bytes)
        return private_key.decrypt(
            raw,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ).decode()

    if token.startswith("ENC-ECIES:"):
        try:
            import ecies
        except ImportError as exc:
            raise ImportError(
                "ECIES support requires the optional 'ecies' dependency.") from exc
        raw = base64.urlsafe_b64decode(token[len("ENC-ECIES:"):])
        return ecies.decrypt(key_bytes, raw).decode()

    if token.startswith("ENC-FF1:"):
        try:
            import pyffx
        except ImportError as exc:
            raise ImportError(
                "FF1 support requires the optional 'pyffx' dependency.") from exc
        raw = base64.urlsafe_b64decode(token[len("ENC-FF1:"):])
        ff = pyffx.String(
            key_bytes, alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", length=len(raw))
        return ff.decrypt(raw.decode())

    if token.startswith("ENC-FF3:"):
        try:
            import ff3
        except ImportError as exc:
            raise ImportError(
                "FF3-1 support requires the optional 'ff3' dependency.") from exc
        raw = base64.urlsafe_b64decode(token[len("ENC-FF3:"):])
        ff = ff3.FF3Cipher.withCustomAlphabet(
            key_bytes, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        return ff.decrypt(raw.decode())

    if token.startswith("ENC-KMS:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-KMS:"):])
        if len(raw) < 4 + 12:
            raise ValueError("Invalid KMS envelope token.")
        encrypted_data_key_len = int.from_bytes(raw[:4], "big")
        offset = 4
        encrypted_data_key = raw[offset:offset + encrypted_data_key_len]
        offset += encrypted_data_key_len
        nonce = raw[offset:offset + 12]
        ct = raw[offset + 12:]
        provider = load_kms_provider(kms_provider, kms_region)
        data_key = provider.decrypt_data_key(
            encrypted_data_key,
            encryption_context=kms_encryption_context,
        )
        try:
            return AESGCM(data_key).decrypt(nonce, ct, None).decode()
        finally:
            del data_key

    if token.startswith("ENC:"):
        raw = base64.urlsafe_b64decode(token[4:])
        nonce, ct = raw[:12], raw[12:]
        return AESGCM(key_bytes).decrypt(nonce, ct, None).decode()

    return token
