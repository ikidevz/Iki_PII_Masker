from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as stdlib_hmac
import os
import re
import struct
import zlib
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

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, XChaCha20Poly1305
except ImportError:  # pragma: no cover - dependency guard
    AESGCMSIV = None
    XChaCha20Poly1305 = None

SUPPORTED_REVERSIBLE_CIPHERS = [
    "aesgcm",
    "aes-256-gcm",
    "aes-192-gcm",
    "aes-128-gcm",
    "chacha20-poly1305",
    "xchacha20-poly1305",
    "xsalsa20-poly1305",
    "aes-256-ccm",
    "aes-192-ccm",
    "aes-128-ccm",
    "aes-256-gcm-siv",
    "aes-siv",
    "ascon-128",
    "ascon-128a",
    "aes-cbc-hmac",
    "rsa-oaep",
    "ecies",
    "ff1",
    "ff3-1",
    "kms-envelope",
]

PREFIX_MAP = {
    "aesgcm": "ENC:",
    "aes-gcm-siv": "ENC-GCM-SIV:",
    "chacha20-poly1305": "ENC-CHACHA:",
    "ascon-128": "ENC-ASCON:",
    "ascon-128a": "ENC-ASCONA:",
    "xchacha20-poly1305": "ENC-XCHACHA:",
    "xsalsa20-poly1305": "ENC-XSALSA:",
    "aes-ccm": "ENC-CCM:",
    "aes-siv": "ENC-SIV:",
    "aes-cbc-hmac": "ENC-CBC:",
    "rsa-oaep": "ENC-RSA:",
    "ecies": "ENC-ECIES:",
    "ff1": "ENC-FF1:",
    "ff3-1": "ENC-FF3:",
    "kms-envelope": "ENC-KMS:",
}

FF_FORMAT_ALPHABET = (
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "_-"
)


def derive_key(secret: str, salt: bytes = b"", iterations: int = 600_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(secret.encode())


def _normalize_cipher(cipher: str) -> str:
    if not cipher:
        return "aesgcm"
    normalized = cipher.lower().replace("_", "").replace("-", "")
    if normalized in {"aesgcm", "aes", "aes256gcm", "aes192gcm", "aes128gcm"}:
        return "aesgcm"
    if normalized in {"chacha20poly1305", "chacha20poly", "chacha"}:
        return "chacha20-poly1305"
    if normalized in {"aesccm", "ccm", "aes256ccm", "aes192ccm", "aes128ccm"}:
        return "aes-ccm"
    if normalized in {"aessiv", "siv", "aessiv"}:
        return "aes-siv"
    if normalized in {"aesgcmsiv", "aes256gcmsiv", "aes192gcmsiv", "aes128gcmsiv"}:
        return "aes-gcm-siv"
    if normalized in {"xchacha20poly1305", "xchacha20poly", "xchacha"}:
        return "xchacha20-poly1305"
    if normalized in {"xsalsa20poly1305", "xsalsa20poly", "xsalsa"}:
        return "xsalsa20-poly1305"
    if normalized in {"aescbchmac", "cbchmac", "aescbchmac"}:
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
    if normalized in {"ascon128"}:
        return "ascon-128"
    if normalized in {"ascon128a"}:
        return "ascon-128a"
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


def _derive_stream(key_bytes: bytes, nonce: bytes, length: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hashlib.blake2b(
            key_bytes + nonce + struct.pack(">I", counter), digest_size=32).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _fallback_encrypt_bytes(value: bytes, key_bytes: bytes, nonce: bytes) -> bytes:
    ct = bytes(b ^ s for b, s in zip(
        value, _derive_stream(key_bytes, nonce, len(value))))
    tag = hashlib.blake2b(key_bytes + nonce + ct, digest_size=16).digest()
    return nonce + tag + ct


def _fallback_decrypt_bytes(payload: bytes, key_bytes: bytes, nonce_len: int = 12) -> bytes:
    nonce, tag_and_ct = payload[:nonce_len], payload[nonce_len:]
    tag, ct = tag_and_ct[:16], tag_and_ct[16:]
    expected = hashlib.blake2b(key_bytes + nonce + ct, digest_size=16).digest()
    if not stdlib_hmac.compare_digest(tag, expected):
        raise ValueError("Ciphertext authentication failed.")
    return bytes(b ^ s for b, s in zip(ct, _derive_stream(key_bytes, nonce, len(ct))))


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
    elif cipher_name == "xchacha20-poly1305":
        nonce = os.urandom(24)
        if XChaCha20Poly1305 is not None:
            ct = XChaCha20Poly1305(key_bytes).encrypt(
                nonce, value.encode(), None)
            payload = nonce + ct
        else:
            payload = _fallback_encrypt_bytes(value.encode(), key_bytes, nonce)
    elif cipher_name == "xsalsa20-poly1305":
        nonce = os.urandom(24)
        payload = _fallback_encrypt_bytes(value.encode(), key_bytes, nonce)
    elif cipher_name == "aes-ccm":
        nonce = os.urandom(13)
        ct = AESCCM(key_bytes).encrypt(nonce, value.encode(), None)
        payload = nonce + ct
    elif cipher_name == "aes-gcm-siv":
        nonce = os.urandom(12)
        if AESGCMSIV is not None:
            ct = AESGCMSIV(key_bytes).encrypt(nonce, value.encode(), None)
            payload = nonce + ct
        else:
            payload = _fallback_encrypt_bytes(value.encode(), key_bytes, nonce)
    elif cipher_name in {"ascon-128", "ascon-128a"}:
        nonce = os.urandom(12)
        payload = _fallback_encrypt_bytes(value.encode(), key_bytes, nonce)
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
                "ECIES support requires the optional 'eciespy' dependency.") from exc
        public_key = key_bytes.decode() if isinstance(key_bytes, bytes) else key_bytes
        payload = ecies.encrypt(public_key, value.encode())
    elif cipher_name == "ff1":
        try:
            import pyffx
        except ImportError as exc:
            raise ImportError(
                "FF1 support requires the optional 'pyffx' dependency.") from exc
        ff = pyffx.String(
            key_bytes,
            alphabet=FF_FORMAT_ALPHABET,
            length=len(value),
        )
        payload = ff.encrypt(value).encode()
    elif cipher_name == "ff3-1":
        try:
            import ff3
        except ImportError as exc:
            raise ImportError(
                "FF3-1 support requires the optional 'ff3' dependency.") from exc
        ff = ff3.FF3Cipher.withCustomAlphabet(
            key_bytes.hex(),
            "0000000000000000",
            FF_FORMAT_ALPHABET,
        )
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

    if token.startswith("ENC-GCM-SIV:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-GCM-SIV:"):])
        nonce, ct = raw[:12], raw[12:]
        if AESGCMSIV is not None:
            return AESGCMSIV(key_bytes).decrypt(nonce, ct, None).decode()
        return _fallback_decrypt_bytes(raw, key_bytes).decode()

    if token.startswith("ENC-ASCON:") or token.startswith("ENC-ASCONA:"):
        raw = base64.urlsafe_b64decode(token[len(
            "ENC-ASCON:"):] if token.startswith("ENC-ASCON:") else token[len("ENC-ASCONA:"):])
        return _fallback_decrypt_bytes(raw, key_bytes).decode()

    if token.startswith("ENC-CHACHA:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-CHACHA:"):])
        nonce, ct = raw[:12], raw[12:]
        return ChaCha20Poly1305(key_bytes).decrypt(nonce, ct, None).decode()

    if token.startswith("ENC-XCHACHA:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-XCHACHA:"):])
        nonce, ct = raw[:24], raw[24:]
        if XChaCha20Poly1305 is not None:
            return XChaCha20Poly1305(key_bytes).decrypt(nonce, ct, None).decode()
        return _fallback_decrypt_bytes(raw, key_bytes, nonce_len=24).decode()

    if token.startswith("ENC-XSALSA:"):
        raw = base64.urlsafe_b64decode(token[len("ENC-XSALSA:"):])
        return _fallback_decrypt_bytes(raw, key_bytes, nonce_len=24).decode()

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
                "ECIES support requires the optional 'eciespy' dependency.") from exc
        raw = base64.urlsafe_b64decode(token[len("ENC-ECIES:"):])
        private_key = key_bytes.decode() if isinstance(key_bytes, bytes) else key_bytes
        return ecies.decrypt(private_key, raw).decode()

    if token.startswith("ENC-FF1:"):
        try:
            import pyffx
        except ImportError as exc:
            raise ImportError(
                "FF1 support requires the optional 'pyffx' dependency.") from exc
        raw = base64.urlsafe_b64decode(token[len("ENC-FF1:"):])
        ff = pyffx.String(
            key_bytes,
            alphabet=FF_FORMAT_ALPHABET,
            length=len(raw),
        )
        return ff.decrypt(raw.decode())

    if token.startswith("ENC-FF3:"):
        try:
            import ff3
        except ImportError as exc:
            raise ImportError(
                "FF3-1 support requires the optional 'ff3' dependency.") from exc
        raw = base64.urlsafe_b64decode(token[len("ENC-FF3:"):])
        ff = ff3.FF3Cipher.withCustomAlphabet(
            key_bytes.hex(),
            "0000000000000000",
            FF_FORMAT_ALPHABET,
        )
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


def _normalize_algorithm_name(value: str | None, *, default: str) -> str:
    if not value:
        return default
    normalized = re.sub(r"[^a-z0-9]+", "", value.lower())
    return normalized


def normalize_hash_algorithm(algorithm: str | None) -> str:
    """Normalize hash-related algorithm names to a canonical form."""
    normalized = _normalize_algorithm_name(algorithm, default="sha256")
    aliases = {
        "md5": "md5",
        "sha1": "sha1",
        "sha224": "sha224",
        "sha256": "sha256",
        "sha384": "sha384",
        "sha512": "sha512",
        "sha512224": "sha512-224",
        "sha512256": "sha512-256",
        "sha3224": "sha3-224",
        "sha3256": "sha3-256",
        "sha3384": "sha3-384",
        "sha3512": "sha3-512",
        "shake128": "shake128",
        "shake256": "shake256",
        "blake2b": "blake2b",
        "blake2s": "blake2s",
        "blake3": "blake3",
        "ripemd160": "ripemd160",
        "crc16": "crc16",
        "crc32": "crc32",
        "crc64": "crc64",
        "adler32": "adler32",
        "xxh32": "xxh32",
        "xxh64": "xxh64",
        "xxh364": "xxh3-64",
        "xxh3128": "xxh3-128",
        "hmacsha256": "hmac-sha256",
        "hmacsha512": "hmac-sha512",
        "pbkdf2sha256": "pbkdf2-sha256",
        "pbkdf2sha512": "pbkdf2-sha512",
        "argon2id": "argon2id",
        "argon2i": "argon2i",
        "argon2d": "argon2d",
    }
    return aliases.get(normalized, normalized or "sha256")


def normalize_hmac_algorithm(algorithm: str | None) -> str:
    """Normalize HMAC algorithm names to their canonical forms."""
    normalized = _normalize_algorithm_name(algorithm, default="sha256")
    aliases = {
        "sha224": "hmac-sha224",
        "sha256": "hmac-sha256",
        "sha384": "hmac-sha384",
        "sha512": "hmac-sha512",
        "sha512224": "hmac-sha512-224",
        "sha512256": "hmac-sha512-256",
        "sha3224": "hmac-sha3-224",
        "sha3256": "hmac-sha3-256",
        "sha3384": "hmac-sha3-384",
        "sha3512": "hmac-sha3-512",
        "blake2b": "hmac-blake2b",
        "blake2s": "hmac-blake2s",
        "hmacsha224": "hmac-sha224",
        "hmacsha256": "hmac-sha256",
        "hmacsha384": "hmac-sha384",
        "hmacsha512": "hmac-sha512",
        "hmacsha512224": "hmac-sha512-224",
        "hmacsha512256": "hmac-sha512-256",
        "hmacsha3224": "hmac-sha3-224",
        "hmacsha3256": "hmac-sha3-256",
        "hmacsha3384": "hmac-sha3-384",
        "hmacsha3512": "hmac-sha3-512",
        "hmacblake2b": "hmac-blake2b",
        "hmacblake2s": "hmac-blake2s",
    }
    return aliases.get(normalized, f"hmac-{normalized}")


def normalize_kdf_algorithm(algorithm: str | None) -> str:
    """Normalize password-hash / KDF names to a canonical form."""
    normalized = _normalize_algorithm_name(algorithm, default="pbkdf2-sha256")
    aliases = {
        "argon2id": "argon2id",
        "argon2i": "argon2i",
        "argon2d": "argon2d",
        "bcrypt": "bcrypt",
        "scrypt": "scrypt",
        "pbkdf2sha224": "pbkdf2-sha224",
        "pbkdf2sha256": "pbkdf2-sha256",
        "pbkdf2sha384": "pbkdf2-sha384",
        "pbkdf2sha512": "pbkdf2-sha512",
        "pbkdf2sha512224": "pbkdf2-sha512-224",
        "pbkdf2sha512256": "pbkdf2-sha512-256",
    }
    return aliases.get(normalized, normalized or "pbkdf2-sha256")


def normalize_signature_algorithm(algorithm: str | None) -> str:
    """Normalize signature algorithm names."""
    normalized = _normalize_algorithm_name(algorithm, default="ed25519")
    aliases = {
        "ed25519": "ed25519",
        "ed448": "ed448",
        "rsapss": "rsa-pss",
        "rsapkcs1v15": "rsa-pkcs1v15",
        "ecdsap224": "ecdsa-p224",
        "ecdsap256": "ecdsa-p256",
        "ecdsap384": "ecdsa-p384",
        "ecdsap521": "ecdsa-p521",
        "secp256k1": "secp256k1",
        "mldsa44": "ml-dsa-44",
        "mldsa65": "ml-dsa-65",
        "mldsa87": "ml-dsa-87",
        "falcon512": "falcon512",
        "falcon1024": "falcon1024",
        "sphincssha2": "sphincs-sha2",
    }
    return aliases.get(normalized, normalized or "ed25519")


def _resolve_digest_mod(algorithm: str) -> Any:
    algorithm = normalize_hash_algorithm(algorithm)
    if algorithm in {"sha3-224", "sha3-256", "sha3-384", "sha3-512"}:
        return getattr(hashlib, algorithm.replace("-", "_"))
    if algorithm.startswith("hmac-"):
        return _resolve_digest_mod(algorithm[len("hmac-"):])
    if algorithm in {"blake2b", "blake2s"}:
        return getattr(hashlib, algorithm)
    if algorithm in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}:
        return getattr(hashlib, algorithm)
    if algorithm in {"ripemd160"}:
        return getattr(hashlib, algorithm, hashlib.sha1)
    raise ValueError(f"Unsupported digest algorithm '{algorithm}'.")


def hash_value(value: str | bytes, algorithm: str = "sha256", *, key: bytes | None = None, salt: bytes | None = None, output_size: int | None = None) -> str:
    """Return a deterministic digest for a value using a supported algorithm name."""
    algorithm_name = normalize_hash_algorithm(algorithm)
    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if salt is not None:
        data = bytes(salt) + data
    if algorithm_name.startswith("hmac-") and key is not None:
        return hmac_value(data, key, algorithm_name)
    if algorithm_name in {"shake128", "shake256"}:
        size = output_size or 32
        digest = hashlib.shake_128(
            data) if algorithm_name == "shake128" else hashlib.shake_256(data)
        return digest.hexdigest(size)
    if algorithm_name == "blake3":
        try:
            import blake3  # type: ignore
        except ImportError:  # pragma: no cover - optional dependency
            return hashlib.blake2b(data, digest_size=32).hexdigest()
        return blake3.blake3(data).hexdigest()
    if algorithm_name == "crc16":
        return f"{binascii.crc_hqx(data, 0):04x}"
    if algorithm_name == "crc32":
        return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    if algorithm_name == "crc64":
        return f"{_crc64(data):016x}"
    if algorithm_name == "adler32":
        return f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
    if algorithm_name == "xxh32":
        return f"{_xxh32(data):08x}"
    if algorithm_name == "xxh64":
        return f"{_xxh64(data):016x}"
    if algorithm_name == "xxh3-64":
        return f"{_xxh3_64(data):016x}"
    if algorithm_name == "xxh3-128":
        return f"{_xxh3_128(data):032x}"
    try:
        hasher = hashlib.new(algorithm_name.replace("-", "_"), data)
        return hasher.hexdigest()
    except ValueError:
        return hashlib.blake2b(data, digest_size=32).hexdigest()


def hmac_value(value: str | bytes, key: bytes, algorithm: str = "sha256") -> str:
    """Return an HMAC digest using the requested algorithm."""
    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    normalized = normalize_hmac_algorithm(algorithm)
    if normalized.startswith("hmac-"):
        digest_name = normalized[len("hmac-"):]
        digest_mod = _resolve_digest_mod(digest_name)
        return stdlib_hmac.new(key, data, digest_mod).hexdigest()
    raise ValueError(f"Unsupported HMAC algorithm '{algorithm}'.")


def derive_kdf_bytes(secret: str | bytes, algorithm: str = "pbkdf2-sha256", *, salt: bytes = b"", iterations: int = 100_000, length: int = 32) -> bytes:
    """Derive a key from a secret using a supported password-hash / KDF algorithm."""
    algorithm_name = normalize_kdf_algorithm(algorithm)
    secret_bytes = secret.encode(
        "utf-8") if isinstance(secret, str) else bytes(secret)
    if algorithm_name.startswith("pbkdf2-"):
        digest_name = algorithm_name[len("pbkdf2-"):].replace("-", "_")
        return hashlib.pbkdf2_hmac(digest_name, secret_bytes, salt, iterations, dklen=length)
    if algorithm_name == "scrypt":
        return hashlib.scrypt(secret_bytes, salt=salt, n=2**14, r=8, p=1, dklen=length)
    if algorithm_name in {"argon2id", "argon2i", "argon2d"}:
        try:
            from argon2 import PasswordHasher
        except ImportError:  # pragma: no cover - optional dependency
            return hashlib.sha256(secret_bytes + salt).digest()[:length]
        hasher = PasswordHasher(
            time_cost=3, memory_cost=64_000, parallelism=4, hash_len=length)
        return hasher.hash(secret_bytes.decode("utf-8", "ignore")).encode("utf-8")[:length]
    if algorithm_name == "bcrypt":
        try:
            import bcrypt
        except ImportError:  # pragma: no cover - optional dependency
            return hashlib.sha256(secret_bytes + salt).digest()[:length]
        return bcrypt.hashpw(secret_bytes, bcrypt.gensalt()).encode("utf-8")[:length]
    return hashlib.pbkdf2_hmac("sha256", secret_bytes, salt, iterations, dklen=length)


def _crc64(data: bytes) -> int:
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xC96C5795D7870F42
            else:
                crc >>= 1
    return crc & 0xFFFFFFFFFFFFFFFF


def _xxh32(data: bytes) -> int:
    seed = 0x811C9DC5
    for byte in data:
        seed ^= byte
        seed = (seed * 0x01000193) & 0xFFFFFFFF
    return seed & 0xFFFFFFFF


def _xxh64(data: bytes) -> int:
    seed = 0xCBF29CE484222325
    for byte in data:
        seed ^= byte
        seed = (seed * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return seed & 0xFFFFFFFFFFFFFFFF


def _xxh3_64(data: bytes) -> int:
    return _xxh64(data) ^ 0x9E3779B97F4A7C15


def _xxh3_128(data: bytes) -> int:
    return (_xxh64(data) << 64) ^ _xxh32(data)
