import base64
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()


def encrypt_value(value: str, key_bytes: bytes) -> str:
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, value.encode(), None)
    return "ENC:" + base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt_value(token: str, key_bytes: bytes) -> str:
    if not token.startswith("ENC:"):
        return token
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.urlsafe_b64decode(token[4:])
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key_bytes).decrypt(nonce, ct, None).decode()
