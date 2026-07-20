from __future__ import annotations

import importlib
from typing import Any


class KMSProviderError(RuntimeError):
    pass


class KMSProvider:
    def generate_data_key(
        self,
        key_id: str,
        encryption_context: dict[str, str] | None = None,
    ) -> tuple[bytes, bytes]:
        raise NotImplementedError

    def decrypt_data_key(
        self,
        encrypted_data_key: bytes,
        encryption_context: dict[str, str] | None = None,
    ) -> bytes:
        raise NotImplementedError


def _import_boto3() -> Any:
    try:
        return importlib.import_module("boto3")
    except ImportError as exc:
        raise ImportError(
            "AWS KMS support requires the optional dependency 'boto3'."
        ) from exc


class AWSKMSProvider(KMSProvider):
    def __init__(self, region_name: str | None = None) -> None:
        boto3 = _import_boto3()
        self.client = boto3.client("kms", region_name=region_name)

    def generate_data_key(
        self,
        key_id: str,
        encryption_context: dict[str, str] | None = None,
    ) -> tuple[bytes, bytes]:
        response = self.client.generate_data_key(
            KeyId=key_id,
            KeySpec="AES_256",
            EncryptionContext=encryption_context or {},
        )
        return response["Plaintext"], response["CiphertextBlob"]

    def decrypt_data_key(
        self,
        encrypted_data_key: bytes,
        encryption_context: dict[str, str] | None = None,
    ) -> bytes:
        response = self.client.decrypt(
            CiphertextBlob=encrypted_data_key,
            EncryptionContext=encryption_context or {},
        )
        return response["Plaintext"]


def load_kms_provider(
    provider_name: str | None = None,
    region_name: str | None = None,
) -> KMSProvider:
    normalized = (provider_name or "aws").lower()
    if normalized in {"aws", "aws-kms"}:
        return AWSKMSProvider(region_name=region_name)
    raise KMSProviderError(
        f"Unsupported KMS provider '{provider_name}'. Supported providers: aws."
    )
