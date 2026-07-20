"""
config/jsonpath_io.py
=====================
JSONPath I/O helpers for masking nested JSON documents.

Provides ``JSONPathAdapter`` — masks values at arbitrary JSONPath
locations inside a JSON document (or a list of JSON documents) without
flattening the structure.

Install extra dependency:
    pip install jsonpath-ng

Usage
-----
    from Iki_PII_Masker.facade import create_jsonpath_adapter

    adapter = create_jsonpath_adapter(
        paths={
            "email":    "$.users[*].contact.email",
            "phone":    "$.users[*].contact.phone",
            "username": "$.users[*].username",
        }
    )
    load_data(adapter, Path("data.json"))
    mask_dataframe(adapter, "email:phone:username", Strategy.fake)
    save_data(adapter, Path("masked.json"))
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional
import io

from .base import BaseDataFrameAdapter
from ..config.registry import PIIType
from ..config.enums import FileFormat
from ..config.crypto import decrypt_value
from ..strategies.base import BaseMaskingStrategy, MaskingContext


class JSONPathAdapter(BaseDataFrameAdapter):
    """
    Masks values at JSONPath locations in a JSON document.

    Parameters
    ----------
    paths : mapping of logical column name → JSONPath expression
            e.g. ``{"email": "$.users[*].email", "phone": "$.users[*].phone"}``
    """

    def __init__(self, paths: dict[str, str]) -> None:
        if not paths:
            raise ValueError("paths must not be empty")
        self._paths:    dict[str, str] = paths
        self._document: Any = None   # parsed JSON (dict or list)

    # ── jsonpath-ng lazy import ───────────────────────────────────────────────

    @staticmethod
    def _parse_path(expression: str) -> Any:
        try:
            from jsonpath_ng import parse
        except ImportError:
            raise ImportError(
                "jsonpath-ng is required for JSONPathAdapter.\n"
                "Install it with:  pip install jsonpath-ng"
            )
        return parse(expression)

    # ── BaseDataFrameAdapter interface ─────────────────────────────────────────

    def load(self, source: Any, fmt: FileFormat = FileFormat.json) -> None:
        if isinstance(source, (str, Path)):
            self._document = json.loads(
                Path(source).read_text(encoding="utf-8"))
        elif isinstance(source, io.BytesIO):
            self._document = json.loads(source.read().decode("utf-8"))
        elif isinstance(source, bytes):
            self._document = json.loads(source.decode("utf-8"))
        else:
            raise TypeError(f"Unsupported JSON source type: {type(source)}")

    def save(self, dest: Any, fmt: FileFormat = FileFormat.json) -> None:
        serialized = json.dumps(self._document, indent=2, ensure_ascii=False)
        if dest is None:
            import sys
            sys.stdout.write(serialized)
        elif isinstance(dest, (str, Path)):
            Path(dest).write_text(serialized, encoding="utf-8")
        elif isinstance(dest, io.BytesIO):
            dest.write(serialized.encode("utf-8"))

    @property
    def columns(self) -> list[str]:
        return list(self._paths.keys())

    def row_count(self) -> int:
        """Return the number of matches for the first path as a proxy for row count."""
        if not self._document or not self._paths:
            return 0
        first_path = next(iter(self._paths.values()))
        matches = self._parse_path(first_path).find(self._document)
        return len(matches)

    def apply_mask(
        self,
        col:      str,
        strategy: BaseMaskingStrategy,
        pii_type: Optional[PIIType],
        ctx:      MaskingContext,
    ) -> None:
        if col not in self._paths:
            return
        expr = self._parse_path(self._paths[col])
        matches = expr.find(self._document)
        for match in matches:
            masked = strategy.mask(match.value, pii_type, ctx)
            match.full_path.update_or_create(self._document, masked)

    def apply_unmask(
        self,
        col: str,
        key_bytes: bytes,
        kms_provider: str | None = None,
        kms_region: str | None = None,
        kms_encryption_context: dict[str, str] | None = None,
    ) -> None:
        if col not in self._paths:
            return
        expr = self._parse_path(self._paths[col])
        matches = expr.find(self._document)
        for match in matches:
            if match.value:
                unmasked = decrypt_value(
                    str(match.value),
                    key_bytes,
                    kms_provider=kms_provider,
                    kms_region=kms_region,
                    kms_encryption_context=kms_encryption_context,
                )
                match.full_path.update_or_create(self._document, unmasked)

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        if col not in self._paths or not self._document:
            return []
        expr = self._parse_path(self._paths[col])
        matches = expr.find(self._document)
        return [m.value for m in matches if m.value is not None][:n]
