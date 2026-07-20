"""
config/xml_io.py
================
XML I/O helpers for XPath-based PII masking.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
import io

from .base import BaseDataFrameAdapter
from ..config.registry import PIIType
from ..config.enums import FileFormat
from ..config.crypto import decrypt_value
from ..strategies.base import BaseMaskingStrategy, MaskingContext


class XMLAdapter(BaseDataFrameAdapter):
    """
    Loads an XML file using an XPath row selector.

    Security note: Uses hardened parser settings to mitigate XXE and
    entity expansion attacks (billion laughs).
    """

    def __init__(
        self,
        xpath: str = "//*",
        pii_fields: list[str] | None = None,
        use_lxml: bool = False,
    ) -> None:
        self._xpath = xpath
        self._pii_fields = pii_fields or []
        self._use_lxml = use_lxml
        self._tree: Any = None
        self._nodes: list[Any] = []

    # ── Secure parser creation ────────────────────────────────────────────────

    def _get_etree(self) -> Any:
        """Return ET module with hardened parser."""
        if self._use_lxml or True:  # Prefer lxml when available
            try:
                import lxml.etree as ET
                return ET
            except ImportError:
                pass

        import xml.etree.ElementTree as ET
        return ET

    def _create_secure_parser(self, ET: Any):
        """Create a secure parser that disables dangerous features."""
        if hasattr(ET, "XMLParser"):  # lxml
            return ET.XMLParser(
                resolve_entities=False,      # Block XXE
                no_network=True,             # Prevent external entity loading
                huge_tree=False,             # Limit tree size
                dtd_validation=False,
                load_dtd=False,
                recover=False,               # Don't try to recover from errors
            )
        else:
            # stdlib xml.etree.ElementTree has limited hardening options
            # It is safer in recent Python versions, but still not ideal
            return None

    # ── Loading ───────────────────────────────────────────────────────────────

    def load(self, source: Any, fmt: FileFormat = FileFormat.csv) -> None:
        ET = self._get_etree()
        parser = self._create_secure_parser(ET)

        if isinstance(source, (str, Path)):
            path = str(source)
            if parser is not None:  # lxml
                self._tree = ET.parse(path, parser=parser)
            else:  # stdlib fallback
                self._tree = ET.parse(path)

            root = self._tree.getroot()

        elif isinstance(source, (bytes, io.BytesIO)):
            data = source.read() if isinstance(source, io.BytesIO) else source
            if parser is not None:
                self._tree = ET.fromstring(data, parser=parser)
            else:
                self._tree = ET.fromstring(data)
            root = self._tree

        else:
            raise TypeError(f"Unsupported XML source type: {type(source)}")

        # Find matching nodes
        if hasattr(root, "findall"):
            # Simple XPath normalization
            xpath = self._xpath.lstrip("/").replace("//", "./") or "."
            self._nodes = root.findall(xpath)
        else:
            self._nodes = []

    # ── Saving ────────────────────────────────────────────────────────────────

    def save(self, dest: Any, fmt: FileFormat = FileFormat.csv) -> None:
        ET = self._get_etree()
        root = self._tree.getroot() if hasattr(self._tree, "getroot") else self._tree

        if dest is None:
            import sys
            raw = ET.tostring(root, encoding="unicode", xml_declaration=True)
            sys.stdout.write(raw)
        elif isinstance(dest, (str, Path)):
            if hasattr(self._tree, "write"):
                self._tree.write(str(dest), encoding="utf-8",
                                 xml_declaration=True)
            else:
                raw = ET.tostring(root, encoding="unicode",
                                  xml_declaration=True)
                Path(dest).write_text(raw, encoding="utf-8")
        elif isinstance(dest, io.BytesIO):
            raw = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            dest.write(raw)

    # ── BaseDataFrameAdapter interface ────────────────────────────────────────

    @property
    def columns(self) -> list[str]:
        return list(self._pii_fields)

    def row_count(self) -> int:
        return len(self._nodes)

    def apply_mask(
        self,
        col: str,
        strategy: BaseMaskingStrategy,
        pii_type: Optional[PIIType],
        ctx: MaskingContext,
    ) -> None:
        for node in self._nodes:
            # Element text
            child = node.find(col)
            if child is not None and child.text:
                child.text = str(strategy.mask(child.text, pii_type, ctx))
            # Attribute
            elif col in node.attrib:
                node.attrib[col] = str(strategy.mask(
                    node.attrib[col], pii_type, ctx))

    def apply_unmask(
        self,
        col: str,
        key_bytes: bytes,
        kms_provider: str | None = None,
        kms_region: str | None = None,
        kms_encryption_context: dict[str, str] | None = None,
    ) -> None:
        for node in self._nodes:
            child = node.find(col)
            if child is not None and child.text:
                child.text = decrypt_value(
                    child.text,
                    key_bytes,
                    kms_provider=kms_provider,
                    kms_region=kms_region,
                    kms_encryption_context=kms_encryption_context,
                )
            elif col in node.attrib:
                node.attrib[col] = decrypt_value(
                    node.attrib[col],
                    key_bytes,
                    kms_provider=kms_provider,
                    kms_region=kms_region,
                    kms_encryption_context=kms_encryption_context,
                )

    def sample_values(self, col: str, n: int = 3) -> list[Any]:
        results = []
        for node in self._nodes:
            child = node.find(col)
            val = child.text if child is not None else node.attrib.get(col)
            if val:
                results.append(val)
            if len(results) >= n:
                break
        return results
