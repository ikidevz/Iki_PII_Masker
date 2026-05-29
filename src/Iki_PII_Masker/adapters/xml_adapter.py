"""
config/xml_io.py
================
XML I/O helpers for XPath-based PII masking.

Provides ``XMLAdapter`` — a thin wrapper that loads an XML document into
a flat list-of-dicts view (one dict per matched XPath node) so the rest
of the masking pipeline can treat it like any other adapter.

Install extra dependency (optional — stdlib ``xml.etree`` is the default):
    pip install lxml    # faster, fuller XPath 1.0 support

Usage
-----
    from Iki_PII_Masker.facade import create_xml_adapter

    adapter = create_xml_adapter(
        xpath="//user",           # repeating element to treat as rows
        pii_fields=["email", "phone"],  # child element names to mask
    )
    load_data(adapter, Path("users.xml"))
    mask_dataframe(adapter, "email:phone", Strategy.fake)
    save_data(adapter, Path("masked.xml"))
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
    Loads an XML file using an XPath row selector and a list of child-element
    field names.  Masking modifies the parsed element tree in-place; saving
    serialises the tree back to XML.

    Parameters
    ----------
    xpath       : XPath expression that selects the repeating row elements
                  e.g. ``"//user"``, ``"//record"``, ``".//row"``
    pii_fields  : child element (or attribute) names treated as columns
                  e.g. ``["email", "phone", "full_name"]``
    use_lxml    : force use of lxml even if not required  (default False)
    """

    def __init__(
        self,
        xpath:      str = "//*",
        pii_fields: list[str] = None,
        use_lxml:   bool = False,
    ) -> None:
        self._xpath = xpath
        self._pii_fields = pii_fields or []
        self._use_lxml = use_lxml
        self._tree:    Any = None
        self._nodes:   list[Any] = []   # matched row elements

    # ── parser selection ──────────────────────────────────────────────────────

    def _get_etree(self) -> Any:
        if self._use_lxml:
            import lxml.etree as ET
            return ET
        try:
            import lxml.etree as ET
            return ET
        except ImportError:
            import xml.etree.ElementTree as ET
            return ET

    # ── BaseDataFrameAdapter interface ─────────────────────────────────────────

    def load(self, source: Any, fmt: FileFormat = FileFormat.csv) -> None:
        ET = self._get_etree()
        if isinstance(source, (str, Path)):
            self._tree = ET.parse(str(source))
            root = self._tree.getroot()
        elif isinstance(source, (bytes, io.BytesIO)):
            data = source.read() if isinstance(source, io.BytesIO) else source
            root = ET.fromstring(data)
            self._tree = root
        else:
            raise TypeError(f"Unsupported XML source type: {type(source)}")

        self._nodes = root.findall(
            self._xpath.lstrip("/").replace("//", "./")
        ) if hasattr(root, "findall") else []

    def save(self, dest: Any, fmt: FileFormat = FileFormat.csv) -> None:
        ET = self._get_etree()
        if dest is None:
            import sys
            raw = ET.tostring(
                self._tree if not hasattr(
                    self._tree, "getroot") else self._tree.getroot(),
                encoding="unicode",
            )
            sys.stdout.write(raw)
        elif isinstance(dest, (str, Path)):
            if hasattr(self._tree, "write"):
                try:
                    self._tree.write(
                        str(dest), encoding="utf-8", xml_declaration=True)
                except TypeError:
                    self._tree.write(
                        str(dest), encoding="unicode", xml_declaration=True)
            else:
                raw = ET.tostring(self._tree, encoding="unicode")
                Path(dest).write_text(raw, encoding="utf-8")
        elif isinstance(dest, io.BytesIO):
            root = self._tree if not hasattr(
                self._tree, "getroot") else self._tree.getroot()
            dest.write(ET.tostring(root))

    @property
    def columns(self) -> list[str]:
        return list(self._pii_fields)

    def row_count(self) -> int:
        return len(self._nodes)

    def apply_mask(
        self,
        col:      str,
        strategy: BaseMaskingStrategy,
        pii_type: Optional[PIIType],
        ctx:      MaskingContext,
    ) -> None:
        for node in self._nodes:
            child = node.find(col)
            if child is not None and child.text:
                child.text = str(strategy.mask(child.text, pii_type, ctx))
            elif col in node.attrib:
                node.attrib[col] = str(strategy.mask(
                    node.attrib[col], pii_type, ctx))

    def apply_unmask(self, col: str, key_bytes: bytes) -> None:
        for node in self._nodes:
            child = node.find(col)
            if child is not None and child.text:
                child.text = decrypt_value(child.text, key_bytes)

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
