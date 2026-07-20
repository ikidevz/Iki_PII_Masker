"""
strategies/ner_redact.py
========================
NER-aware redaction strategy for free-text values.
"""

from __future__ import annotations

from typing import Optional, Any

from .base import BaseMaskingStrategy, MaskingContext
from ..config.registry import PIIType

_nlp_cache: dict[str, Any] = {}


def _load_spacy_model(model: str) -> Any:
    if model not in _nlp_cache:
        try:
            import spacy
        except ImportError as exc:
            raise ImportError(
                "NER redaction requires: pip install iki-pii-masker[ner] "
                "&& python -m spacy download en_core_web_sm"
            ) from exc
        _nlp_cache[model] = spacy.load(model)
    return _nlp_cache[model]


class NERRedactStrategy(BaseMaskingStrategy):
    """
    Redact named entities inside a string using NER labels.

    Example
    -------
        "Hello Alice from Boston" -> "Hello [PERSON] from [LOCATION]"
    """

    def _apply(self, value: str, pii_type: Optional[PIIType],
               ctx: MaskingContext) -> str:
        nlp = _load_spacy_model("en_core_web_sm")
        doc = nlp(value)
        spans: list[tuple[int, int, str]] = []
        for ent in doc.ents:
            label = ent.label_
            if label in {"PERSON", "ORG", "GPE", "LOC", "NORP", "FAC"}:
                spans.append((ent.start_char, ent.end_char, f"[{label}]"))

        if not spans:
            return value

        result_parts: list[str] = []
        last = 0
        for start, end, replacement in spans:
            if start > last:
                result_parts.append(value[last:start])
            result_parts.append(replacement)
            last = end
        result_parts.append(value[last:])
        return "".join(result_parts)
