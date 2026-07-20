"""
config/ner_detector.py
======================
NER-based detection for free-text PII columns.
"""

from __future__ import annotations

from typing import Any

from .registry import PIIRegistry, PIIType

_nlp_cache: dict[str, Any] = {}

NER_TO_PII = {
    "PERSON": "person",
    "ORG": "organization",
    "GPE": "location",
    "LOC": "location",
    "NORP": "organization",
    "FAC": "organization",
    "PRODUCT": "misc",
    "EVENT": "misc",
    "WORK_OF_ART": "misc",
    "LAW": "misc",
    "LANGUAGE": "misc",
}


def _load_spacy_model(model: str) -> Any:
    if model not in _nlp_cache:
        try:
            import spacy
        except ImportError as exc:
            raise ImportError(
                "NER detection requires: pip install iki-pii-masker[ner] "
                "&& python -m spacy download en_core_web_sm"
            ) from exc

        try:
            _nlp_cache[model] = spacy.load(model)
        except OSError as exc:
            raise OSError(
                f"spaCy model '{model}' is not installed. "
                "Install it with: python -m spacy download en_core_web_sm"
            ) from exc
    return _nlp_cache[model]


def detect_pii_by_ner(
    adapter: Any,
    *,
    sample_rows: int = 100,
    model: str = "en_core_web_sm",
    threshold: float = 0.3,
    existing: dict[str, PIIType] | None = None,
) -> dict[str, PIIType]:
    """
    Scan free-text-like columns for NER-detected entities.

    Returns a dict mapping inferred PII columns to the best-matching PIIType.
    """
    existing = existing or {}
    already_found = set(existing.keys())
    candidate_columns: dict[str, list[str]] = {}

    for col in adapter.columns:
        if col in already_found:
            continue

        values = [
            str(v) for v in adapter.sample_values(col, sample_rows)
            if v is not None and str(v).strip()
        ]
        if not values:
            continue

        avg_len = sum(len(v) for v in values) / len(values)
        if avg_len < 20:
            continue

        candidate_columns[col] = values

    if not candidate_columns:
        return {}

    nlp = _load_spacy_model(model)
    results: dict[str, PIIType] = {}

    for col, values in candidate_columns.items():
        entity_counts: dict[str, int] = {}

        for doc in nlp.pipe(values, disable=["tagger", "parser", "attribute_ruler"]):
            for ent in doc.ents:
                pii_name = NER_TO_PII.get(ent.label_)
                if pii_name:
                    entity_counts[pii_name] = entity_counts.get(
                        pii_name, 0) + 1

        if not entity_counts:
            continue

        total = len(values)
        best_match, hits = max(entity_counts.items(), key=lambda item: item[1])
        if hits / total < threshold:
            continue

        pii_type = PIIRegistry.get(best_match)
        if pii_type is not None:
            results[col] = pii_type

    return results
