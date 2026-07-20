"""
config/value_detector.py
========================
ValuePatternDetector — scans actual cell values for PII patterns.
"""

from __future__ import annotations

import re
from typing import Any

from .registry import PIIType, PIIRegistry


VALUE_PATTERNS: dict[str, list[str]] = {
    "email": [
        r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"
    ],

    "ssn": [
        # With optional separators
        r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
    ],

    "credit_card": [
        # Strip spaces/dashes before matching (handled in code below)
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"
        r"5[1-5][0-9]{14}|"
        r"3[47][0-9]{13}|"
        r"6(?:011|5[0-9]{2})[0-9]{12}|"
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"
        r"(?:2131|1800|35\d{3})\d{11})\b",
    ],

    "ip": [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    ],

    "phone": [
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    ],

    "dob": [
        # ISO + common separators
        r"\b\d{4}[-/]\d{2}[-/]\d{2}\b",
        r"\b\d{2}[-/]\d{2}[-/]\d{4}\b",
        # Text formats (e.g. Jul 15, 1990)
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[\s.]\d{1,2},?\s\d{4}\b",
        r"\b\d{1,2}[-/\s](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-\s]\d{4}\b",
    ],

    "user_id": [
        # UUID
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    ],

    "credit_card": [
        # Strip spaces/dashes before matching (handled in code below)
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"                    # Visa
        r"5[1-5][0-9]{14}|"                           # Mastercard
        r"3[47][0-9]{13}|"                            # Amex
        r"6(?:011|5[0-9]{2})[0-9]{12}|"               # Discover
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"            # Diners Club
        r"(?:2131|1800|35\d{3})\d{11})\b"             # JCB
    ],

    "ip": [
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    ],

    "dob": [
        # ISO + common separators
        r"\b\d{4}[-/]\d{2}[-/]\d{2}\b",
        r"\b\d{2}[-/]\d{2}[-/]\d{4}\b",
        # Text formats (e.g. Jul 15, 1990)
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[\s.]\d{1,2},?\s\d{4}\b",
        r"\b\d{1,2}[-/\s](?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-\s]\d{4}\b",
    ],

    "user_id": [
        # UUID
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
    ],
}


_COMPILED: dict[str, list[re.Pattern]] = {
    name: [re.compile(p, re.IGNORECASE) for p in patterns]
    for name, patterns in VALUE_PATTERNS.items()
}


class ValuePatternDetector:
    """
    Scan sampled cell values for known PII patterns.
    """

    def __init__(self, sample_rows: int = 100, threshold: float = 0.3) -> None:
        self.sample_rows = sample_rows
        self.threshold = threshold

    def detect(
        self,
        columns: list[str],
        sample_fn: Any,
        existing: dict[str, PIIType] | None = None,
    ) -> dict[str, PIIType]:
        """
        Detect PII by scanning actual values.
        """
        already_found = set(existing.keys()) if existing else set()
        results: dict[str, PIIType] = {}

        for col in columns:
            if col in already_found:
                continue

            raw_values = [
                str(v) for v in sample_fn(col, self.sample_rows)
                if v is not None and str(v).strip()
            ]
            if not raw_values:
                continue

            for pii_name, compiled_patterns in _COMPILED.items():
                hit_count = 0

                for v in raw_values:
                    if isinstance(v, str) and v.startswith("ENC:"):
                        continue
                    test_value = v
                    if pii_name == "credit_card":
                        test_value = v.replace(" ", "").replace(
                            "-", "").replace("_", "")

                    if any(p.search(test_value) for p in compiled_patterns):
                        hit_count += 1

                ratio = hit_count / len(raw_values)
                if ratio >= self.threshold:
                    pii_type = PIIRegistry.get(pii_name)
                    if pii_type:
                        results[col] = pii_type
                    break

        return results
