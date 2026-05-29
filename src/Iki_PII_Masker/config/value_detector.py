"""
config/value_detector.py
========================
ValuePatternDetector — scan actual cell *values* for PII patterns.

The existing ``PIIRegistry.detect()`` only matches column *names*
(e.g. a column named ``col_7`` is never flagged, even if it contains
Social Security numbers).  ``ValuePatternDetector`` adds a second pass
that samples cell values and runs regex patterns directly against them.

Usage
-----
    from Iki_PII_Masker.facade import detect_pii_by_value

    # adapter must already be loaded
    detected = detect_pii_by_value(adapter, sample_rows=50)
    # → {"col_7": PIIType("ssn", ...), "col_12": PIIType("email", ...)}

Design
------
Each ``PIIType`` stores column-name *patterns* already.  The value
detector uses a separate set of *value regexes* defined here.  If a
column matches a value pattern AND doesn't already appear in the
name-based results, it is added to the detection output.
"""

from __future__ import annotations

import re
from typing import Any

from .registry import PIIType, PIIRegistry


VALUE_PATTERNS: dict[str, list[str]] = {
    "email":       [r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"],
    "phone":       [r"\+?1?\s?[\(]?\d{3}[\)]?[\s.\-]?\d{3}[\s.\-]\d{4}"],
    "ssn":         [r"\b\d{3}-\d{2}-\d{4}\b"],
    "credit_card": [r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"],
    "ip":          [r"\b(?:\d{1,3}\.){3}\d{1,3}\b"],
    "dob":         [r"\b\d{4}[-/]\d{2}[-/]\d{2}\b",
                    r"\b\d{2}[-/]\d{2}[-/]\d{4}\b"],
    # UUID
    "user_id":     [r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"],
}

# Pre-compile
_COMPILED: dict[str, list[re.Pattern]] = {
    name: [re.compile(p, re.IGNORECASE) for p in patterns]
    for name, patterns in VALUE_PATTERNS.items()
}


class ValuePatternDetector:
    """
    Scan sampled cell values for known PII patterns.

    Parameters
    ----------
    sample_rows  : number of rows to sample per column  (default 100)
    threshold    : fraction of sampled non-null values that must match
                   before the column is flagged  (default 0.3 = 30 %)
    """

    def __init__(self, sample_rows: int = 100, threshold: float = 0.3) -> None:
        self.sample_rows = sample_rows
        self.threshold = threshold

    def detect(
        self,
        columns:     list[str],
        sample_fn:   Any,
        existing:    dict[str, PIIType] | None = None,
    ) -> dict[str, PIIType]:
        """
        Detect PII in cell values.

        Parameters
        ----------
        columns    : all column names in the adapter
        sample_fn  : ``adapter.sample_values`` — callable(col, n) → list of values
        existing   : result of name-based detection to merge/skip duplicates

        Returns
        -------
        dict mapping newly detected column names → PIIType.
        Already-detected columns are excluded from the return value but
        merged into the final result by the caller.
        """
        already_found = set(existing.keys()) if existing else set()
        results: dict[str, PIIType] = {}

        for col in columns:
            if col in already_found:
                continue

            values = [
                str(v) for v in sample_fn(col, self.sample_rows)
                if v is not None and str(v).strip()
            ]
            if not values:
                continue

            for pii_name, compiled_patterns in _COMPILED.items():
                hit_count = sum(
                    1 for v in values
                    if any(p.search(v) for p in compiled_patterns)
                )
                ratio = hit_count / len(values)
                if ratio >= self.threshold:
                    pii_type = PIIRegistry.get(pii_name)
                    if pii_type:
                        results[col] = pii_type
                    break

        return results
