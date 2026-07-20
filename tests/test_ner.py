import builtins
import types
import sys
from typing import Any

import pytest

from Iki_PII_Masker.config import ner_detector
from Iki_PII_Masker.config.ner_detector import detect_pii_by_ner
from Iki_PII_Masker.facade import PIIRegistry
from Iki_PII_Masker.strategies import ner_redact
from Iki_PII_Masker.strategies.ner_redact import NERRedactStrategy
from Iki_PII_Masker.strategies.base import MaskingContext


def _clear_spacy_cache() -> None:
    ner_detector._nlp_cache.clear()


class DummyAdapter:
    def __init__(self, columns: list[str], values: dict[str, list[str]]):
        self.columns = columns
        self._values = values

    def sample_values(self, col: str, n: int) -> list[str]:
        return self._values.get(col, [])[:n]


def test_detect_pii_by_ner_raises_helpful_error_when_spacy_missing(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name: str, globals: Any = None, locals: Any = None,
                    fromlist: tuple[str, ...] = (), level: int = 0):
        if name == "spacy":
            raise ImportError("No module named spacy")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    adapter = DummyAdapter(
        ["notes"], {"notes": ["Alice went to Paris yesterday"]})

    with pytest.raises(ImportError, match=r"NER detection requires: pip install iki-pii-masker\[ner\]"):
        detect_pii_by_ner(adapter, sample_rows=1, threshold=0.1)


def test_detect_pii_by_ner_returns_person_type_for_mocked_entities(monkeypatch):
    class FakeEntity:
        def __init__(self, label: str) -> None:
            self.label_ = label

    class FakeDoc:
        def __init__(self, text: str) -> None:
            self.ents = [FakeEntity("PERSON")]

    class FakeNLP:
        def __call__(self, text: str) -> FakeDoc:
            return FakeDoc(text)

        def pipe(self, values: list[str], disable: list[str] | None = None):
            for value in values:
                yield FakeDoc(value)

    fake_spacy = types.SimpleNamespace(load=lambda model: FakeNLP())
    monkeypatch.setitem(sys.modules, "spacy", fake_spacy)
    _clear_spacy_cache()

    adapter = DummyAdapter(
        ["notes"], {"notes": ["Alice went to Paris yesterday"]})
    detected = detect_pii_by_ner(adapter, sample_rows=1, threshold=0.1)

    assert detected == {"notes": PIIRegistry.get("person")}


def test_ner_redact_strategy_replaces_mocked_entities(monkeypatch):
    class FakeEntity:
        def __init__(self, start: int, end: int, label: str) -> None:
            self.start_char = start
            self.end_char = end
            self.label_ = label

    class FakeDoc:
        def __init__(self, text: str) -> None:
            self.ents = [FakeEntity(0, 5, "PERSON"), FakeEntity(14, 20, "GPE")]

    class FakeNLP:
        def __call__(self, text: str) -> FakeDoc:
            return FakeDoc(text)

    monkeypatch.setattr(ner_redact, "_load_spacy_model",
                        lambda model: FakeNLP())

    strategy = NERRedactStrategy()
    ctx = MaskingContext()
    result = strategy.mask("Alice went to Paris", None, ctx)

    assert result == "[PERSON] went to [GPE]"


def test_ner_redact_strategy_leaves_text_unchanged_when_no_entities(monkeypatch):
    class FakeDoc:
        def __init__(self, text: str) -> None:
            self.ents = []

    class FakeNLP:
        def __call__(self, text: str) -> FakeDoc:
            return FakeDoc(text)

    monkeypatch.setattr(ner_redact, "_load_spacy_model",
                        lambda model: FakeNLP())

    strategy = NERRedactStrategy()
    ctx = MaskingContext()
    result = strategy.mask("Plain text without names", None, ctx)

    assert result == "Plain text without names"
