"""
config/profile.py
=================
ProfileConfig and ColumnRuleMap — load masking rules from a YAML file
or build them in Python, then apply them in a single call.

Install extra dependency (for YAML loading):
    pip install pyyaml

────────────────────────────────────────────────────────────────────
ColumnRuleMap
────────────────────────────────────────────────────────────────────
A typed dict mapping column names to ``Strategy`` values:

    from Iki_PII_Masker.facade import ColumnRuleMap, Strategy

    rules = ColumnRuleMap({
        "email":       Strategy.fake,
        "ssn":         Strategy.null,
        "credit_card": Strategy.partial,
        "user_id":     Strategy.hash,
    })
    rules.apply(adapter)

────────────────────────────────────────────────────────────────────
ProfileConfig
────────────────────────────────────────────────────────────────────
Load rules from a YAML file:

    # masking_profile.yaml
    # --------------------
    # engine: polars              # optional — overrides default
    # strategy: fake              # default strategy if column has none
    # seed: 42
    # salt: ""
    # partial_keep: 4
    # partial_side: right
    # columns:
    #   email:       fake
    #   ssn:         null
    #   credit_card: partial
    #   user_id:     hash
    #   full_name:   pseudonymize
    #   dob:         generalize
    # auto: true                  # also auto-detect additional PII columns

    from Iki_PII_Masker.facade import ProfileConfig

    profile = ProfileConfig.from_yaml("masking_profile.yaml")
    profile.apply(adapter)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .enums import Strategy, Engine


# ══════════════════════════════════════════════════════════════════════════════
# ColumnRuleMap
# ══════════════════════════════════════════════════════════════════════════════

class ColumnRuleMap(dict):
    """
    A ``dict[column_name, Strategy]`` with a convenience ``.apply()`` method.

    Example
    -------
        rules = ColumnRuleMap({"email": Strategy.fake, "ssn": Strategy.null})
        rules.apply(adapter, context=make_context(seed=42))
    """

    # ── constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: dict[str, str | Strategy]) -> "ColumnRuleMap":
        """Build from a plain dict mapping col → strategy string or enum."""
        return cls({
            col: Strategy(s) if isinstance(s, str) else s
            for col, s in data.items()
        })

    # ── apply ─────────────────────────────────────────────────────────────────

    def apply(
        self,
        adapter: Any,
        context: Any = None,
        *,
        dry_run:  bool = False,
        progress: bool = False,
    ) -> float:
        """
        Apply each column → strategy mapping to *adapter*.

        Returns elapsed seconds.  Requires the façade to be importable
        (avoids a circular import by importing inline).
        """
        from ..facade import mask_dataframe, make_context

        ctx = context or make_context()
        elapsed = 0.0
        for col, strategy in self.items():
            elapsed += mask_dataframe(
                adapter, col, strategy, ctx,
                dry_run=dry_run, progress=progress,
            )
        return elapsed


# ══════════════════════════════════════════════════════════════════════════════
# ProfileConfig
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProfileConfig:
    """
    Full masking profile loaded from a YAML file or built in Python.

    Fields
    ------
    columns       : mapping of column name → Strategy
    engine        : Engine to use  (default: polars)
    default_strategy : strategy for auto-detected columns not in ``columns``
    auto          : also auto-detect PII columns not listed in ``columns``
    seed          : RNG seed for reproducible fake data
    salt          : salt for hash strategy
    partial_keep  : chars to keep for partial strategy
    partial_side  : "right" | "left"
    """

    columns:          dict[str, Strategy] = field(default_factory=dict)
    engine:           Engine = Engine.polars
    default_strategy: Strategy = Strategy.redact
    auto:             bool = False
    seed:             Optional[int] = None
    salt:             str = ""
    partial_keep:     int = 4
    partial_side:     str = "right"

    # ── constructors ──────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ProfileConfig":
        """Load a ProfileConfig from a YAML file."""
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML is required for ProfileConfig.from_yaml().\n"
                "Install it with:  pip install pyyaml"
            )
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls._from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProfileConfig":
        """Build a ProfileConfig from a plain Python dict."""
        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> "ProfileConfig":
        raw_cols: dict[str, str] = data.get("columns", {}) or {}
        columns = {
            col: Strategy(s) if isinstance(s, str) else s
            for col, s in raw_cols.items()
        }
        return cls(
            columns=columns,
            engine=Engine(
                data["engine"]) if "engine" in data else Engine.polars,
            default_strategy=Strategy(
                data["strategy"]) if "strategy" in data else Strategy.redact,
            auto=bool(data.get("auto", False)),
            seed=data.get("seed"),
            salt=data.get("salt", ""),
            partial_keep=int(data.get("partial_keep", 4)),
            partial_side=data.get("partial_side", "right"),
        )

    # ── convenience builders ──────────────────────────────────────────────────

    def to_column_rule_map(self) -> ColumnRuleMap:
        """Return a ``ColumnRuleMap`` view of ``self.columns``."""
        return ColumnRuleMap(self.columns)

    def to_context(self) -> Any:
        """Build a ``MaskingContext`` from this profile's options."""
        from ..facade import make_context

        return make_context(
            salt=self.salt,
            seed=self.seed,
            partial_keep=self.partial_keep,
            partial_side=self.partial_side,
        )

    # ── apply ─────────────────────────────────────────────────────────────────

    def apply(
        self,
        adapter:  Any,
        *,
        dry_run:  bool = False,
        progress: bool = False,
    ) -> float:
        """
        Apply this profile to *adapter* in one call.

        Returns total elapsed seconds.
        """
        from ..facade import mask_dataframe, detect_pii

        ctx = self.to_context()
        elapsed = 0.0

        # ── explicit column rules ─────────────────────────────────────────────
        for col, strategy in self.columns.items():
            elapsed += mask_dataframe(
                adapter, col, strategy, ctx,
                dry_run=dry_run, progress=progress,
            )

        # ── auto-detect remaining PII ─────────────────────────────────────────
        if self.auto:
            already = set(self.columns.keys())
            detected = detect_pii(adapter.columns)
            extra = {c: s for c, s in detected.items() if c not in already}
            for col in extra:
                elapsed += mask_dataframe(
                    adapter, col, self.default_strategy, ctx,
                    dry_run=dry_run, progress=progress,
                )

        return elapsed

    # ── serialise ─────────────────────────────────────────────────────────────

    def to_yaml(self, path: str | Path) -> None:
        """Write this profile back to a YAML file."""
        try:
            import yaml
        except ImportError:
            raise ImportError("pip install pyyaml")

        data = {
            "engine":        self.engine.value,
            "strategy":      self.default_strategy.value,
            "auto":          self.auto,
            "seed":          self.seed,
            "salt":          self.salt,
            "partial_keep":  self.partial_keep,
            "partial_side":  self.partial_side,
            "columns":       {c: s.value for c, s in self.columns.items()},
        }
        Path(path).write_text(
            yaml.dump(data, default_flow_style=False), encoding="utf-8")

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine":        self.engine.value,
            "strategy":      self.default_strategy.value,
            "auto":          self.auto,
            "seed":          self.seed,
            "salt":          self.salt,
            "partial_keep":  self.partial_keep,
            "partial_side":  self.partial_side,
            "columns":       {c: s.value for c, s in self.columns.items()},
        }
