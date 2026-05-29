from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

# ── internal imports (the only place in user-facing code these appear) ─────────
from .config.enums import Strategy, Engine, FileFormat
from .config.registry import PIIType, PIIRegistry
from .config.crypto import derive_key, encrypt_value, decrypt_value
from .config.io import load_adapter as _load_adapter, save_adapter as _save_adapter
from .strategies.base import MaskingContext
from .adapters.base import BaseDataFrameAdapter
from .adapters.factory import AdapterFactory
from .service import MaskingService
from .reporter import Reporter


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: detect PII columns
# ══════════════════════════════════════════════════════════════════════════════

def detect_pii(columns: list[str]) -> dict[str, PIIType]:
    """
    Scan *columns* against the built-in PII pattern catalogue.

    Returns a dict mapping every column name that looks like PII to its
    inferred ``PIIType`` (email, phone, name, ssn, credit_card, …).

    Example
    -------
        from Iki_PII_Masker.facade import detect_pii

        found = detect_pii(adapter.columns)
        # {"email": PIIType("email", ...), "full_name": PIIType("name", ...)}
    """
    return PIIRegistry.detect(columns)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: mask data
# ══════════════════════════════════════════════════════════════════════════════

def mask_dataframe(
    adapter:   BaseDataFrameAdapter,
    columns:   str | None,
    strategy:  Strategy,
    context:   MaskingContext | None = None,
    *,
    auto:      bool = False,
    dry_run:   bool = False,
    progress:  bool = False,
) -> float:
    """
    Apply *strategy* to *columns* in *adapter*.

    Parameters
    ----------
    adapter   : a loaded adapter (from ``create_adapter`` + ``load_data``)
    columns   : colon-separated column names, e.g. ``"email:phone:ssn"``
                Pass ``None`` together with ``auto=True`` to auto-detect.
    strategy  : ``Strategy.redact`` | ``Strategy.fake`` | ``Strategy.hash``
                | ``Strategy.partial`` | ``Strategy.null`` | ``Strategy.keep``
    context   : built by ``make_context()`` or ``make_reversible_context()``;
                defaults to a plain MaskingContext() if omitted
    auto      : if ``True``, also mask auto-detected PII columns
    dry_run   : simulate the run without modifying the adapter
    progress  : show a Rich progress bar (only when stderr is a tty)

    Returns
    -------
    float — elapsed seconds

    Example
    -------
        from Iki_PII_Masker.facade import mask_dataframe, Strategy

        elapsed = mask_dataframe(adapter, "email:full_name", Strategy.fake)
    """
    ctx = context or MaskingContext()
    svc = MaskingService(adapter, strategy, ctx)
    col_map = svc.resolve_columns(columns, auto=auto)
    return svc.run(col_map, dry_run=dry_run, progress=progress)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: unmask (reverse AES-256-GCM masking)
# ══════════════════════════════════════════════════════════════════════════════

def unmask_dataframe(
    adapter:  BaseDataFrameAdapter,
    columns:  list[str],
    key:      bytes,
) -> None:
    """
    Reverse AES-256-GCM masking for each column in *columns*.

    *key* must be the same bytes used during masking (from
    ``derive_encryption_key`` or ``make_reversible_context``).

    Example
    -------
        from Iki_PII_Masker.facade import unmask_dataframe, derive_encryption_key

        key = derive_encryption_key("my-secret")
        unmask_dataframe(adapter, ["email", "user_id"], key)
    """
    for col in columns:
        adapter.apply_unmask(col, key)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: load data into an adapter
# ══════════════════════════════════════════════════════════════════════════════

def load_data(
    adapter: BaseDataFrameAdapter,
    source:  Any,                       # Path | str | BytesIO | None (stdin)
    fmt:     FileFormat | None = None,
) -> FileFormat:
    """
    Load *source* into *adapter*.

    *source* can be a ``Path``, a file-path string, a ``BytesIO`` buffer
    (for in-memory / pipe use), or ``None`` to read from stdin.

    *fmt* is optional when *source* is a ``Path`` — the format is inferred
    from the file extension automatically.

    Returns the resolved ``FileFormat``.

    Example
    -------
        from Iki_PII_Masker.facade import load_data, FileFormat

        load_data(adapter, Path("data.csv"))
        load_data(adapter, buf_in, FileFormat.csv)   # BytesIO pipe
    """
    src = Path(source) if isinstance(source, str) else source
    return _load_adapter(adapter, src, fmt)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: save data from an adapter
# ══════════════════════════════════════════════════════════════════════════════

def save_data(
    adapter:    BaseDataFrameAdapter,
    dest:       Any,                    # Path | str | BytesIO | None (stdout)
    fmt:        FileFormat | None = None,
    source_fmt: FileFormat | None = None,
) -> None:
    """
    Write *adapter* data to *dest*.

    *dest* can be a ``Path``, a file-path string, a ``BytesIO`` buffer,
    or ``None`` to write to stdout.

    *fmt* defaults to the same format used during loading (*source_fmt*)
    or is inferred from the *dest* extension.

    Example
    -------
        from Iki_PII_Masker.facade import save_data

        save_data(adapter, Path("output.csv"))
        save_data(adapter, buf_out, FileFormat.csv)   # in-memory
        save_data(adapter, None, source_fmt=FileFormat.csv)  # stdout
    """
    out = Path(dest) if isinstance(dest, str) else dest
    _save_adapter(adapter, out, fmt, source_fmt)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: build a masking context
# ══════════════════════════════════════════════════════════════════════════════

def make_context(
    *,
    salt:          str = "",
    seed:          Optional[int] = None,
    partial_keep:  int = 4,
    partial_side:  str = "right",
) -> MaskingContext:
    """
    Build a plain (non-reversible) ``MaskingContext``.

    Parameters
    ----------
    salt          : added to every value before hashing (``Strategy.hash``)
    seed          : fixed random seed for reproducible fake data
    partial_keep  : number of characters to keep for ``Strategy.partial``
    partial_side  : ``"right"`` (keep last N) or ``"left"`` (keep first N)

    Example
    -------
        from Iki_PII_Masker.facade import make_context

        ctx = make_context(seed=42)                          # reproducible fakes
        ctx = make_context(salt="pepper", partial_keep=4)   # hash + partial
    """
    return MaskingContext(
        salt=salt,
        seed=seed,
        partial_keep=partial_keep,
        partial_side=partial_side,
    )


def make_reversible_context(
    secret: str,
    **kwargs: Any,
) -> MaskingContext:
    """
    Build a ``MaskingContext`` that encrypts every masked value with
    AES-256-GCM so it can be recovered later via ``unmask_dataframe``.

    The key is derived from *secret* automatically.  Any additional
    keyword arguments are forwarded to ``make_context``.

    Example
    -------
        from Iki_PII_Masker.facade import make_reversible_context, mask_dataframe

        ctx = make_reversible_context("my-production-secret-2024")
        mask_dataframe(adapter, "email:user_id", Strategy.redact, ctx)
    """
    key = derive_key(secret)
    base = make_context(**kwargs)
    return MaskingContext(
        reversible=True,
        key_bytes=key,
        salt=base.salt,
        seed=base.seed,
        partial_keep=base.partial_keep,
        partial_side=base.partial_side,
    )


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: derive an encryption key
# ══════════════════════════════════════════════════════════════════════════════

def derive_encryption_key(secret: str) -> bytes:
    """
    Derive a 32-byte AES-256 key from an arbitrary *secret* string.

    Use this when you need the raw key bytes — e.g. to call
    ``unmask_dataframe`` after loading a previously masked file.

    Example
    -------
        from Iki_PII_Masker.facade import derive_encryption_key, unmask_dataframe

        key = derive_encryption_key("my-production-secret-2024")
        unmask_dataframe(adapter, ["email"], key)
    """
    return derive_key(secret)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: create a data adapter
# ══════════════════════════════════════════════════════════════════════════════

def create_adapter(engine: Engine | str = Engine.polars) -> BaseDataFrameAdapter:
    """
    Instantiate the right adapter for the given *engine*.

    *engine* can be an ``Engine`` enum value or a plain string
    (``"polars"``, ``"pandas"``, ``"duckdb"``).

    Polars  — best general-purpose choice; fast, low memory
    Pandas  — use when the rest of your pipeline is already pandas
              or when reading Excel files (.xlsx)
    DuckDB  — use for files larger than RAM (streaming scans)

    Example
    -------
        from Iki_PII_Masker.facade import create_adapter, Engine

        adapter = create_adapter(Engine.polars)
        adapter = create_adapter("duckdb")
    """
    if isinstance(engine, str):
        engine = Engine(engine)
    return AdapterFactory.create(engine)


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE: report results
# ══════════════════════════════════════════════════════════════════════════════

def report_detection(
    adapter:     BaseDataFrameAdapter,
    detected:    dict[str, PIIType],
    source_file: Optional[Path] = None,
    *,
    samples:     int = 3,
) -> None:
    """
    Print a Rich table showing every column, its detected PII type, and
    sample values.  Suggests a CLI command for the detected columns.

    Example
    -------
        from Iki_PII_Masker.facade import detect_pii, report_detection

        found = detect_pii(adapter.columns)
        report_detection(adapter, found, Path("data.csv"), samples=2)
    """
    Reporter.detect_report(adapter, detected, source_file, samples)


def report_masking(
    adapter:   BaseDataFrameAdapter,
    col_map:   dict[str, Optional[PIIType]],
    strategy:  Strategy,
    elapsed:   float,
    *,
    dry_run:   bool = False,
) -> None:
    """
    Print a Rich masking-summary table with column names, PII types,
    strategy used, rows affected, and elapsed time.

    Example
    -------
        from Iki_PII_Masker.facade import report_masking, Strategy

        report_masking(adapter, col_map, Strategy.fake, elapsed)
    """
    Reporter.masking_report(
        col_map, strategy, adapter.row_count(), elapsed, dry_run)


# ── raw types re-exported for type hints & isinstance checks ──────────────────
__all__ = [
    # features
    "detect_pii",
    "mask_dataframe",
    "unmask_dataframe",
    "load_data",
    "save_data",
    "make_context",
    "make_reversible_context",
    "derive_encryption_key",
    "create_adapter",
    "report_detection",
    "report_masking",
    # types / enums (needed for arguments)
    "Strategy",
    "Engine",
    "FileFormat",
    "PIIType",
    "PIIRegistry",
    "MaskingContext",
    "BaseDataFrameAdapter",
]
