"""
Iki_PII_Masker.facade
=====================
Single-file façade — import by what the library *can do*.

    from Iki_PII_Masker.facade import detect_pii
    from Iki_PII_Masker.facade import detect_pii_by_value
    from Iki_PII_Masker.facade import mask_dataframe
    from Iki_PII_Masker.facade import unmask_dataframe
    from Iki_PII_Masker.facade import load_data, save_data
    from Iki_PII_Masker.facade import make_context, make_reversible_context
    from Iki_PII_Masker.facade import derive_encryption_key
    from Iki_PII_Masker.facade import create_adapter
    from Iki_PII_Masker.facade import create_sql_adapter
    from Iki_PII_Masker.facade import create_xml_adapter
    from Iki_PII_Masker.facade import create_jsonpath_adapter
    from Iki_PII_Masker.facade import report_detection, report_masking
    from Iki_PII_Masker.facade import ProfileConfig, ColumnRuleMap
    from Iki_PII_Masker.facade import Strategy, Engine, FileFormat

────────────────────────────────────────────────────────────────────
FEATURES AT A GLANCE
────────────────────────────────────────────────────────────────────

DETECT
  detect_pii(columns)
      Scan column *names* → {col: PIIType} for every PII match.

  detect_pii_by_value(adapter, sample_rows, threshold)
      Scan actual cell *values* → {col: PIIType}.
      Catches columns like "col_7" that hold SSNs but have generic names.

MASK
  mask_dataframe(adapter, columns, strategy, context, *, auto, dry_run, progress)
      Apply any strategy to named columns of a loaded adapter.
      Strategies: redact · fake · hash · partial · null · keep ·
                  tokenize · pseudonymize · generalize · mask_format

UNMASK
  unmask_dataframe(adapter, columns, key)
      Reverse AES-256-GCM masking. Requires the same key used during masking.

I/O
  load_data(adapter, source, fmt)    — CSV/Parquet/JSON/NDJSON/Excel/XML/BytesIO
  save_data(adapter, dest, fmt)      — file / BytesIO / stdout

CONTEXT
  make_context(**kwargs)             — plain (non-reversible) MaskingContext
  make_reversible_context(secret)    — AES-256-GCM reversible context

CRYPTO
  derive_encryption_key(secret)      — 32-byte AES key from a secret string

ADAPTERS
  create_adapter(engine)             — Polars / Pandas / DuckDB
  create_sql_adapter(url, table)     — live relational DB via SQLAlchemy
  create_xml_adapter(xpath, fields)  — XML document via XPath selectors
  create_jsonpath_adapter(paths)     — nested JSON via JSONPath expressions

PROFILES
  ProfileConfig.from_yaml(path)      — load masking rules from YAML
  ProfileConfig.from_dict(data)      — build from a Python dict
  ColumnRuleMap({col: Strategy})     — per-column strategy map with .apply()

REPORT
  report_detection(adapter, detected, file)
  report_masking(adapter, col_map, strategy, elapsed)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

# ── internal imports (the only place these appear in user-facing code) ─────────
from .config.enums import Strategy, Engine, FileFormat
from .config.registry import PIIType, PIIRegistry
from .config.crypto import derive_key
from .config.io import load_adapter as _load_adapter, save_adapter as _save_adapter
from .config.value_detector import ValuePatternDetector
from .config.ner_detector import detect_pii_by_ner as _detect_pii_by_ner
from .config.vault.factory import create_vault
from .config.keys.local_provider import LocalKeyProvider
from .strategies.base import MaskingContext
from .strategies.composite import CompositeStrategy
from .adapters.base import BaseDataFrameAdapter
from .adapters.factory import AdapterFactory
from .adapters.json_adapter import JSONPathAdapter
from .adapters.xml_adapter import XMLAdapter
from .service import MaskingService
from .reporter import Reporter


# ══════════════════════════════════════════════════════════════════════════════
# DETECT — column names
# ══════════════════════════════════════════════════════════════════════════════

def detect_pii(columns: list[str]) -> dict[str, PIIType]:
    """
    Scan *columns* against the built-in PII *name* pattern catalogue.

    Returns a dict mapping every column name that looks like PII to its
    inferred ``PIIType``.

    Example
    -------
        found = detect_pii(adapter.columns)
        # {"email": PIIType("email",...), "full_name": PIIType("name",...)}
    """
    return PIIRegistry.detect(columns)


# ══════════════════════════════════════════════════════════════════════════════
# DETECT — cell values
# ══════════════════════════════════════════════════════════════════════════════

def detect_pii_by_value(
    adapter:     BaseDataFrameAdapter,
    *,
    sample_rows: int = 100,
    threshold:   float = 0.3,
    existing:    dict[str, PIIType] | None = None,
) -> dict[str, PIIType]:
    """
    Scan actual cell *values* for PII patterns.

    Catches columns with generic names (``col_7``, ``field_2``) that
    still contain Social Security numbers, credit card numbers, emails, etc.

    Parameters
    ----------
    adapter      : a loaded adapter
    sample_rows  : rows to sample per column  (default 100)
    threshold    : fraction of sampled values that must match to flag  (0.3 = 30 %)
    existing     : name-based results to merge; already-detected cols are skipped

    Example
    -------
        name_based  = detect_pii(adapter.columns)
        value_based = detect_pii_by_value(adapter, existing=name_based)
        all_found   = {**name_based, **value_based}
    """
    detector = ValuePatternDetector(
        sample_rows=sample_rows, threshold=threshold)
    return detector.detect(
        columns=adapter.columns,
        sample_fn=adapter.sample_values,
        existing=existing,
    )


def detect_pii_by_ner(
    adapter:     BaseDataFrameAdapter,
    *,
    sample_rows: int = 100,
    threshold:   float = 0.3,
    model:       str = "en_core_web_sm",
    existing:    dict[str, PIIType] | None = None,
) -> dict[str, PIIType]:
    """
    Scan actual cell values for NER-detected PII in free-text-like columns.

    Returns the same shape as ``detect_pii_by_value`` so results can be merged.
    """
    return _detect_pii_by_ner(
        adapter,
        sample_rows=sample_rows,
        threshold=threshold,
        model=model,
        existing=existing,
    )


# ══════════════════════════════════════════════════════════════════════════════
# MASK
# ══════════════════════════════════════════════════════════════════════════════

def mask_dataframe(
    adapter:  BaseDataFrameAdapter,
    columns:  str | None,
    strategy: Strategy,
    context:  MaskingContext | None = None,
    *,
    auto:     bool = False,
    dry_run:  bool = False,
    progress: bool = False,
) -> float:
    """
    Apply *strategy* to *columns* in *adapter*.

    Parameters
    ----------
    adapter   : a loaded adapter
    columns   : colon-separated column names e.g. ``"email:phone:ssn"``
                Pass ``None`` with ``auto=True`` to auto-detect only.
    strategy  : Strategy.redact | .fake | .hash | .partial | .null | .keep
                           | .tokenize | .pseudonymize | .generalize | .mask_format
    context   : from ``make_context()`` or ``make_reversible_context()``
    auto      : also mask auto-detected PII columns
    dry_run   : simulate without modifying the adapter
    progress  : show a Rich progress bar

    Returns elapsed seconds.

    Example
    -------
        mask_dataframe(adapter, "email:full_name", Strategy.fake, make_context(seed=42))
        mask_dataframe(adapter, "dob:zip",         Strategy.generalize)
        mask_dataframe(adapter, "credit_card",     Strategy.mask_format)
        mask_dataframe(adapter, "user_id",         Strategy.tokenize)
        mask_dataframe(adapter, "email",           Strategy.pseudonymize)
    """
    ctx = context or MaskingContext()
    svc = MaskingService(adapter, strategy, ctx)
    col_map = svc.resolve_columns(columns, auto=auto)
    return svc.run(col_map, dry_run=dry_run, progress=progress)


# ══════════════════════════════════════════════════════════════════════════════
# UNMASK
# ══════════════════════════════════════════════════════════════════════════════

def unmask_dataframe(
    adapter: BaseDataFrameAdapter,
    columns: list[str],
    key:     bytes,
    *,
    kms_provider: str | None = None,
    kms_region: str | None = None,
    kms_encryption_context: dict[str, str] | None = None,
) -> None:
    """
    Reverse reversible masking for each column in *columns*.

    *key* must be the same bytes used during masking for AES-style
    reversible ciphers. For ``kms-envelope`` tokens, pass a KMS provider,
    region, and optional encryption context instead.

    Example
    -------
        key = derive_encryption_key("my-secret")
        unmask_dataframe(adapter, ["email", "user_id"], key)

        unmask_dataframe(
            adapter,
            ["email"],
            b"",
            kms_provider="aws",
            kms_region="us-east-1",
            kms_encryption_context={"purpose": "pii-mask"},
        )
    """
    for col in columns:
        adapter.apply_unmask(
            col,
            key,
            kms_provider=kms_provider,
            kms_region=kms_region,
            kms_encryption_context=kms_encryption_context,
        )


# ══════════════════════════════════════════════════════════════════════════════
# I/O
# ══════════════════════════════════════════════════════════════════════════════

def load_data(
    adapter: BaseDataFrameAdapter,
    source:  Any,
    fmt:     FileFormat | None = None,
) -> FileFormat:
    """
    Load *source* into *adapter*.

    *source* can be a ``Path``, string path, ``BytesIO``, or ``None`` (stdin).
    *fmt* is inferred from the file extension when omitted.

    Example
    -------
        load_data(adapter, Path("data.csv"))
        load_data(adapter, buf, FileFormat.csv)
    """
    src = Path(source) if isinstance(source, str) else source
    return _load_adapter(adapter, src, fmt)


def save_data(
    adapter:    BaseDataFrameAdapter,
    dest:       Any,
    fmt:        FileFormat | None = None,
    source_fmt: FileFormat | None = None,
) -> None:
    """
    Write *adapter* data to *dest*.

    *dest* can be a ``Path``, string path, ``BytesIO``, or ``None`` (stdout).

    Example
    -------
        save_data(adapter, Path("output.csv"))
        save_data(adapter, None, source_fmt=FileFormat.csv)  # stdout
    """
    out = Path(dest) if isinstance(dest, str) else dest
    _save_adapter(adapter, out, fmt, source_fmt)


# ══════════════════════════════════════════════════════════════════════════════
# CONTEXT
# ══════════════════════════════════════════════════════════════════════════════

def make_context(
    *,
    salt:               str = "",
    key:                str | bytes | None = None,
    key_bytes:          Any = None,
    seed:               Optional[int] = None,
    partial_keep:       int = 4,
    partial_side:       str = "right",
    truncate_keep:      int = 4,
    bucket_step:        int = 10,
    date_precision:     str = "year",
    anonymize_prefix:   str = "ANON",
    perturbation_scale: float = 0.1,
    perturbation_days:  int = 7,
    pbkdf2_iterations:  int = 100_000,
    reversible_cipher:  str = "aesgcm",
    kms_provider:       str | None = None,
    kms_region:         str | None = None,
    kms_key_id:         str | None = None,
    kms_encryption_context: dict[str, str] | None = None,
    token_vault:        Any | None = None,
    vault_namespace:    str = "default",
    key_provider:       Any | None = None,
) -> MaskingContext:
    """
    Build a plain (non-reversible) ``MaskingContext``.

    Example
    -------
        ctx = make_context(seed=42)
        ctx = make_context(salt="pepper", partial_keep=4)
        ctx = make_context(key="secret-key")
    """
    return MaskingContext(
        key=key,
        key_bytes=key_bytes,
        salt=salt,
        pbkdf2_iterations=pbkdf2_iterations,
        seed=seed,
        partial_keep=partial_keep,
        partial_side=partial_side,
        truncate_keep=truncate_keep,
        bucket_step=bucket_step,
        date_precision=date_precision,
        anonymize_prefix=anonymize_prefix,
        perturbation_scale=perturbation_scale,
        perturbation_days=perturbation_days,
        reversible_cipher=reversible_cipher,
        kms_provider=kms_provider,
        kms_region=kms_region,
        kms_key_id=kms_key_id,
        kms_encryption_context=kms_encryption_context,
        token_vault=token_vault,
        vault_namespace=vault_namespace,
        key_provider=key_provider,
    )


def make_reversible_context(secret: str, salt: bytes = b"", **kwargs: Any) -> MaskingContext:
    """
    Build a ``MaskingContext`` that AES-256-GCM encrypts every masked value.

    The key is derived from *secret* automatically.

    Example
    -------
        ctx = make_reversible_context("my-production-secret-2024")
        mask_dataframe(adapter, "email:user_id", Strategy.redact, ctx)
    """
    key = derive_key(secret, salt=salt)
    base = make_context(**kwargs)
    return MaskingContext(
        reversible=True,
        key_bytes=key,
        salt=base.salt,
        seed=base.seed,
        partial_keep=base.partial_keep,
        partial_side=base.partial_side,
        truncate_keep=base.truncate_keep,
        bucket_step=base.bucket_step,
        date_precision=base.date_precision,
        anonymize_prefix=base.anonymize_prefix,
        perturbation_scale=base.perturbation_scale,
        perturbation_days=base.perturbation_days,
        reversible_cipher=base.reversible_cipher,
        kms_provider=base.kms_provider,
        kms_region=base.kms_region,
        kms_key_id=base.kms_key_id,
        kms_encryption_context=base.kms_encryption_context,
        token_vault=base.token_vault,
        vault_namespace=base.vault_namespace,
        key_provider=base.key_provider,
    )


# ══════════════════════════════════════════════════════════════════════════════
# CRYPTO
# ══════════════════════════════════════════════════════════════════════════════

def derive_encryption_key(secret: str) -> bytes:
    """
    Derive a 32-byte AES-256 key from *secret*.

    Use when you need the raw key bytes for ``unmask_dataframe`` after
    loading a previously masked file.

    Example
    -------
        key = derive_encryption_key("my-production-secret-2024")
        unmask_dataframe(adapter, ["email"], key)
    """
    return derive_key(secret)


# ══════════════════════════════════════════════════════════════════════════════
# ADAPTERS — standard
# ══════════════════════════════════════════════════════════════════════════════

def create_adapter(engine: Engine | str = Engine.polars) -> BaseDataFrameAdapter:
    """
    Instantiate the right adapter for the given *engine*.

    Accepts ``Engine`` enum values or plain strings
    (``"polars"``, ``"pandas"``, ``"duckdb"``).

    Example
    -------
        adapter = create_adapter(Engine.polars)
        adapter = create_adapter("duckdb")
    """
    if isinstance(engine, str):
        engine = Engine(engine)
    return AdapterFactory.create(engine)


# ══════════════════════════════════════════════════════════════════════════════
# ADAPTERS — SQLAlchemy (live database)
# ══════════════════════════════════════════════════════════════════════════════

def create_sql_adapter(
    url:        str,
    table:      str,
    id_column:  str = "id",
    chunk_size: int = 500,
) -> BaseDataFrameAdapter:
    """
    Mask data in a live relational database table via SQLAlchemy.

    Requires:  ``pip install sqlalchemy``
    Plus the driver for your database:
        PostgreSQL → ``pip install psycopg2-binary``
        MySQL      → ``pip install pymysql``
        SQLite     → built-in, no extra install

    Parameters
    ----------
    url        : SQLAlchemy connection URL
                 ``"sqlite:///mydb.sqlite"``
                 ``"postgresql+psycopg2://user:pass@host/db"``
                 ``"mysql+pymysql://user:pass@host/db"``
    table      : table name to read and update
    id_column  : primary key column used in UPDATE WHERE clause  (default "id")
    chunk_size : rows per commit batch  (default 500)

    Usage
    -----
        adapter = create_sql_adapter("sqlite:///data.db", "users")
        mask_dataframe(adapter, "email:phone", Strategy.fake)
        save_data(adapter)   # writes UPDATEs back to the database
    """
    from .adapters.sqlalchemy_adapter import SQLAlchemyAdapter
    return SQLAlchemyAdapter(
        url=url, table=table, id_column=id_column, chunk_size=chunk_size
    )


# ══════════════════════════════════════════════════════════════════════════════
# ADAPTERS — XML
# ══════════════════════════════════════════════════════════════════════════════

def create_xml_adapter(
    xpath:      str = "//*",
    pii_fields: list[str] = None,
) -> BaseDataFrameAdapter:
    """
    Mask PII fields inside an XML document using XPath row selection.

    Parameters
    ----------
    xpath       : XPath expression selecting the repeating row elements
                  e.g. ``"//user"``, ``"//record"``, ``".//row"``
    pii_fields  : child element names (or attribute names) to treat as columns
                  e.g. ``["email", "phone", "full_name"]``

    Usage
    -----
        adapter = create_xml_adapter("//user", ["email", "phone"])
        load_data(adapter, Path("users.xml"))
        mask_dataframe(adapter, "email:phone", Strategy.fake)
        save_data(adapter, Path("masked.xml"))
    """
    return XMLAdapter(xpath=xpath, pii_fields=pii_fields or [])


# ══════════════════════════════════════════════════════════════════════════════
# ADAPTERS — JSONPath
# ══════════════════════════════════════════════════════════════════════════════

def create_jsonpath_adapter(paths: dict[str, str]) -> BaseDataFrameAdapter:
    """
    Mask values at JSONPath locations inside a nested JSON document.

    Requires:  ``pip install jsonpath-ng``

    Parameters
    ----------
    paths : mapping of logical column name → JSONPath expression
            e.g. ``{"email": "$.users[*].contact.email",
                    "phone": "$.users[*].contact.phone"}``

    Usage
    -----
        adapter = create_jsonpath_adapter({
            "email": "$.users[*].email",
            "phone": "$.users[*].phone",
        })
        load_data(adapter, Path("data.json"))
        mask_dataframe(adapter, "email:phone", Strategy.redact)
        save_data(adapter, Path("masked.json"))
    """

    return JSONPathAdapter(paths=paths)


# ══════════════════════════════════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════════════════════════════════

def report_detection(
    adapter:     BaseDataFrameAdapter,
    detected:    dict[str, PIIType],
    source_file: Optional[Path] = None,
    *,
    samples:     int = 3,
    source_labels: dict[str, str] | None = None,
) -> None:
    """
    Print a Rich table of detected PII columns with sample values.

    Example
    -------
        found = detect_pii(adapter.columns)
        report_detection(adapter, found, Path("data.csv"))
    """
    Reporter.detect_report(adapter, detected, source_file, samples,
                           source_labels=source_labels)


def report_masking(
    adapter:  BaseDataFrameAdapter,
    col_map:  dict[str, Optional[PIIType]],
    strategy: Strategy,
    elapsed:  float,
    *,
    dry_run:  bool = False,
) -> None:
    """
    Print a Rich masking-summary table.

    Example
    -------
        report_masking(adapter, col_map, Strategy.fake, elapsed)
    """
    Reporter.masking_report(
        col_map, strategy, adapter.row_count(), elapsed, dry_run)
