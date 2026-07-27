#!/usr/bin/env python3
"""
run_examples.py — Python API examples for every pii_masker feature.

Usage:
    cd <project_root>
    python examples/run_examples.py

Prerequisites:
    pip install -e .
    pip install jsonpath-ng pyyaml          # for JSONPath and ProfileConfig examples
    python examples/generate_sample_data.py
"""

from __future__ import annotations

import csv
import io
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from rich.console import Console
from rich.rule import Rule

from Iki_PII_Masker import (
    ColumnRuleMap,
    Engine,
    FileFormat,
    MaskingContext,
    ProfileConfig,
    Strategy,
    create_adapter,
    create_jsonpath_adapter,
    create_sql_adapter,
    create_xml_adapter,
    decrypt_value,
    derive_encryption_key,
    detect_pii,
    detect_pii_by_value,
    encrypt_value,
    load_data,
    make_context,
    make_reversible_context,
    mask_dataframe,
    report_detection,
    report_masking,
    save_data,
    unmask_dataframe,
)
from Iki_PII_Masker.config.crypto import (
    derive_kdf_bytes,
    hash_value,
    hmac_value,
    normalize_hash_algorithm,
    normalize_hmac_algorithm,
    normalize_kdf_algorithm,
    normalize_signature_algorithm,
)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

# ── import every feature from the façade — one feature per import line ────────

console = Console()
DATA = ROOT / "examples" / "data" / "sample.csv"
OUT = ROOT / "examples" / "output"
OUT.mkdir(parents=True, exist_ok=True)


def section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/]", style="cyan"))


def show_csv_head(path: Path, rows: int = 3, cols: list[str] = None) -> None:
    with open(path) as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= rows:
                break
            display = {k: v for k, v in row.items(
            ) if k in cols} if cols else dict(row)
            console.print(f"  [dim]{display}[/]")


def _generate_rsa_key_pair() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return public_bytes, private_bytes


# ══════════════════════════════════════════════════════════════════════════════
# 01 — Detect PII by column name
# ══════════════════════════════════════════════════════════════════════════════

def example_01_detect_by_name() -> None:
    section("01 · Detect PII by column name")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    detected = detect_pii(adapter.columns)
    console.print(f"  Detected: {list(detected.keys())}")
    report_detection(adapter, detected, DATA, samples=2)


# ══════════════════════════════════════════════════════════════════════════════
# 02 — Detect PII by cell values (catches generic column names)
# ══════════════════════════════════════════════════════════════════════════════

def example_02_detect_by_value() -> None:
    section("02 · Detect PII by cell values")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    name_hits = detect_pii(adapter.columns)
    value_hits = detect_pii_by_value(
        adapter, sample_rows=50, existing=name_hits)
    all_found = {**name_hits, **value_hits}

    console.print(f"  Name-based  : {list(name_hits.keys())}")
    console.print(
        f"  Value-based : {list(value_hits.keys())}  (new finds only)")
    console.print(f"  Combined    : {list(all_found.keys())}")


# ══════════════════════════════════════════════════════════════════════════════
# 03 — Redact explicit columns
# ══════════════════════════════════════════════════════════════════════════════

def example_03_redact() -> None:
    section("03 · Redact explicit columns")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:full_name:phone", Strategy.redact)

    out = OUT / "03_redacted.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["email", "full_name", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# 04 — Fake data (random per row)
# ══════════════════════════════════════════════════════════════════════════════

def example_04_fake() -> None:
    section("04 · Fake data — random realistic replacements")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:full_name:phone", Strategy.fake,
                   make_context(seed=42))

    out = OUT / "04_faked.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["email", "full_name", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# 05 — Pseudonymize (consistent fake — same input → same output)
# ══════════════════════════════════════════════════════════════════════════════

def example_05_pseudonymize() -> None:
    section("05 · Pseudonymize — consistent fake (preserves referential integrity)")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:full_name", Strategy.pseudonymize,
                   make_context(seed=42))

    out = OUT / "05_pseudonymized.csv"
    save_data(adapter, out)
    console.print(
        "  Same input always → same fake output (check for repeated names):")
    show_csv_head(out, cols=["full_name", "email"])


# ══════════════════════════════════════════════════════════════════════════════
# 06 — Tokenize (stable opaque token, reversible via token_table)
# ══════════════════════════════════════════════════════════════════════════════

def example_06_tokenize() -> None:
    section("06 · Tokenize — stable opaque tokens")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "user_id:email", Strategy.tokenize)

    out = OUT / "06_tokenized.csv"
    save_data(adapter, out)
    console.print("  Values replaced with TOK-<hex> tokens:")
    show_csv_head(out, cols=["user_id", "email"])


# ══════════════════════════════════════════════════════════════════════════════
# 07 — Generalize (ranges / year buckets)
# ══════════════════════════════════════════════════════════════════════════════

def example_07_generalize() -> None:
    section("07 · Generalize — numeric ranges and date year buckets")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    # Numeric columns bucketed in steps of 10; dates truncated to year
    mask_dataframe(adapter, "age:revenue:dob", Strategy.generalize)

    out = OUT / "07_generalized.csv"
    save_data(adapter, out)
    console.print("  34 → '30-40',  1990-07-15 → '1990':")
    show_csv_head(out, cols=["age", "revenue", "dob"])


# ══════════════════════════════════════════════════════════════════════════════
# 08 — MaskFormat (preserve structure — separators kept)
# ══════════════════════════════════════════════════════════════════════════════

def example_08_mask_format() -> None:
    section("08 · MaskFormat — preserve structural separators")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:phone:credit_card", Strategy.mask_format)

    out = OUT / "08_mask_format.csv"
    save_data(adapter, out)
    console.print("  john@corp.com → xxxx@xxxx.xxx,  4111-1234 → ****-****:")
    show_csv_head(out, cols=["email", "phone", "credit_card"])


# ══════════════════════════════════════════════════════════════════════════════
# 09 — Hash with salt
# ══════════════════════════════════════════════════════════════════════════════

def example_09_hash() -> None:
    section("09 · Hash with salt")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "user_id:email", Strategy.hash,
                   make_context(salt="pepper_2024"))

    out = OUT / "09_hashed.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["user_id", "email"])


# ══════════════════════════════════════════════════════════════════════════════
# 10 — Partial (keep last 4)
# ══════════════════════════════════════════════════════════════════════════════

def example_10_partial() -> None:
    section("10 · Partial masking — keep last 4 digits")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "credit_card:phone", Strategy.partial,
                   make_context(partial_keep=4, partial_side="right"))

    out = OUT / "10_partial.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["credit_card", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# 11 — Null
# ══════════════════════════════════════════════════════════════════════════════

def example_11_null() -> None:
    section("11 · Null out sensitive columns")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "ssn:dob:password", Strategy.null)

    out = OUT / "11_nulled.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["ssn", "dob", "password", "id"])


# ══════════════════════════════════════════════════════════════════════════════
# 12 — Reversible masking + unmask
# ══════════════════════════════════════════════════════════════════════════════

def example_12_reversible() -> None:
    section("12 · Reversible AES-256-GCM masking + unmask")

    SECRET = "my-production-secret-2024"

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:user_id", Strategy.redact,
                   make_reversible_context(SECRET))

    masked_path = OUT / "12_reversible_masked.csv"
    save_data(adapter, masked_path)
    console.print(f"  Masked →")
    show_csv_head(masked_path, cols=["email", "user_id"])

    key = derive_encryption_key(SECRET)
    adapter2 = create_adapter(Engine.polars)
    load_data(adapter2, masked_path)
    unmask_dataframe(adapter2, ["email", "user_id"], key)

    restored_path = OUT / "12_reversible_restored.csv"
    save_data(adapter2, restored_path)
    console.print(f"  Restored →")
    show_csv_head(restored_path, cols=["email", "user_id"])


# ══════════════════════════════════════════════════════════════════════════════
# 13 — All three standard engines
# ══════════════════════════════════════════════════════════════════════════════

def example_13_all_engines() -> None:
    section("13 · All engines — Polars / Pandas / DuckDB")

    for engine in [Engine.polars, Engine.pandas, Engine.duckdb]:
        t0 = time.perf_counter()
        adapter = create_adapter(engine)
        load_data(adapter, DATA)
        mask_dataframe(adapter, "email:full_name", Strategy.redact)
        out = OUT / f"13_engine_{engine.value}.csv"
        save_data(adapter, out)
        console.print(
            f"  [{engine.value:6}]  {out.name}  {time.perf_counter()-t0:.3f}s")


# ══════════════════════════════════════════════════════════════════════════════
# 14 — SQLAlchemy adapter (SQLite in-memory)
# ══════════════════════════════════════════════════════════════════════════════

def example_14_sqlalchemy() -> None:
    section("14 · SQLAlchemy adapter — mask a live SQLite table")

    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        console.print("  [yellow]Skip[/] — pip install sqlalchemy")
        return

    import sqlite3
    import csv as csv_mod

    db_path = OUT / "14_sample.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, phone TEXT)")
    with open(DATA) as f:
        reader = csv_mod.DictReader(f)
        for i, row in enumerate(reader):
            if i >= 20:
                break
            conn.execute("INSERT INTO users VALUES (?,?,?)",
                         (i + 1, row.get("email", ""), row.get("phone", "")))
    conn.commit()
    conn.close()

    adapter = create_sql_adapter(f"sqlite:///{db_path}", "users")
    adapter.load()
    console.print(f"  Before: {adapter.sample_values('email', 2)}")

    mask_dataframe(adapter, "email:phone", Strategy.fake, make_context(seed=7))
    adapter.save()

    adapter2 = create_sql_adapter(f"sqlite:///{db_path}", "users")
    adapter2.load()
    console.print(f"  After : {adapter2.sample_values('email', 2)}")


# ══════════════════════════════════════════════════════════════════════════════
# 15 — XML adapter
# ══════════════════════════════════════════════════════════════════════════════

def example_15_xml() -> None:
    section("15 · XML adapter — XPath-based masking")

    xml_in = OUT / "15_users.xml"
    xml_in.write_text("""<?xml version="1.0"?>
<users>
  <user><email>alice@example.com</email><phone>+1-555-0100</phone><name>Alice Smith</name></user>
  <user><email>bob@corp.org</email><phone>+1-555-0101</phone><name>Bob Jones</name></user>
  <user><email>carol@test.net</email><phone>+1-555-0102</phone><name>Carol White</name></user>
</users>""", encoding="utf-8")

    adapter = create_xml_adapter("//user", ["email", "phone", "name"])
    load_data(adapter, xml_in)
    console.print(f"  Rows found: {adapter.row_count()}")
    console.print(f"  Before email: {adapter.sample_values('email', 2)}")

    mask_dataframe(adapter, "email:phone:name",
                   Strategy.fake, make_context(seed=1))

    xml_out = OUT / "15_masked.xml"
    save_data(adapter, xml_out)
    console.print(f"  After  email: {adapter.sample_values('email', 2)}")
    console.print(f"  Output → {xml_out.name}")


# ══════════════════════════════════════════════════════════════════════════════
# 16 — JSONPath adapter
# ══════════════════════════════════════════════════════════════════════════════

def example_16_jsonpath() -> None:
    section("16 · JSONPath adapter — nested JSON masking")

    try:
        import jsonpath_ng  # noqa: F401
    except ImportError:
        console.print("  [yellow]Skip[/] — pip install jsonpath-ng")
        return

    json_in = OUT / "16_users.json"
    json_in.write_text(json.dumps({
        "users": [
            {"id": 1, "contact": {"email": "alice@example.com", "phone": "+1-555-0100"}},
            {"id": 2, "contact": {"email": "bob@corp.org",      "phone": "+1-555-0101"}},
            {"id": 3, "contact": {"email": "carol@test.net",    "phone": "+1-555-0102"}},
        ]
    }, indent=2), encoding="utf-8")

    adapter = create_jsonpath_adapter({
        "email": "$.users[*].contact.email",
        "phone": "$.users[*].contact.phone",
    })
    load_data(adapter, json_in)
    console.print(f"  Before: {adapter.sample_values('email', 2)}")

    mask_dataframe(adapter, "email:phone", Strategy.redact)

    json_out = OUT / "16_masked.json"
    save_data(adapter, json_out)
    console.print(f"  After : {adapter.sample_values('email', 2)}")
    console.print(f"  Output → {json_out.name}")


# ══════════════════════════════════════════════════════════════════════════════
# 17 — ColumnRuleMap (per-column strategy in Python)
# ══════════════════════════════════════════════════════════════════════════════

def example_17_column_rule_map() -> None:
    section("17 · ColumnRuleMap — per-column strategy map")

    rules = ColumnRuleMap({
        "email":       Strategy.fake,
        "full_name":   Strategy.pseudonymize,
        "credit_card": Strategy.partial,
        "ssn":         Strategy.null,
        "user_id":     Strategy.hash,
    })

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    rules.apply(adapter, make_context(seed=42))

    out = OUT / "17_column_rule_map.csv"
    save_data(adapter, out)
    console.print(f"  Applied {len(rules)} column rules:")
    for col, strat in rules.items():
        console.print(f"    {col:15} → {strat.value}")
    show_csv_head(out, cols=list(rules.keys()))


# ══════════════════════════════════════════════════════════════════════════════
# 18 — ProfileConfig from dict
# ══════════════════════════════════════════════════════════════════════════════

def example_18_profile_from_dict() -> None:
    section("18 · ProfileConfig — load rules from a dict")

    profile = ProfileConfig.from_dict({
        "engine":   "polars",
        "strategy": "redact",
        "seed":     42,
        "auto":     True,
        "columns": {
            "email":       "fake",
            "full_name":   "pseudonymize",
            "credit_card": "partial",
            "ssn":         "null",
        },
    })

    adapter = create_adapter(profile.engine)
    load_data(adapter, DATA)
    profile.apply(adapter)

    out = OUT / "18_profile_dict.csv"
    save_data(adapter, out)
    console.print(f"  Profile columns : {list(profile.columns.keys())}")
    console.print(f"  Auto-detect     : {profile.auto}")
    show_csv_head(out, cols=["email", "full_name", "credit_card", "ssn"])


# ══════════════════════════════════════════════════════════════════════════════
# 19 — ProfileConfig from YAML file
# ══════════════════════════════════════════════════════════════════════════════

def example_19_profile_from_yaml() -> None:
    section("19 · ProfileConfig — load rules from YAML file")

    try:
        import yaml  # noqa: F401
    except ImportError:
        console.print("  [yellow]Skip[/] — pip install pyyaml")
        return

    yaml_path = OUT / "19_masking_profile.yaml"
    ProfileConfig.from_dict({
        "engine":   "polars",
        "strategy": "redact",
        "seed":     99,
        "auto":     False,
        "columns": {
            "email":     "fake",
            "phone":     "mask_format",
            "dob":       "generalize",
            "user_id":   "tokenize",
        },
    }).to_yaml(yaml_path)

    console.print(f"  Profile written → {yaml_path.name}")
    console.print(f"  Contents:\n{yaml_path.read_text()}")

    profile = ProfileConfig.from_yaml(yaml_path)
    adapter = create_adapter(profile.engine)
    load_data(adapter, DATA)
    profile.apply(adapter)

    out = OUT / "19_profile_yaml.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["email", "phone", "dob", "user_id"])


# ══════════════════════════════════════════════════════════════════════════════
# 20 — Pipe simulation (BytesIO)
# ══════════════════════════════════════════════════════════════════════════════

def example_20_pipe() -> None:
    section("20 · Pipe simulation — BytesIO in-memory")

    buf_in = io.BytesIO(DATA.read_bytes())
    adapter = create_adapter(Engine.polars)
    load_data(adapter, buf_in, FileFormat.csv)
    mask_dataframe(adapter, "email:full_name",
                   Strategy.fake, make_context(seed=99))

    buf_out = io.BytesIO()
    save_data(adapter, buf_out, FileFormat.csv)

    lines = buf_out.getvalue().decode().splitlines()
    console.print("  In-memory CSV (first 3 lines):")
    for line in lines[:4]:
        console.print(f"  [dim]{line}[/]")


# ══════════════════════════════════════════════════════════════════════════════
# 21 — Dry run + masking report
# ══════════════════════════════════════════════════════════════════════════════

def example_21_dry_run() -> None:
    section("21 · Dry run + masking report")

    from Iki_PII_Masker.service import MaskingService

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    ctx = make_context()
    svc = MaskingService(adapter, Strategy.fake, ctx)
    col_map = svc.resolve_columns(None, auto=True)

    t0 = time.perf_counter()
    mask_dataframe(adapter, None, Strategy.fake, ctx,
                   auto=True, dry_run=True, progress=True)
    elapsed = time.perf_counter() - t0

    report_masking(adapter, col_map, Strategy.fake, elapsed, dry_run=True)


# ══════════════════════════════════════════════════════════════════════════════
# 22 — Multi-strategy pipeline on one adapter
# ══════════════════════════════════════════════════════════════════════════════

def example_22_multi_strategy() -> None:
    section("22 · Multi-strategy pipeline — one adapter, multiple passes")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    mask_dataframe(adapter, "email:full_name",
                   Strategy.pseudonymize, make_context(seed=42))
    mask_dataframe(adapter, "credit_card",      Strategy.mask_format)
    mask_dataframe(adapter, "dob:age",          Strategy.generalize)
    mask_dataframe(adapter, "user_id",          Strategy.tokenize)
    mask_dataframe(adapter, "password:ssn",     Strategy.null)

    out = OUT / "22_multi_strategy.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["email", "full_name",
                  "credit_card", "dob", "user_id", "ssn"])


# ══════════════════════════════════════════════════════════════════════════════
# 23 — Keep strategy (explicit pass-through)
# ══════════════════════════════════════════════════════════════════════════════

def example_23_keep_strategy() -> None:
    section("23 · Keep strategy — preserve selected columns explicitly")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:full_name:phone", Strategy.keep)

    out = OUT / "23_keep.csv"
    save_data(adapter, out)
    console.print(
        "  Values are preserved exactly as-is; this is useful when you want"
        " explicit column inclusion without transformation.")
    show_csv_head(out, cols=["email", "full_name", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# 24 — HMAC hashing with a secret key
# ══════════════════════════════════════════════════════════════════════════════

def example_24_hash_with_secret_key() -> None:
    section("24 · Hash with secret key — HMAC-SHA256 strengthens hashing")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    ctx = make_context(key="super_secret_hash_key_2026")
    mask_dataframe(adapter, "user_id:email", Strategy.hash, ctx)

    out = OUT / "24_hashed_with_key.csv"
    save_data(adapter, out)
    console.print("  HashStrategy now uses an explicit secret key for HMAC.")
    show_csv_head(out, cols=["user_id", "email"])


# ══════════════════════════════════════════════════════════════════════════════
# 25 — PBKDF2 hashing
# ══════════════════════════════════════════════════════════════════════════════

def example_25_pbkdf2_hash() -> None:
    section("25 · PBKDF2 hashing — key-stretched one-way hash")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    ctx = make_context(
        key="super_secret_pbkdf2_key_2026",
        pbkdf2_iterations=5_000,
    )
    mask_dataframe(adapter, "user_id:email", Strategy.pbkdf2, ctx)

    out = OUT / "25_pbkdf2.csv"
    save_data(adapter, out)
    console.print(
        "  PBKDF2 produces a strong one-way hash using a secret key.")
    show_csv_head(out, cols=["user_id", "email"])


# ══════════════════════════════════════════════════════════════════════════════
# 26 — Direct cryptography helpers
# ══════════════════════════════════════════════════════════════════════════════

def example_26_direct_crypto_helpers() -> None:
    section("26 · Direct cryptography helpers — AES-GCM encode/decode")

    secret = "my-crypto-secret-2026"
    key = derive_encryption_key(secret)
    sample_value = "alice@example.com"
    encrypted = encrypt_value(sample_value, key)
    decrypted = decrypt_value(encrypted, key)

    console.print(f"  Original : {sample_value}")
    console.print(f"  Encrypted: {encrypted}")
    console.print(f"  Decrypted: {decrypted}")

    if decrypted != sample_value:
        raise RuntimeError("Direct crypto helper round-trip failed")


def example_27_truncate() -> None:
    section("27 · Truncate — preserve prefix, discard remainder")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:full_name", Strategy.truncate,
                   make_context(truncate_keep=6))

    out = OUT / "27_truncate.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["email", "full_name"])


def example_28_salted_hash() -> None:
    section("28 · Salted hash — stable one-way hash with a secret key")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    ctx = make_context(key="salted-secret-2026")
    mask_dataframe(adapter, "user_id:email", Strategy.salted_hash, ctx)

    out = OUT / "28_salted_hash.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["user_id", "email"])


def example_29_hmac_hash() -> None:
    section("29 · HMAC hash — keyed deterministic hashing")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    ctx = make_context(key="hmac-secret-2026")
    mask_dataframe(adapter, "user_id:email", Strategy.hmac, ctx)

    out = OUT / "29_hmac_hash.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["user_id", "email"])


def example_30_shuffle() -> None:
    section("30 · Shuffle — randomize values within a column")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email", Strategy.shuffle,
                   make_context(seed=123))

    out = OUT / "30_shuffled.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["email"])


def example_31_anonymize() -> None:
    section("31 · Anonymize — generic anonymous placeholders")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "full_name:email", Strategy.anonymize,
                   make_context(seed=24))

    out = OUT / "31_anonymized.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["full_name", "email"])


def example_32_perturb() -> None:
    section("32 · Perturb — slight noise for analytics-safe values")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    ctx = make_context(perturbation_scale=0.15, perturbation_days=14, seed=5)
    mask_dataframe(adapter, "age:revenue", Strategy.perturb, ctx)

    out = OUT / "32_perturbed.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["age", "revenue"])


def example_33_bucketize() -> None:
    section("33 · Bucketize — coarse value ranges")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    ctx = make_context(bucket_step=20)
    mask_dataframe(adapter, "age", Strategy.bucketize, ctx)

    out = OUT / "33_bucketize.csv"
    save_data(adapter, out)
    show_csv_head(out, cols=["age"])


def example_34_reversible_cipher_choice() -> None:
    section("34 · Reversible cipher choice — ChaCha20-Poly1305")

    SECRET = "chacha-secret-2026"
    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email", Strategy.redact,
                   make_reversible_context(SECRET,
                                           reversible_cipher="chacha20-poly1305"))

    masked_path = OUT / "34_reversible_chacha.csv"
    save_data(adapter, masked_path)
    console.print("  Masked →")
    show_csv_head(masked_path, cols=["email"])

    key = derive_encryption_key(SECRET)
    adapter2 = create_adapter(Engine.polars)
    load_data(adapter2, masked_path)
    unmask_dataframe(adapter2, ["email"], key)

    restored_path = OUT / "34_reversible_chacha_restored.csv"
    save_data(adapter2, restored_path)
    console.print("  Restored →")
    show_csv_head(restored_path, cols=["email"])


def example_35_reversible_cipher_variants() -> None:
    section(
        "35 · Reversible cipher variants — AES / ChaCha20 / Ascon / RSA / ECIES / FF1 / FF3-1"
    )

    variants = [
        ("aes-ccm", "35_reversible_aes_ccm.csv", "email"),
        ("aes-siv", "35_reversible_aes_siv.csv", "email"),
        ("aes-cbc-hmac", "35_reversible_aes_cbc_hmac.csv", "email"),
        ("rsa-oaep", "35_reversible_rsa_oaep.csv", "email"),
        ("ecies", "35_reversible_ecies.csv", "email"),
        ("ff1", "35_reversible_ff1.csv", "user_id"),
        ("ff3-1", "35_reversible_ff3.csv", "user_id"),
        ("aes-256-gcm", "35_reversible_aes_256_gcm.csv", "email"),
        ("aes-192-gcm", "35_reversible_aes_192_gcm.csv", "email"),
        ("aes-128-gcm", "35_reversible_aes_128_gcm.csv", "email"),
        ("aes-256-ccm", "35_reversible_aes_256_ccm.csv", "email"),
        ("aes-192-ccm", "35_reversible_aes_192_ccm.csv", "email"),
        ("aes-128-ccm", "35_reversible_aes_128_ccm.csv", "email"),
        ("aes-256-gcm-siv", "35_reversible_aes_256_gcm_siv.csv", "email"),
        ("aes-siv", "35_reversible_aes_siv.csv", "email"),
        ("ascon-128", "35_reversible_ascon_128.csv", "email"),
        ("ascon-128a", "35_reversible_ascon_128a.csv", "email"),
        ("chacha20-poly1305", "35_reversible_chacha20_poly1305.csv", "email"),
        ("xsalsa20-poly1305", "35_reversible_xsalsa20_poly1305.csv", "email"),
        ("xchacha20-poly1305", "35_reversible_xchacha20_poly1305.csv", "email"),
    ]

    for cipher_name, filename, column in variants:
        console.print(f"  [cyan]{cipher_name}[/]")
        adapter = create_adapter(Engine.polars)
        load_data(adapter, DATA)

        try:
            if cipher_name == "rsa-oaep":
                public_key, private_key = _generate_rsa_key_pair()
                ctx = MaskingContext(
                    reversible=True,
                    key_bytes=public_key,
                    reversible_cipher=cipher_name,
                )
                unmask_key = private_key
            elif cipher_name == "ecies":
                try:
                    from ecies.keys.private import PrivateKey
                except ImportError as exc:
                    raise ImportError(
                        "ECIES support requires the optional 'eciespy' dependency."
                    ) from exc
                private_key = PrivateKey("secp256k1")
                public_key = private_key.public_key
                ctx = MaskingContext(
                    reversible=True,
                    key_bytes=public_key.to_hex().encode(),
                    reversible_cipher=cipher_name,
                )
                unmask_key = private_key.to_hex().encode()
            else:
                ctx = make_reversible_context(
                    "variant-secret-2026",
                    reversible_cipher=cipher_name,
                )
                unmask_key = derive_encryption_key("variant-secret-2026")

            mask_dataframe(adapter, column, Strategy.redact, ctx)
            masked_path = OUT / filename
            save_data(adapter, masked_path)
            console.print(f"    Masked → {masked_path.name}")

            adapter2 = create_adapter(Engine.polars)
            load_data(adapter2, masked_path)
            unmask_dataframe(adapter2, [column], unmask_key)

            restored_path = OUT / f"{filename[:-4]}_restored.csv"
            save_data(adapter2, restored_path)
            console.print(f"    Restored → {restored_path.name}")
        except ImportError as exc:
            console.print(f"    [yellow]Skip {cipher_name} — {exc}[/]")
        except Exception as exc:
            console.print(f"    [yellow]Skip {cipher_name} — {exc}[/]")


def example_36_ner_redact() -> None:
    section("36 · NER redaction — free-text entity masking")

    try:
        import spacy  # noqa: F401
    except ImportError:
        console.print(
            "  [yellow]Skip[/] — install spaCy and a model: pip install spacy && python -m spacy download en_core_web_sm"
        )
        return

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "notes", Strategy.ner_redact)

    out = OUT / "36_ner_redacted.csv"
    save_data(adapter, out)
    console.print("  Notes after NER redaction:")
    show_csv_head(out, cols=["notes"])


def example_37_kms_envelope() -> None:
    section("37 · KMS envelope — advanced optional KMS integration")

    try:
        import boto3  # noqa: F401
    except ImportError:
        console.print(
            "  [yellow]Skip[/] — pip install .[kms] or pip install boto3")
        return

    console.print(
        "  AWS KMS envelope masking is supported by the CLI and requires")
    console.print("  a configured AWS environment and a valid KMS key.")
    console.print("  Example command:")
    console.print("  pii_masker mask data.csv")
    console.print("      --columns email:user_id")
    console.print("      --reversible")
    console.print("      --reversible-cipher kms-envelope")
    console.print("      --kms-provider aws")
    console.print("      --kms-key-id alias/my-key")
    console.print("      --kms-region us-east-1")
    console.print("      --kms-encryption-context purpose=pii-mask")
    console.print("      -o output.csv")
    console.print("  To restore:")
    console.print("  pii_masker unmask output.csv")
    console.print("      --columns email:user_id")
    console.print("      --kms-provider aws")
    console.print("      --kms-region us-east-1")
    console.print("      --kms-encryption-context purpose=pii-mask")
    console.print("      -o restored.csv")


def example_38_algorithm_aliases() -> None:
    section(
        "38 · Algorithm aliases — new cipher / hash / HMAC / KDF / signature support")

    key = derive_encryption_key("demo-alias-secret")
    cipher_names = [
        "aes-256-gcm",
        "aes-192-gcm",
        "aes-128-gcm",
        "aes-256-ccm",
        "aes-192-ccm",
        "aes-128-ccm",
        "aes-256-gcm-siv",
        "aes-siv",
        "ascon-128",
        "ascon-128a",
        "chacha20-poly1305",
        "xsalsa20-poly1305",
        "xchacha20-poly1305",
    ]
    for cipher_name in cipher_names:
        token = encrypt_value("alice@example.com", key, cipher_name)
        round_trip = decrypt_value(token, key)
        console.print(
            f"  [cyan]{cipher_name}[/] → round-trip {'ok' if round_trip == 'alice@example.com' else 'failed'}"
        )

    hash_examples = [
        ("sha3-256", "sha3-256"),
        ("sha512-256", "sha512-256"),
        ("xxh3-64", "xxh3-64"),
        ("blake3", "blake3"),
    ]
    for raw_name, display_name in hash_examples:
        normalized = normalize_hash_algorithm(raw_name)
        digest = hash_value("alice@example.com", algorithm=raw_name)
        console.print(
            f"  [green]hash[/] {display_name} → {normalized} ({digest[:16]}...)")

    hmac_examples = [
        ("hmac-sha3-256", "hmac-sha3-256"),
        ("hmac-blake2s", "hmac-blake2s"),
    ]
    for raw_name, display_name in hmac_examples:
        normalized = normalize_hmac_algorithm(raw_name)
        digest = hmac_value("alice@example.com",
                            b"shared-secret", algorithm=raw_name)
        console.print(
            f"  [green]hmac[/] {display_name} → {normalized} ({digest[:16]}...)")

    kdf_examples = [
        ("pbkdf2-sha512-256", "pbkdf2-sha512-256"),
        ("scrypt", "scrypt"),
    ]
    for raw_name, display_name in kdf_examples:
        normalized = normalize_kdf_algorithm(raw_name)
        derived = derive_kdf_bytes(
            "demo-secret", algorithm=raw_name, length=16)
        console.print(
            f"  [green]kdf[/] {display_name} → {normalized} ({derived.hex()[:24]}...)"
        )

    signature_examples = ["rsa-pss", "ed25519", "ml-dsa-44"]
    for raw_name in signature_examples:
        normalized = normalize_signature_algorithm(raw_name)
        console.print(f"  [green]signature[/] {raw_name} → {normalized}")


# ══════════════════════════════════════════════════════════════════════════════
# 39 — StrategyFactory — stateless vs stateful caching
# ══════════════════════════════════════════════════════════════════════════════

def example_39_strategy_factory() -> None:
    section("39 · StrategyFactory — stateless vs stateful caching")

    from Iki_PII_Masker.strategies.factory import StrategyFactory

    console.print("  [bold]Stateless Strategies (cached as singletons):[/]")
    # Stateless strategies return the same cached instance
    redact1 = StrategyFactory.create(Strategy.redact)
    redact2 = StrategyFactory.create(Strategy.redact)
    is_same = redact1 is redact2
    console.print(
        f"    Strategy.redact:  instance 1 is instance 2 = {is_same} (cached)")

    hash1 = StrategyFactory.create(Strategy.hash)
    hash2 = StrategyFactory.create(Strategy.hash)
    is_same = hash1 is hash2
    console.print(
        f"    Strategy.hash:    instance 1 is instance 2 = {is_same} (cached)")

    console.print(
        "  [bold]Stateful Strategies (fresh instances each time):[/]")
    # Stateful strategies return fresh instances
    tok1 = StrategyFactory.create(Strategy.tokenize)
    tok2 = StrategyFactory.create(Strategy.tokenize)
    is_same = tok1 is tok2
    console.print(
        f"    Strategy.tokenize:    instance 1 is instance 2 = {is_same} (fresh)")

    pseudo1 = StrategyFactory.create(Strategy.pseudonymize)
    pseudo2 = StrategyFactory.create(Strategy.pseudonymize)
    is_same = pseudo1 is pseudo2
    console.print(
        f"    Strategy.pseudonymize: instance 1 is instance 2 = {is_same} (fresh)")

    console.print("  [bold]Performance Benefit:[/]")
    console.print(f"    Stateless strategies avoid re-initialization overhead")
    console.print(f"    Stateful strategies prevent cross-job state leakage")

    console.print("  [bold]Reset Cache:[/]")
    StrategyFactory.reset()
    redact3 = StrategyFactory.create(Strategy.redact)
    is_same = redact1 is redact3
    console.print(f"    After reset, new instance created = {not is_same}")


# ══════════════════════════════════════════════════════════════════════════════
# 40 — FormatRegistry — file format detection from extension
# ══════════════════════════════════════════════════════════════════════════════

def example_40_format_registry() -> None:
    section("40 · FormatRegistry — file format detection from extension")

    from Iki_PII_Masker.strategies.factory import FormatRegistry

    console.print("  [bold]Format Detection by Extension:[/]")
    test_files = [
        "data.csv",
        "data.parquet",
        "data.json",
        "data.ndjson",
        "data.xlsx",
        "data.xml",
        "data.feather",
        "data.orc",
        "data.pkl",
        "data.html",
    ]

    for filename in test_files:
        path = Path(filename)
        try:
            fmt = FormatRegistry.detect(path)
            console.print(f"    {filename:20} → {fmt.value:12} ✓")
        except SystemExit:
            console.print(f"    {filename:20} → error")

    console.print("  [bold]Supported Extensions Mapping:[/]")
    ext_samples = {
        ".csv": "CSV",
        ".parquet": "Apache Parquet",
        ".json": "JSON",
        ".ndjson/.jsonl": "JSON Lines",
        ".xlsx/.xls": "Excel",
        ".feather/.arrow": "Apache Feather",
        ".orc": "Apache ORC",
        ".pkl": "Python Pickle",
        ".xml": "XML",
    }
    for ext, desc in ext_samples.items():
        console.print(f"    {ext:20} → {desc}")


# ══════════════════════════════════════════════════════════════════════════════
# 41 — Adapter Pattern — engine selection and format routing
# ══════════════════════════════════════════════════════════════════════════════

def example_41_adapter_pattern() -> None:
    section("41 · Adapter Pattern — engine selection and format routing")

    console.print("  [bold]DataFrame Engines:[/]")
    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    console.print(f"    Engine.polars → {adapter.__class__.__name__}")
    console.print(
        f"      Columns: {len(adapter.columns)}, Rows: {adapter.row_count()}")

    adapter = create_adapter(Engine.pandas)
    load_data(adapter, DATA)
    console.print(f"    Engine.pandas → {adapter.__class__.__name__}")
    console.print(
        f"      Columns: {len(adapter.columns)}, Rows: {adapter.row_count()}")

    adapter = create_adapter(Engine.duckdb)
    load_data(adapter, DATA)
    console.print(f"    Engine.duckdb → {adapter.__class__.__name__}")
    console.print(
        f"      Columns: {len(adapter.columns)}, Rows: {adapter.row_count()}")

    console.print("  [bold]Format-Specific Unsupported Combinations:[/]")
    console.print("    Polars:")
    console.print(
        "      ✗ ORC, Pickle, HTML, HDF5, Stata, SPSS, SAS (pandas-only)")
    console.print("      ✓ Avro, Delta, ODS (read-only)")

    console.print("    Pandas:")
    console.print("      ✗ Avro, Delta (Polars-native)")
    console.print(
        "      ✓ All pandas-native formats (CSV, Parquet, Excel, ORC, etc.)")

    console.print("  [bold]Adapter Masking Capabilities:[/]")
    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    original = adapter.sample_values("email", 2)
    console.print(f"    Before mask: {original}")

    mask_dataframe(adapter, "email", Strategy.redact)
    masked = adapter.sample_values("email", 2)
    console.print(f"    After mask:  {masked}")
    console.print(f"    Masking applied via adapter interface ✓")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

EXAMPLES = [
    example_01_detect_by_name,
    example_02_detect_by_value,
    example_03_redact,
    example_04_fake,
    example_05_pseudonymize,
    example_06_tokenize,
    example_07_generalize,
    example_08_mask_format,
    example_09_hash,
    example_10_partial,
    example_11_null,
    example_12_reversible,
    example_13_all_engines,
    example_14_sqlalchemy,
    example_15_xml,
    example_16_jsonpath,
    example_17_column_rule_map,
    example_18_profile_from_dict,
    example_19_profile_from_yaml,
    example_20_pipe,
    example_21_dry_run,
    example_22_multi_strategy,
    example_23_keep_strategy,
    example_24_hash_with_secret_key,
    example_25_pbkdf2_hash,
    example_26_direct_crypto_helpers,
    example_27_truncate,
    example_28_salted_hash,
    example_29_hmac_hash,
    example_30_shuffle,
    example_31_anonymize,
    example_32_perturb,
    example_33_bucketize,
    example_34_reversible_cipher_choice,
    example_35_reversible_cipher_variants,
    example_36_ner_redact,
    example_37_kms_envelope,
    example_38_algorithm_aliases,
    example_39_strategy_factory,
    example_40_format_registry,
    example_41_adapter_pattern,
]


def main() -> None:
    if not DATA.exists():
        console.print("[bold red]Error:[/] Sample data not found.")
        console.print("Run:  [cyan]python examples/generate_sample_data.py[/]")
        sys.exit(1)

    console.print()
    console.print("[bold cyan]pii_masker[/] — Python API Examples")
    console.print(f"[dim]Source : {DATA}[/]")
    console.print(f"[dim]Output : {OUT}[/]")

    for fn in EXAMPLES:
        try:
            fn()
        except Exception as exc:
            console.print(f"  [bold red]✗ {fn.__name__} failed:[/] {exc}")
            raise

    console.print()
    console.print(
        f"[green]✓[/] All {len(EXAMPLES)} examples done. "
        f"Output in [cyan]{OUT.relative_to(ROOT)}[/]"
    )


if __name__ == "__main__":
    main()
