#!/usr/bin/env python3
"""
run_examples.py — Python code examples for every pii_masker feature.

Covers all strategies, all engines, reversible masking, pipe simulation,
auto-detect, dry-run, parquet, and the detect subcommand — all via the
Python API directly (no subprocess).

Usage:
    cd <project_root>
    python examples/run_examples.py

Prerequisites:
    pip install -e .
    python examples/generate_sample_data.py   # creates examples/data/sample.csv etc.
"""

from __future__ import annotations
from rich.rule import Rule
from rich.console import Console
from Iki_PII_Masker import (
    AdapterFactory,
    Engine,
    FileFormat,
    MaskingContext,
    MaskingService,
    PIIRegistry,
    Reporter,
    Strategy,
    derive_key,
    load_adapter,
    save_adapter,
)

import io
import sys
from pathlib import Path

# ── ensure project root is importable ────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


console = Console()
DATA = ROOT / "examples" / "data" / "sample.csv"
OUT = ROOT / "examples" / "output"
OUT.mkdir(parents=True, exist_ok=True)


# ── helpers ───────────────────────────────────────────────────────────────────

def section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/]", style="cyan"))


def show_csv_head(path: Path, rows: int = 3, cols: list[str] = None) -> None:
    """Print the first N rows of a CSV, optionally filtering columns."""
    import csv
    with open(path) as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= rows:
                break
            if cols:
                row = {k: v for k, v in row.items() if k in cols}
            console.print(f"  [dim]{dict(row)}[/]")


def mask_and_save(
    strategy:     Strategy,
    columns:      str,
    output_name:  str,
    engine:       Engine = Engine.polars,
    ctx:          MaskingContext = None,
    source:       Path = DATA,
    fmt:          FileFormat = FileFormat.csv,
) -> Path:
    """
    Core helper — load → mask → save.
    Returns the output path.
    """
    ctx = ctx or MaskingContext()
    out = OUT / output_name
    adapter = AdapterFactory.create(engine)

    load_adapter(adapter, source, fmt)

    svc = MaskingService(adapter, strategy, ctx)
    col_map = svc.resolve_columns(columns, auto=False)
    svc.run(col_map, dry_run=False, progress=False)

    save_adapter(adapter, out, None, fmt)
    return out


# ══════════════════════════════════════════════════════════════════════════════
# Example 1 — Detect PII columns
# ══════════════════════════════════════════════════════════════════════════════

def example_01_detect() -> None:
    section("01 · Detect PII columns")

    adapter = AdapterFactory.create(Engine.polars)
    load_adapter(adapter, DATA, FileFormat.csv)

    detected = PIIRegistry.detect(adapter.columns)

    console.print(f"  All columns   : {adapter.columns}")
    console.print(f"  Detected PII  : {list(detected.keys())}")

    Reporter.detect_report(adapter, detected, DATA, samples=2)


# ══════════════════════════════════════════════════════════════════════════════
# Example 2 — Redact with explicit columns
# ══════════════════════════════════════════════════════════════════════════════

def example_02_redact() -> None:
    section("02 · Redact explicit columns")

    out = mask_and_save(
        strategy=Strategy.redact,
        columns="email:full_name:phone",
        output_name="02_redacted.csv",
    )
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["email", "full_name", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 3 — Auto-detect + redact
# ══════════════════════════════════════════════════════════════════════════════

def example_03_auto_redact() -> None:
    section("03 · Auto-detect + redact")

    adapter = AdapterFactory.create(Engine.polars)
    load_adapter(adapter, DATA, FileFormat.csv)

    ctx = MaskingContext()
    svc = MaskingService(adapter, Strategy.redact, ctx)
    col_map = svc.resolve_columns(None, auto=True)   # auto=True

    console.print(f"  Auto-detected : {list(col_map.keys())}")

    svc.run(col_map, dry_run=False, progress=False)

    out = OUT / "03_auto_redacted.csv"
    save_adapter(adapter, out, None, FileFormat.csv)
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["email", "full_name", "id"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 4 — Fake data (realistic replacements)
# ══════════════════════════════════════════════════════════════════════════════

def example_04_fake() -> None:
    section("04 · Fake data — realistic replacements")

    out = mask_and_save(
        strategy=Strategy.fake,
        columns="email:full_name:phone",
        output_name="04_faked.csv",
        ctx=MaskingContext(seed=42),   # reproducible
    )
    console.print(f"  Output → {out.name}  (seed=42 → reproducible)")
    show_csv_head(out, cols=["email", "full_name", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 5 — Hash with salt
# ══════════════════════════════════════════════════════════════════════════════

def example_05_hash() -> None:
    section("05 · Hash with salt")

    out = mask_and_save(
        strategy=Strategy.hash,
        columns="user_id:email",
        output_name="05_hashed.csv",
        ctx=MaskingContext(salt="pepper_2024"),
    )
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["user_id", "email"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 6 — Partial masking (keep last 4 digits)
# ══════════════════════════════════════════════════════════════════════════════

def example_06_partial() -> None:
    section("06 · Partial masking — keep last 4 digits")

    out = mask_and_save(
        strategy=Strategy.partial,
        columns="credit_card:phone",
        output_name="06_partial.csv",
        ctx=MaskingContext(partial_keep=4, partial_side="right"),
    )
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["credit_card", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 7 — Null out columns
# ══════════════════════════════════════════════════════════════════════════════

def example_07_null() -> None:
    section("07 · Null out sensitive columns")

    out = mask_and_save(
        strategy=Strategy.null,
        columns="ssn:dob:password",
        output_name="07_nulled.csv",
    )
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["ssn", "dob", "password", "id"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 8 — Reversible masking + unmask
# ══════════════════════════════════════════════════════════════════════════════

def example_08_reversible() -> None:
    section("08 · Reversible masking (AES-256-GCM) + unmask")

    SECRET = "my-production-secret-2024"
    key_bytes = derive_key(SECRET)
    ctx = MaskingContext(reversible=True, key_bytes=key_bytes)

    # ── mask ─────────────────────────────────────────────────────────────────
    masked_path = mask_and_save(
        strategy=Strategy.redact,
        columns="email:user_id",
        output_name="08_reversible.csv",
        ctx=ctx,
    )
    console.print(f"  Masked → {masked_path.name}")
    show_csv_head(masked_path, cols=["email", "user_id"])

    # ── unmask ────────────────────────────────────────────────────────────────
    adapter = AdapterFactory.create(Engine.polars)
    load_adapter(adapter, masked_path, FileFormat.csv)

    for col in ["email", "user_id"]:
        adapter.apply_unmask(col, key_bytes)

    restored_path = OUT / "08_restored.csv"
    save_adapter(adapter, restored_path, None, FileFormat.csv)
    console.print(f"  Restored → {restored_path.name}")
    show_csv_head(restored_path, cols=["email", "user_id"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 9 — All three engines side-by-side
# ══════════════════════════════════════════════════════════════════════════════

def example_09_all_engines() -> None:
    section("09 · All engines — Polars / Pandas / DuckDB")

    import time

    for engine in [Engine.polars, Engine.pandas, Engine.duckdb]:
        t0 = time.perf_counter()
        out = mask_and_save(
            strategy=Strategy.redact,
            columns="email:full_name",
            output_name=f"09_engine_{engine.value}.csv",
            engine=engine,
        )
        elapsed = time.perf_counter() - t0
        console.print(f"  [{engine.value:6}]  {out.name}  {elapsed:.3f}s")


# ══════════════════════════════════════════════════════════════════════════════
# Example 10 — Parquet round-trip
# ══════════════════════════════════════════════════════════════════════════════

def example_10_parquet() -> None:
    section("10 · Parquet round-trip")

    src = ROOT / "examples" / "data" / "sample.parquet"
    out = OUT / "10_masked.parquet"

    adapter = AdapterFactory.create(Engine.polars)
    load_adapter(adapter, src, FileFormat.parquet)

    svc = MaskingService(adapter, Strategy.redact, MaskingContext())
    col_map = svc.resolve_columns(None, auto=True)
    svc.run(col_map, dry_run=False, progress=False)

    save_adapter(adapter, out, None, FileFormat.parquet)
    console.print(f"  Input  → sample.parquet  ({adapter.row_count()} rows)")
    console.print(f"  Output → {out.name}")

    # Reload and verify
    verify = AdapterFactory.create(Engine.polars)
    load_adapter(verify, out, FileFormat.parquet)
    console.print(f"  email after mask : {verify.sample_values('email', 2)}")


# ══════════════════════════════════════════════════════════════════════════════
# Example 11 — Stdin / stdout simulation (pipe)
# ══════════════════════════════════════════════════════════════════════════════

def example_11_pipe_simulation() -> None:
    section("11 · Pipe simulation (stdin → stdout)")

    # Read CSV into bytes (simulates: cat data.csv | pii_masker ...)
    raw_bytes = DATA.read_bytes()
    buf_in = io.BytesIO(raw_bytes)

    adapter = AdapterFactory.create(Engine.polars)
    adapter.load(buf_in, FileFormat.csv)

    svc = MaskingService(adapter, Strategy.fake, MaskingContext(seed=99))
    col_map = svc.resolve_columns("email:full_name", auto=False)
    svc.run(col_map, dry_run=False, progress=False)

    # Write to bytes buffer (simulates stdout)
    buf_out = io.BytesIO()
    adapter.save(buf_out, FileFormat.csv)

    # Show first 3 lines of the in-memory output
    lines = buf_out.getvalue().decode().splitlines()
    console.print("  In-memory CSV output (first 3 rows):")
    for line in lines[:4]:
        console.print(f"  [dim]{line}[/]")


# ══════════════════════════════════════════════════════════════════════════════
# Example 12 — Dry run with masking report
# ══════════════════════════════════════════════════════════════════════════════

def example_12_dry_run() -> None:
    section("12 · Dry run + masking report (no file written)")

    import time

    adapter = AdapterFactory.create(Engine.polars)
    load_adapter(adapter, DATA, FileFormat.csv)

    ctx = MaskingContext()
    svc = MaskingService(adapter, Strategy.fake, ctx)
    col_map = svc.resolve_columns(None, auto=True)

    t0 = time.perf_counter()
    svc.run(col_map, dry_run=True, progress=False)   # dry_run=True
    elapsed = time.perf_counter() - t0

    Reporter.masking_report(
        col_map, Strategy.fake,
        adapter.row_count(), elapsed, dry_run=True,
    )


# ══════════════════════════════════════════════════════════════════════════════
# Example 13 — Keep strategy (whitelist non-PII passthrough)
# ══════════════════════════════════════════════════════════════════════════════

def example_13_keep() -> None:
    section("13 · Keep strategy — passthrough (whitelist)")

    out = mask_and_save(
        strategy=Strategy.keep,
        columns="id:revenue:department",
        output_name="13_kept.csv",
    )
    console.print(f"  Output → {out.name}  (values unchanged)")
    show_csv_head(out, cols=["id", "revenue", "department"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 14 — Multiple strategies in one pipeline
# ══════════════════════════════════════════════════════════════════════════════

def example_14_multi_strategy_pipeline() -> None:
    section("14 · Multi-strategy pipeline (one adapter, multiple passes)")

    adapter = AdapterFactory.create(Engine.polars)
    load_adapter(adapter, DATA, FileFormat.csv)

    ctx = MaskingContext()

    # Pass 1 — fake: email + full_name
    svc1 = MaskingService(adapter, Strategy.fake, MaskingContext(seed=42))
    svc1.run(svc1.resolve_columns("email:full_name", auto=False),
             dry_run=False, progress=False)

    # Pass 2 — partial: credit_card (keep last 4)
    svc2 = MaskingService(adapter, Strategy.partial,
                          MaskingContext(partial_keep=4, partial_side="right"))
    svc2.run(svc2.resolve_columns("credit_card", auto=False),
             dry_run=False, progress=False)

    # Pass 3 — null: password + ssn
    svc3 = MaskingService(adapter, Strategy.null, ctx)
    svc3.run(svc3.resolve_columns("password:ssn", auto=False),
             dry_run=False, progress=False)

    out = OUT / "14_multi_strategy.csv"
    save_adapter(adapter, out, None, FileFormat.csv)
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["email", "full_name",
                  "credit_card", "password", "ssn"])


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

EXAMPLES = [
    example_01_detect,
    example_02_redact,
    example_03_auto_redact,
    example_04_fake,
    example_05_hash,
    example_06_partial,
    example_07_null,
    example_08_reversible,
    example_09_all_engines,
    example_10_parquet,
    example_11_pipe_simulation,
    example_12_dry_run,
    example_13_keep,
    example_14_multi_strategy_pipeline,
]


def main() -> None:
    if not DATA.exists():
        console.print("[bold red]Error:[/] Sample data not found.")
        console.print(
            "Run first:  [cyan]python examples/generate_sample_data.py[/]")
        sys.exit(1)

    console.print()
    console.print("[bold cyan]pii_masker[/] — Python API Examples")
    console.print(f"[dim]Source data : {DATA}[/]")
    console.print(f"[dim]Output dir  : {OUT}[/]")

    for fn in EXAMPLES:
        try:
            fn()
        except Exception as exc:
            console.print(f"  [bold red]✗ {fn.__name__} failed:[/] {exc}")
            raise

    console.print()
    console.print(
        f"[green]✓[/] All {len(EXAMPLES)} examples completed. "
        f"Output files in [cyan]{OUT.relative_to(ROOT)}[/]"
    )


if __name__ == "__main__":
    main()
