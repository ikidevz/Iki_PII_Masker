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
from Iki_PII_Masker.facade import Strategy, Engine, FileFormat  # enum types
from Iki_PII_Masker.facade import report_detection, report_masking  # Rich output
from Iki_PII_Masker.facade import create_adapter        # polars/pandas/duckdb
from Iki_PII_Masker.facade import derive_encryption_key  # raw key bytes
from Iki_PII_Masker.facade import make_context, make_reversible_context  # contexts
from Iki_PII_Masker.facade import load_data, save_data  # file I/O
from Iki_PII_Masker.facade import unmask_dataframe      # reverse AES masking
from Iki_PII_Masker.facade import mask_dataframe        # apply any strategy
from Iki_PII_Masker.facade import detect_pii           # scan columns for PII

import io
import sys
import time
import csv
from pathlib import Path

from rich.console import Console
from rich.rule import Rule

# ── ensure project root is importable ────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── import by feature from the façade ────────────────────────────────────────

console = Console()
DATA = ROOT / "examples" / "data" / "sample.csv"
OUT = ROOT / "examples" / "output"
OUT.mkdir(parents=True, exist_ok=True)


# ── helpers ───────────────────────────────────────────────────────────────────

def section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/]", style="cyan"))


def show_csv_head(path: Path, rows: int = 3, cols: list[str] = None) -> None:
    with open(path) as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= rows:
                break
            if cols:
                row = {k: v for k, v in row.items() if k in cols}
            console.print(f"  [dim]{dict(row)}[/]")


# ══════════════════════════════════════════════════════════════════════════════
# Example 1 — Detect PII columns
# ══════════════════════════════════════════════════════════════════════════════

def example_01_detect() -> None:
    section("01 · Detect PII columns")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    detected = detect_pii(adapter.columns)

    console.print(f"  All columns   : {adapter.columns}")
    console.print(f"  Detected PII  : {list(detected.keys())}")

    report_detection(adapter, detected, DATA, samples=2)


# ══════════════════════════════════════════════════════════════════════════════
# Example 2 — Redact with explicit columns
# ══════════════════════════════════════════════════════════════════════════════

def example_02_redact() -> None:
    section("02 · Redact explicit columns")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:full_name:phone", Strategy.redact)

    out = OUT / "02_redacted.csv"
    save_data(adapter, out)
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["email", "full_name", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 3 — Auto-detect + redact
# ══════════════════════════════════════════════════════════════════════════════

def example_03_auto_redact() -> None:
    section("03 · Auto-detect + redact")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, None, Strategy.redact, auto=True)

    out = OUT / "03_auto_redacted.csv"
    save_data(adapter, out)
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["email", "full_name", "id"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 4 — Fake data (realistic replacements)
# ══════════════════════════════════════════════════════════════════════════════

def example_04_fake() -> None:
    section("04 · Fake data — realistic replacements")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:full_name:phone", Strategy.fake,
                   make_context(seed=42))

    out = OUT / "04_faked.csv"
    save_data(adapter, out)
    console.print(f"  Output → {out.name}  (seed=42 → reproducible)")
    show_csv_head(out, cols=["email", "full_name", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 5 — Hash with salt
# ══════════════════════════════════════════════════════════════════════════════

def example_05_hash() -> None:
    section("05 · Hash with salt")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "user_id:email", Strategy.hash,
                   make_context(salt="pepper_2024"))

    out = OUT / "05_hashed.csv"
    save_data(adapter, out)
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["user_id", "email"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 6 — Partial masking (keep last 4 digits)
# ══════════════════════════════════════════════════════════════════════════════

def example_06_partial() -> None:
    section("06 · Partial masking — keep last 4 digits")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "credit_card:phone", Strategy.partial,
                   make_context(partial_keep=4, partial_side="right"))

    out = OUT / "06_partial.csv"
    save_data(adapter, out)
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["credit_card", "phone"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 7 — Null out columns
# ══════════════════════════════════════════════════════════════════════════════

def example_07_null() -> None:
    section("07 · Null out sensitive columns")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "ssn:dob:password", Strategy.null)

    out = OUT / "07_nulled.csv"
    save_data(adapter, out)
    console.print(f"  Output → {out.name}")
    show_csv_head(out, cols=["ssn", "dob", "password", "id"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 8 — Reversible masking + unmask
# ══════════════════════════════════════════════════════════════════════════════

def example_08_reversible() -> None:
    section("08 · Reversible masking (AES-256-GCM) + unmask")

    SECRET = "my-production-secret-2024"

    # ── mask ─────────────────────────────────────────────────────────────────
    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "email:user_id", Strategy.redact,
                   make_reversible_context(SECRET))

    masked_path = OUT / "08_reversible.csv"
    save_data(adapter, masked_path)
    console.print(f"  Masked → {masked_path.name}")
    show_csv_head(masked_path, cols=["email", "user_id"])

    # ── unmask ────────────────────────────────────────────────────────────────
    key = derive_encryption_key(SECRET)
    adapter2 = create_adapter(Engine.polars)
    load_data(adapter2, masked_path)
    unmask_dataframe(adapter2, ["email", "user_id"], key)

    restored_path = OUT / "08_restored.csv"
    save_data(adapter2, restored_path)
    console.print(f"  Restored → {restored_path.name}")
    show_csv_head(restored_path, cols=["email", "user_id"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 9 — All three engines side-by-side
# ══════════════════════════════════════════════════════════════════════════════

def example_09_all_engines() -> None:
    section("09 · All engines — Polars / Pandas / DuckDB")

    for engine in [Engine.polars, Engine.pandas, Engine.duckdb]:
        t0 = time.perf_counter()
        adapter = create_adapter(engine)
        load_data(adapter, DATA)
        mask_dataframe(adapter, "email:full_name", Strategy.redact)

        out = OUT / f"09_engine_{engine.value}.csv"
        save_data(adapter, out)
        console.print(
            f"  [{engine.value:6}]  {out.name}  {time.perf_counter()-t0:.3f}s")


# ══════════════════════════════════════════════════════════════════════════════
# Example 10 — Parquet round-trip
# ══════════════════════════════════════════════════════════════════════════════

def example_10_parquet() -> None:
    section("10 · Parquet round-trip")

    src = ROOT / "examples" / "data" / "sample.parquet"
    adapter = create_adapter(Engine.polars)
    load_data(adapter, src, FileFormat.parquet)
    mask_dataframe(adapter, None, Strategy.redact, auto=True)

    out = OUT / "10_masked.parquet"
    save_data(adapter, out)
    console.print(f"  Input  → sample.parquet  ({adapter.row_count()} rows)")
    console.print(f"  Output → {out.name}")

    verify = create_adapter(Engine.polars)
    load_data(verify, out, FileFormat.parquet)
    console.print(f"  email after mask : {verify.sample_values('email', 2)}")


# ══════════════════════════════════════════════════════════════════════════════
# Example 11 — Stdin / stdout simulation (pipe)
# ══════════════════════════════════════════════════════════════════════════════

def example_11_pipe_simulation() -> None:
    section("11 · Pipe simulation (stdin → stdout)")

    buf_in = io.BytesIO(DATA.read_bytes())
    adapter = create_adapter(Engine.polars)
    load_data(adapter, buf_in, FileFormat.csv)
    mask_dataframe(adapter, "email:full_name", Strategy.fake,
                   make_context(seed=99))

    buf_out = io.BytesIO()
    save_data(adapter, buf_out, FileFormat.csv)

    lines = buf_out.getvalue().decode().splitlines()
    console.print("  In-memory CSV output (first 3 rows):")
    for line in lines[:4]:
        console.print(f"  [dim]{line}[/]")


# ══════════════════════════════════════════════════════════════════════════════
# Example 12 — Dry run with masking report
# ══════════════════════════════════════════════════════════════════════════════

def example_12_dry_run() -> None:
    section("12 · Dry run + masking report (no file written)")

    from Iki_PII_Masker.service import MaskingService   # needed for col_map only

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    ctx = make_context()
    svc = MaskingService(adapter, Strategy.fake, ctx)
    col_map = svc.resolve_columns(None, auto=True)

    t0 = time.perf_counter()
    mask_dataframe(adapter, None, Strategy.fake, ctx,
                   auto=True, dry_run=True)
    elapsed = time.perf_counter() - t0

    report_masking(adapter, col_map, Strategy.fake, elapsed, dry_run=True)


# ══════════════════════════════════════════════════════════════════════════════
# Example 13 — Keep strategy (whitelist non-PII passthrough)
# ══════════════════════════════════════════════════════════════════════════════

def example_13_keep() -> None:
    section("13 · Keep strategy — passthrough (whitelist)")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)
    mask_dataframe(adapter, "id:revenue:department", Strategy.keep)

    out = OUT / "13_kept.csv"
    save_data(adapter, out)
    console.print(f"  Output → {out.name}  (values unchanged)")
    show_csv_head(out, cols=["id", "revenue", "department"])


# ══════════════════════════════════════════════════════════════════════════════
# Example 14 — Multiple strategies in one pipeline
# ══════════════════════════════════════════════════════════════════════════════

def example_14_multi_strategy_pipeline() -> None:
    section("14 · Multi-strategy pipeline (one adapter, multiple passes)")

    adapter = create_adapter(Engine.polars)
    load_data(adapter, DATA)

    # Pass 1 — fake: email + full_name
    mask_dataframe(adapter, "email:full_name",
                   Strategy.fake, make_context(seed=42))

    # Pass 2 — partial: credit_card (keep last 4)
    mask_dataframe(adapter, "credit_card",
                   Strategy.partial, make_context(partial_keep=4, partial_side="right"))

    # Pass 3 — null: password + ssn
    mask_dataframe(adapter, "password:ssn", Strategy.null)

    out = OUT / "14_multi_strategy.csv"
    save_data(adapter, out)
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
