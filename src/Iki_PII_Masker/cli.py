from __future__ import annotations
import argparse

from pathlib import Path
from rich.console import Console
from .config import Strategy, Engine, FileFormat, derive_key, PIIRegistry, exit_error
from .strategies import MaskingContext
from .adapters import AdapterFactory
from .service import MaskingService
from .config.io import load_adapter, save_adapter
from .reporter import Reporter

console = Console(stderr=True)


# ── parser builders ───────────────────────────────────────────────────────────

def _add_engine_fmt(p: argparse.ArgumentParser) -> None:
    """Common --engine / --format flags shared by all subcommands."""
    p.add_argument(
        "--engine", "-e",
        choices=[e.value for e in Engine],
        default=Engine.polars.value,
        help="DataFrame engine (default: polars).",
    )
    p.add_argument(
        "--format", "-f",
        dest="fmt",
        choices=[f.value for f in FileFormat],
        default=None,
        help="File format — auto-detected from extension when omitted.",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii_masker",
        description=(
            "pii_masker — Mask PII data in CSV, Parquet, JSON, NDJSON, and Excel.\n"
            "Pipe-friendly · Reversible · Multi-engine (Polars / Pandas / DuckDB)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'pii_masker <subcommand> --help' for subcommand details.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # ── mask ──────────────────────────────────────────────────────────────────
    mask_p = sub.add_parser(
        "mask",
        help="Mask PII columns in a dataset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Apply a masking strategy to one or more columns.\n\n"
            "Examples:\n"
            "  pii_masker mask data.csv --columns email:name --strategy fake -o out.csv\n"
            "  pii_masker mask data.parquet --auto --strategy redact\n"
            "  cat data.csv | pii_masker mask --format csv --strategy fake > masked.csv"
        ),
    )
    mask_p.add_argument(
        "input_file", nargs="?", type=Path, default=None,
        metavar="INPUT_FILE",
        help="Input file. Omit to read from stdin.",
    )
    mask_p.add_argument(
        "--output", "-o", type=Path, default=None,
        help="Output file. Omit to write to stdout.",
    )
    mask_p.add_argument(
        "--columns", "-c", default=None,
        metavar="COL1:COL2:...",
        help="Colon-separated columns to mask. e.g. email:name:phone",
    )
    mask_p.add_argument(
        "--strategy", "-s",
        choices=[s.value for s in Strategy],
        default=Strategy.redact.value,
        help="Masking strategy (default: redact).",
    )
    _add_engine_fmt(mask_p)
    mask_p.add_argument(
        "--auto", action="store_true",
        help="Auto-detect PII columns by name heuristics.",
    )
    mask_p.add_argument(
        "--reversible", action="store_true",
        help="Use AES-256-GCM reversible encryption.",
    )
    mask_p.add_argument(
        "--key", default=None,
        help="Secret key for reversible masking (required with --reversible).",
    )
    mask_p.add_argument(
        "--salt", default="",
        help="Salt prepended before hashing (default: empty).",
    )
    mask_p.add_argument(
        "--seed", type=int, default=None,
        help="RNG seed for reproducible fake data.",
    )
    mask_p.add_argument(
        "--partial-keep", type=int, default=4, metavar="N",
        help="Characters to keep in partial strategy (default: 4).",
    )
    mask_p.add_argument(
        "--partial-side", choices=["right", "left"], default="right",
        help="Which side to keep in partial strategy (default: right).",
    )
    mask_p.add_argument(
        "--dry-run", action="store_true",
        help="Preview masking plan without writing output.",
    )
    mask_p.add_argument(
        "--report", action="store_true",
        help="Print a masking summary table after processing.",
    )
    mask_p.add_argument(
        "--no-progress", action="store_true",
        help="Disable the progress bar.",
    )

    # ── unmask ────────────────────────────────────────────────────────────────
    unmask_p = sub.add_parser(
        "unmask",
        help="Reverse AES-GCM masked columns (requires --key).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Decrypt columns previously masked with --reversible.\n\n"
            "Example:\n"
            "  pii_masker unmask masked.csv --columns email:user_id --key mysecret -o restored.csv"
        ),
    )
    unmask_p.add_argument(
        "input_file", nargs="?", type=Path, default=None,
        metavar="INPUT_FILE",
        help="Input file. Omit to read from stdin.",
    )
    unmask_p.add_argument("--output", "-o", type=Path, default=None)
    unmask_p.add_argument(
        "--columns", "-c", required=True,
        metavar="COL1:COL2:...",
        help="Colon-separated columns to decrypt.",
    )
    unmask_p.add_argument(
        "--key", required=True,
        help="Secret key used during masking.",
    )
    _add_engine_fmt(unmask_p)

    # ── detect ────────────────────────────────────────────────────────────────
    detect_p = sub.add_parser(
        "detect",
        help="Analyze a file and suggest PII columns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Scan column names for PII heuristics and print sample values.\n\n"
            "Example:\n"
            "  pii_masker detect data.csv\n"
            "  pii_masker detect data.parquet --engine duckdb --samples 5"
        ),
    )
    detect_p.add_argument(
        "input_file", nargs="?", type=Path, default=None,
        metavar="INPUT_FILE",
    )
    detect_p.add_argument(
        "--samples", type=int, default=3,
        help="Sample values to show per column (default: 3).",
    )
    _add_engine_fmt(detect_p)

    # ── examples ──────────────────────────────────────────────────────────────
    sub.add_parser("examples", help="Show usage examples and cheat-sheet.")

    return parser


# ── command handlers ──────────────────────────────────────────────────────────

def _cmd_mask(args: argparse.Namespace) -> None:
    # validation
    if args.reversible and not args.key:
        exit_error("--reversible requires --key <secret>.")
    if not args.columns and not args.auto:
        exit_error("Specify --columns, --auto, or both.")

    ctx = MaskingContext(
        reversible=args.reversible,
        key_bytes=derive_key(args.key) if args.key else b"",
        salt=args.salt,
        seed=args.seed,
        partial_keep=args.partial_keep,
        partial_side=args.partial_side,
    )
    adapter = AdapterFactory.create(Engine(args.engine))
    fmt = FileFormat(args.fmt) if args.fmt else None

    try:
        source_fmt = load_adapter(adapter, args.input_file, fmt)
    except SystemExit:
        raise
    except Exception as exc:
        exit_error(f"Error loading data: {exc}")

    svc = MaskingService(adapter, Strategy(args.strategy), ctx)
    col_map = svc.resolve_columns(args.columns, args.auto)
    elapsed = svc.run(col_map, dry_run=args.dry_run,
                      progress=not args.no_progress)

    if not args.dry_run:
        try:
            save_adapter(adapter, args.output, fmt, source_fmt)
        except SystemExit:
            raise
        except Exception as exc:
            exit_error(f"Error writing output: {exc}")

    if args.report or args.dry_run:
        Reporter.masking_report(col_map, Strategy(args.strategy),
                                adapter.row_count(), elapsed, args.dry_run)
    else:
        Reporter.success(col_map, adapter.row_count(), elapsed)


def _cmd_unmask(args: argparse.Namespace) -> None:
    adapter = AdapterFactory.create(Engine(args.engine))
    fmt = FileFormat(args.fmt) if args.fmt else None

    try:
        source_fmt = load_adapter(adapter, args.input_file, fmt)
    except SystemExit:
        raise
    except Exception as exc:
        exit_error(f"Error loading data: {exc}")

    key_bytes = derive_key(args.key)
    for col in args.columns.split(":"):
        col = col.strip()
        if not col:
            continue
        if col not in adapter.columns:
            exit_error(
                f"Column '{col}' not found. Available: {', '.join(adapter.columns)}")
        try:
            adapter.apply_unmask(col, key_bytes)
        except Exception as exc:
            exit_error(f"Decryption failed for '{col}': {exc}")

    try:
        save_adapter(adapter, args.output, fmt, source_fmt)
    except SystemExit:
        raise
    except Exception as exc:
        exit_error(f"Error writing output: {exc}")

    console.print(
        f"[green]✓[/] Unmasked {len([c for c in args.columns.split(':') if c.strip()])} column(s).")


def _cmd_detect(args: argparse.Namespace) -> None:
    adapter = AdapterFactory.create(Engine(args.engine))
    fmt = FileFormat(args.fmt) if args.fmt else None

    try:
        load_adapter(adapter, args.input_file, fmt)
    except SystemExit:
        raise
    except Exception as exc:
        exit_error(f"Error loading data: {exc}")

    detected = PIIRegistry.detect(adapter.columns)
    Reporter.detect_report(adapter, detected, args.input_file, args.samples)


def _cmd_examples() -> None:
    console.print("""
[bold cyan]pii_masker[/] — Usage Examples

[bold]1. Basic fake-data masking:[/]
   pii_masker mask data.csv --columns email:name:phone --strategy fake -o masked.csv

[bold]2. Redact with auto-detect:[/]
   pii_masker mask data.parquet --auto --strategy redact --engine polars

[bold]3. DuckDB engine (large files > RAM):[/]
   pii_masker mask data.parquet --auto --strategy redact --engine duckdb

[bold]4. Reversible encryption (unmask later):[/]
   pii_masker mask data.csv --columns user_id:email --reversible --key mysecret -o masked.csv
   pii_masker unmask masked.csv --columns user_id:email --key mysecret -o restored.csv

[bold]5. Pipe-friendly:[/]
   cat data.csv | pii_masker mask --format csv --strategy fake > masked.csv

[bold]6. Partial masking (keep last 4 digits):[/]
   pii_masker mask data.csv --columns credit_card --strategy partial \\
     --partial-keep 4 --partial-side right -o masked.csv

[bold]7. Dry run + report:[/]
   pii_masker mask data.csv --auto --strategy redact --dry-run --report

[bold]8. Detect PII columns:[/]
   pii_masker detect data.csv

[bold]9. Reproducible fake data (CI / snapshot tests):[/]
   pii_masker mask data.csv --columns email:name --strategy fake --seed 42 -o masked.csv

[bold]10. Hash with salt:[/]
    pii_masker mask data.csv --columns user_id --strategy hash --salt pepper123

[bold]11. Null-out columns — Pandas + Excel:[/]
    pii_masker mask report.xlsx --auto --strategy null --engine pandas -o clean.xlsx
""")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    dispatch = {
        "mask":     _cmd_mask,
        "unmask":   _cmd_unmask,
        "detect":   _cmd_detect,
        "examples": lambda _: _cmd_examples(),
    }
    dispatch[args.command](args)
