from typing import Optional
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import Strategy, PIIType
from .adapters import BaseDataFrameAdapter
from .strategies import MaskingContext
from .strategies.redact import RedactStrategy


console = Console(stderr=True)


class Reporter:
    """Handles all Rich terminal output for the tool."""

    @staticmethod
    def masking_report(
        col_map: dict[str, Optional[PIIType]],
        strategy: Strategy,
        row_count: int,
        elapsed: float,
        dry_run: bool = False,
    ) -> None:
        """Print summary after masking operation."""
        table = Table(title="Masking Report",
                      border_style="cyan", show_lines=True)
        table.add_column("Column", style="bold white")
        table.add_column("PII Type", style="yellow")
        table.add_column("Strategy", style="green")
        table.add_column("Rows Affected", justify="right")

        for col, pii_type in col_map.items():
            table.add_row(
                col,
                pii_type.name if pii_type else "generic",
                strategy.value,
                str(row_count),
            )

        console.print(table)

        suffix = "  [bold yellow][DRY RUN — no output written][/]" if dry_run else ""
        console.print(
            f"[dim]Rows:[/] {row_count}   "
            f"[dim]Columns masked:[/] {len(col_map)}   "
            f"[dim]Time:[/] {elapsed:.3f}s{suffix}"
        )

    @staticmethod
    def detect_report(
        adapter: BaseDataFrameAdapter,
        detected: dict[str, PIIType],
        input_file: Optional[Path] = None,
        samples: int = 3,
        redact_samples: bool = True,      # Secure by default
        source_labels: dict[str, str] | None = None,
    ) -> None:
        """Print PII detection results with optional redaction of sample values."""
        table = Table(title="PII Detection Results",
                      border_style="magenta", show_lines=True)
        table.add_column("Column", style="bold white")
        table.add_column("PII Type", style="yellow")
        table.add_column("Source", style="cyan")
        table.add_column("Sample Values", style="dim")

        redactor = RedactStrategy() if redact_samples else None

        for col in adapter.columns:
            pii_type = detected.get(col)
            raw_samples = adapter.sample_values(col, samples)

            if redact_samples and redactor and raw_samples:
                # Redact samples to avoid leaking real PII
                masked_samples = []
                ctx = MaskingContext()
                for v in raw_samples:
                    if v is None or str(v).strip() == "":
                        masked_samples.append(str(v))
                    else:
                        masked_samples.append(
                            redactor.mask(str(v), pii_type, ctx))
                sample_str = ", ".join(masked_samples)
            else:
                sample_str = ", ".join(str(v) for v in raw_samples)

            # Truncate very long strings
            if len(sample_str) > 80:
                sample_str = sample_str[:77] + "..."

            source = "—"
            if source_labels is not None and col in source_labels:
                source = source_labels[col]

            table.add_row(
                col,
                pii_type.name if pii_type else "—",
                source,
                sample_str,
            )

        console.print(table)

        if detected:
            cols_arg = ":".join(detected.keys())
            console.print(
                Panel(
                    f"[bold]Suggested command:[/]\n\n"
                    f"  pii_masker mask {input_file or 'data.csv'} "
                    f"--columns {cols_arg} --strategy fake",
                    border_style="cyan",
                    title="Next Step",
                )
            )

    @staticmethod
    def success(col_map: dict, row_count: int, elapsed: float) -> None:
        """Print success message after masking."""
        console.print(
            f"[green]✓[/] Masked [bold]{len(col_map)}[/] column(s) "
            f"across [bold]{row_count}[/] rows in [dim]{elapsed:.3f}s[/]"
        )

    @staticmethod
    def verification_success() -> None:
        console.print(
            "[green]✓[/] Output verification passed — no remaining detected PII.")

    @staticmethod
    def verification_failed(leftovers: dict[str, PIIType]) -> None:
        table = Table(title="Verification Failed",
                      border_style="red", show_lines=True)
        table.add_column("Column", style="bold white")
        table.add_column("Detected PII", style="yellow")

        for col, pii_type in leftovers.items():
            table.add_row(col, pii_type.name)

        console.print(table)
