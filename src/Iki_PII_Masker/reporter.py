from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from .config import Strategy, PIIType
from .adapters import BaseDataFrameAdapter


console = Console(stderr=True)


class Reporter:
    """Owns all Rich terminal output. Single Responsibility."""

    @staticmethod
    def masking_report(col_map: dict[str, Optional[PIIType]], strategy: Strategy,
                       row_count: int, elapsed: float, dry_run: bool) -> None:
        table = Table(title="Masking Report",
                      border_style="cyan", show_lines=True)
        table.add_column("Column",        style="bold white")
        table.add_column("PII Type",      style="yellow")
        table.add_column("Strategy",      style="green")
        table.add_column("Rows Affected", justify="right")
        for col, pii_type in col_map.items():
            table.add_row(col, pii_type.name if pii_type else "generic",
                          strategy.value, str(row_count))
        console.print(table)
        suffix = "  [bold yellow][DRY RUN — no output written][/]" if dry_run else ""
        console.print(
            f"[dim]Rows:[/] {row_count}  "
            f"[dim]Columns masked:[/] {len(col_map)}  "
            f"[dim]Time:[/] {elapsed:.3f}s{suffix}"
        )

    @staticmethod
    def detect_report(adapter: BaseDataFrameAdapter, detected: dict[str, PIIType],
                      input_file: Optional[Path], samples: int) -> None:
        table = Table(title="PII Detection Results",
                      border_style="magenta", show_lines=True)
        table.add_column("Column",        style="bold white")
        table.add_column("PII Type",      style="yellow")
        table.add_column("Sample Values", style="dim")
        for col in adapter.columns:
            pii_type = detected.get(col)
            sample_str = ", ".join(str(v)
                                   for v in adapter.sample_values(col, samples))
            table.add_row(
                col, pii_type.name if pii_type else "—", sample_str[:60])
        console.print(table)
        if detected:
            cols_arg = ":".join(detected.keys())
            console.print(
                Panel(
                    f"[bold]Suggested masking command:[/]\n\n"
                    f"  pii_masker mask [dim]{input_file or 'data.csv'}[/] "
                    f"[cyan]--columns {cols_arg} --strategy fake[/]",
                    border_style="cyan", title="Next Step",
                )
            )

    @staticmethod
    def success(col_map: dict, row_count: int, elapsed: float) -> None:
        console.print(
            f"[green]✓[/] Masked [bold]{len(col_map)}[/] column(s) "
            f"across [bold]{row_count}[/] rows in [dim]{elapsed:.3f}s[/]"
        )
