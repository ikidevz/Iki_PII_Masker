import sys
import time
from typing import Optional
from rich.console import Console

from .config import PIIRegistry, PIIType, Strategy, exit_error
from .strategies import StrategyFactory, MaskingContext
from .adapters import BaseDataFrameAdapter

console = Console(stderr=True)


class MaskingService:
    """
    Orchestrates strategies + adapters. Keeps all business logic out of CLI.
    """

    def __init__(self, adapter: BaseDataFrameAdapter, strategy: Strategy,
                 ctx: MaskingContext) -> None:
        self.adapter = adapter
        self._strategy = StrategyFactory.create(strategy)
        self.ctx = ctx

    def resolve_columns(self, columns: Optional[str],
                        auto: bool) -> dict[str, Optional[PIIType]]:
        """Return {col_name: PIIType|None} for all columns to be masked."""
        all_cols = self.adapter.columns
        col_map: dict[str, Optional[PIIType]] = {}

        if auto:
            col_map.update(PIIRegistry.detect(all_cols))

        if columns:
            for c in columns.split(":"):
                c = c.strip()
                if not c:
                    continue
                if c not in all_cols:
                    exit_error(
                        f"Column '{c}' not found. Available: {', '.join(all_cols)}"
                    )
                col_map.setdefault(c, PIIRegistry.guess(c))

        return col_map

    def run(self, col_map: dict[str, Optional[PIIType]],
            dry_run: bool = False, progress: bool = True) -> float:
        """Apply masking. Returns elapsed seconds."""
        t0 = time.perf_counter()
        original_key_bytes = self.ctx.key_bytes
        try:
            if not dry_run:
                if progress and sys.stderr.isatty():
                    self._run_with_progress(col_map)
                else:
                    for col, pii_type in col_map.items():
                        self._prepare_column_key(col)
                        self.adapter.apply_mask(
                            col, self._strategy, pii_type, self.ctx)
        finally:
            self.ctx.key_bytes = original_key_bytes
        return time.perf_counter() - t0

    def _run_with_progress(self, col_map: dict[str, Optional[PIIType]]) -> None:
        from rich.progress import (BarColumn, Progress, SpinnerColumn,
                                   TextColumn, TimeElapsedColumn)
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total} columns"),
            TimeElapsedColumn(),
            console=console,
        ) as prog:
            task = prog.add_task("Masking", total=len(col_map))
            for col, pii_type in col_map.items():
                self._prepare_column_key(col)
                self.adapter.apply_mask(
                    col, self._strategy, pii_type, self.ctx)
                prog.advance(task)

    def _prepare_column_key(self, col: str) -> None:
        if self.ctx.key_provider is not None and self.ctx.reversible:
            self.ctx.key_bytes = self.ctx.key_provider.get_key(col)
