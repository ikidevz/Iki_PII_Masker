from __future__ import annotations

from .enums import FileFormat
from .utils import exit_error
from ..adapters.base import BaseDataFrameAdapter
from ..strategies.factory import FormatRegistry

from pathlib import Path
from typing import Optional

import io
import sys


def load_adapter(adapter: BaseDataFrameAdapter, input_file: Optional[Path],
                 fmt: Optional[FileFormat]) -> FileFormat:
    """Load data from a file or stdin. Returns the resolved FileFormat."""
    if input_file:
        resolved = fmt or FormatRegistry.detect(input_file)
        adapter.load(input_file, resolved)
        return resolved
    if not fmt:
        exit_error("--format is required when reading from stdin.")
    adapter.load(io.BytesIO(sys.stdin.buffer.read()), fmt)
    return fmt


def save_adapter(adapter: BaseDataFrameAdapter, output: Optional[Path],
                 fmt: Optional[FileFormat], source_fmt: FileFormat) -> None:
    """Write adapter data to a file or stdout."""
    out_fmt = fmt or (FormatRegistry.detect(output) if output else source_fmt)
    if output:
        adapter.save(output, out_fmt)
    else:
        buf = io.BytesIO()
        adapter.save(buf, out_fmt)
        sys.stdout.buffer.write(buf.getvalue())
