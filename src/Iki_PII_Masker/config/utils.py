from rich.console import Console
import sys

console = Console(stderr=True)


def exit_error(msg: str, code: int = 1) -> None:
    """Print a styled error to stderr and exit."""
    console.print(f"[bold red]Error:[/] {msg}")
    sys.exit(code)
