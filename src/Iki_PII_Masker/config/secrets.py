from __future__ import annotations

import os
from pathlib import Path

from .utils import exit_error

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None


def resolve_secret(cli_value: str | None) -> str:
    """Resolve the reversible masking secret from CLI, env var, or user config."""
    if cli_value:
        return cli_value

    if env := os.environ.get("PII_MASKER_KEY"):
        return env

    home = (
        os.environ.get("PII_MASKER_HOME")
        or os.environ.get("HOME")
        or os.environ.get("USERPROFILE")
        or (os.path.join(os.environ.get("HOMEDRIVE", ""), os.environ.get("HOMEPATH", "")) if os.environ.get("HOMEDRIVE") and os.environ.get("HOMEPATH") else None)
    )
    config_path = Path(home).expanduser() / ".pii_masker" / \
        "config.toml" if home else Path.home() / ".pii_masker" / "config.toml"
    if config_path.exists():
        if tomllib is None:
            exit_error(
                "TOML config support requires Python 3.11+ or tomli installed. "
                "Set PII_MASKER_KEY instead."
            )
        try:
            data = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            exit_error(f"Failed to read secret config {config_path}: {exc}")

        key = data.get("key")
        if isinstance(key, str) and key:
            return key
        exit_error(
            f"Secret config {config_path} must contain a non-empty 'key' string."
        )

    exit_error(
        "No secret provided. Use --key, $PII_MASKER_KEY, or ~/.pii_masker/config.toml"
    )
