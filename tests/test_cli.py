"""
test_cli.py — End-to-end CLI tests via subprocess.

Every test calls the real CLI binary so the full stack
(argparse → app → service → adapter → strategy) is exercised.
"""

import csv
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLI = [sys.executable, "-m", "Iki_PII_Masker.cli"]


def run(*args, input_text: str = None) -> subprocess.CompletedProcess:
    env = {**dict(os.environ), "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [*CLI, *args],
        capture_output=True,
        text=True,
        input=input_text,
        cwd=str(ROOT),
        env=env,
    )


def csv_col(path: Path, col: str) -> list[str]:
    with open(path) as f:
        return [row[col] for row in csv.DictReader(f)]


# ══════════════════════════════════════════════════════════════════════════════
# mask — basic strategies
# ══════════════════════════════════════════════════════════════════════════════

def test_mask_redact(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "email",
            "-s", "redact", "-o", str(out))
    assert r.returncode == 0
    assert all(v == "[EMAIL]" for v in csv_col(out, "email"))


def test_mask_fake(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "email", "-s", "fake",
            "--seed", "42", "-o", str(out))
    assert r.returncode == 0
    emails = csv_col(out, "email")
    assert all("alice@example.com" not in e for e in emails)


def test_mask_hash(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "user_id", "-s", "hash",
            "--salt", "pepper", "-o", str(out))
    assert r.returncode == 0
    assert all(v.startswith("SHA:") for v in csv_col(out, "user_id"))


def test_mask_partial(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "credit_card", "-s", "partial",
            "--partial-keep", "4", "--partial-side", "right", "-o", str(out))
    assert r.returncode == 0
    assert all("*" in v for v in csv_col(out, "credit_card"))


def test_mask_null(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "ssn", "-s", "null", "-o", str(out))
    assert r.returncode == 0
    assert all(v == "" for v in csv_col(out, "ssn"))


def test_mask_keep(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "revenue",
            "-s", "keep", "-o", str(out))
    assert r.returncode == 0
    original = csv_col(csv_file, "revenue")
    assert csv_col(out, "revenue") == original


# ══════════════════════════════════════════════════════════════════════════════
# mask — new strategies
# ══════════════════════════════════════════════════════════════════════════════

def test_mask_tokenize(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "user_id",
            "-s", "tokenize", "-o", str(out))
    assert r.returncode == 0
    assert all(v.startswith("TOK-") for v in csv_col(out, "user_id"))


def test_mask_pseudonymize(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "full_name", "-s", "pseudonymize",
            "--seed", "1", "-o", str(out))
    assert r.returncode == 0
    values = csv_col(out, "full_name")
    assert all(v not in ("Alice Smith", "Bob Jones") for v in values)
    assert all(isinstance(v, str) and v for v in values)


def test_mask_generalize(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "age",
            "-s", "generalize", "-o", str(out))
    assert r.returncode == 0
    assert all("-" in v for v in csv_col(out, "age"))


def test_mask_mask_format(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "email",
            "-s", "mask_format", "-o", str(out))
    assert r.returncode == 0
    for v in csv_col(out, "email"):
        assert "@" in v
        assert "*" in v


# ══════════════════════════════════════════════════════════════════════════════
# mask — auto-detect
# ══════════════════════════════════════════════════════════════════════════════

def test_mask_auto(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "--auto", "-s", "redact", "-o", str(out))
    assert r.returncode == 0
    assert all(v == "[EMAIL]" for v in csv_col(out, "email"))
    assert all(v == "[PHONE]" for v in csv_col(out, "phone"))


def test_mask_auto_plus_explicit(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "--auto", "-c", "revenue", "-s", "redact",
            "-o", str(out))
    assert r.returncode == 0
    assert all(v == "[EMAIL]" for v in csv_col(out, "email"))
    assert all(v == "[REDACTED]" for v in csv_col(out, "revenue"))


def test_mask_with_profile_yaml(csv_file, tmp_path):
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        """
        engine: polars
        seed: 42
        columns:
          email: fake
          full_name: pseudonymize
        auto: false
        """
    )
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "--profile", str(profile), "-o", str(out))
    assert r.returncode == 0
    assert out.exists()
    assert all(v not in ("alice@example.com", "bob@corp.org", "carol@test.net",
               "dave@email.com", "eve@sample.io") for v in csv_col(out, "email"))
    assert all(v not in ("Alice Smith", "Bob Jones", "Carol White",
               "Dave Brown", "Eve Davis") for v in csv_col(out, "full_name"))


def test_mask_with_profile_yaml_reversible(csv_file, tmp_path):
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        """
        engine: polars
        seed: 42
        salt: pepper
        columns:
          email: fake
        auto: false
        """
    )
    masked = tmp_path / "masked.csv"
    restored = tmp_path / "restored.csv"

    r = run(
        "mask", str(csv_file), "--profile", str(profile), "--reversible",
        "--key", "secret123", "--salt", "pepper", "-o", str(masked),
    )
    assert r.returncode == 0
    assert all(v.startswith("ENC:") for v in csv_col(masked, "email"))

    r = run(
        "unmask", str(masked), "-c", "email",
        "--key", "secret123", "--salt", "pepper", "-o", str(restored),
    )
    assert r.returncode == 0
    assert csv_col(restored, "email") == csv_col(csv_file, "email")


def test_mask_with_env_key_and_verify(csv_file, tmp_path, monkeypatch):
    out = tmp_path / "out.csv"
    monkeypatch.setenv("PII_MASKER_KEY", "secret123")

    r = run(
        "mask", str(csv_file), "-c", "email", "-s", "redact",
        "--reversible", "--salt", "pepper", "--verify", "-o", str(out),
    )
    assert r.returncode == 0
    assert "verification passed" in (r.stdout + r.stderr).lower()

    r = run("unmask", str(out), "-c", "email", "--salt",
            "pepper", "-o", str(tmp_path / "restored.csv"))
    assert r.returncode == 0


def test_unmask_with_config_key(csv_file, tmp_path, monkeypatch):
    config_dir = tmp_path / ".pii_masker"
    config_dir.mkdir()
    config_file = config_dir / "config.toml"
    config_file.write_text('key = "secret123"')

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))

    masked = tmp_path / "masked.csv"
    restored = tmp_path / "restored.csv"

    r = run(
        "mask", str(csv_file), "-c", "email", "-s", "redact",
        "--reversible", "--salt", "pepper", "--key", "secret123", "-o", str(
            masked),
    )
    assert r.returncode == 0

    r = run("unmask", str(masked), "-c", "email",
            "--salt", "pepper", "-o", str(restored))
    assert r.returncode == 0
    assert csv_col(restored, "email") == csv_col(csv_file, "email")


def test_validate_profile_yaml_ok(tmp_path):
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        """
        engine: polars
        seed: 42
        columns:
          email: fake
        auto: false
        """
    )

    r = run("validate-profile", str(profile))
    assert r.returncode == 0
    output = r.stdout + r.stderr
    assert "Profile" in output and "valid" in output


def test_validate_profile_yaml_invalid(tmp_path):
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        """
        engine: invalid-engine
        columns:
          email: fake
        auto: false
        """
    )

    r = run("validate-profile", str(profile))
    assert r.returncode != 0
    assert "Profile validation failed" in r.stderr or "Profile validation failed" in r.stdout


# ══════════════════════════════════════════════════════════════════════════════
# mask — engines
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("engine", ["polars", "pandas", "duckdb"])
def test_mask_all_engines(csv_file, tmp_path, engine):
    out = tmp_path / f"out_{engine}.csv"
    r = run("mask", str(csv_file), "-c", "email", "-s", "redact",
            "--engine", engine, "-o", str(out))
    assert r.returncode == 0
    assert all(v == "[EMAIL]" for v in csv_col(out, "email"))


# ══════════════════════════════════════════════════════════════════════════════
# mask — multiple columns
# ══════════════════════════════════════════════════════════════════════════════

def test_mask_multiple_columns(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "email:phone:full_name",
            "-s", "redact", "-o", str(out))
    assert r.returncode == 0
    assert all(v == "[EMAIL]" for v in csv_col(out, "email"))
    assert all(v == "[PHONE]" for v in csv_col(out, "phone"))
    assert all(v == "[NAME]" for v in csv_col(out, "full_name"))


# ══════════════════════════════════════════════════════════════════════════════
# mask — dry run
# ══════════════════════════════════════════════════════════════════════════════

def test_dry_run_produces_no_output_file(csv_file, tmp_path):
    out = tmp_path / "out.csv"
    r = run("mask", str(csv_file), "-c", "email", "-s", "redact",
            "--dry-run", "-o", str(out))
    assert r.returncode == 0
    assert not out.exists()


def test_dry_run_report_in_stderr_or_stdout(csv_file, tmp_path):
    r = run("mask", str(csv_file), "-c", "email", "-s", "redact", "--dry-run")
    assert r.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# mask — reversible + unmask
# ══════════════════════════════════════════════════════════════════════════════

def test_reversible_mask_unmask_round_trip(csv_file, tmp_path):
    masked = tmp_path / "masked.csv"
    restored = tmp_path / "restored.csv"
    original = csv_col(csv_file, "email")

    run("mask", str(csv_file), "-c", "email", "-s", "redact",
        "--reversible", "--key", "secret123", "-o", str(masked))
    assert all(v.startswith("ENC:") for v in csv_col(masked, "email"))

    run("unmask", str(masked), "-c", "email",
        "--key", "secret123", "-o", str(restored))
    assert csv_col(restored, "email") == original


def test_reversible_cipher_choice_round_trip(csv_file, tmp_path):
    masked = tmp_path / "masked_chacha.csv"
    restored = tmp_path / "restored_chacha.csv"
    original = csv_col(csv_file, "email")

    run("mask", str(csv_file), "-c", "email", "-s", "redact",
        "--reversible", "--reversible-cipher", "chacha20-poly1305",
        "--key", "secret123", "-o", str(masked))
    assert all(v.startswith("ENC-CHACHA:") for v in csv_col(masked, "email"))

    run("unmask", str(masked), "-c", "email",
        "--key", "secret123", "-o", str(restored))
    assert csv_col(restored, "email") == original


def test_unmask_wrong_key_exits(csv_file, tmp_path):
    masked = tmp_path / "masked.csv"
    run("mask", str(csv_file), "-c", "email", "-s", "redact",
        "--reversible", "--key", "correct", "-o", str(masked))
    r = run("unmask", str(masked), "-c", "email", "--key", "wrong")
    assert r.returncode != 0


# ══════════════════════════════════════════════════════════════════════════════
# mask — file formats
# ══════════════════════════════════════════════════════════════════════════════

def test_mask_parquet(tmp_path, csv_file):
    parquet_in = tmp_path / "in.parquet"
    parquet_out = tmp_path / "out.parquet"

    # create parquet from csv via polars
    import polars as pl
    pl.read_csv(csv_file).write_parquet(parquet_in)

    r = run("mask", str(parquet_in), "-c", "email", "-s", "redact",
            "-o", str(parquet_out))
    assert r.returncode == 0
    assert parquet_out.exists()
    df = pl.read_parquet(parquet_out)
    assert all(v == "[EMAIL]" for v in df["email"].to_list())


# ══════════════════════════════════════════════════════════════════════════════
# detect subcommand
# ══════════════════════════════════════════════════════════════════════════════

def test_detect_finds_pii_columns(csv_file):
    r = run("detect", str(csv_file))
    assert r.returncode == 0
    assert "email" in r.stdout or "email" in r.stderr


def test_detect_shows_sample_values(csv_file):
    r = run("detect", str(csv_file), "--samples", "2")
    assert r.returncode == 0


# ══════════════════════════════════════════════════════════════════════════════
# pipe mode (stdin → stdout)
# ══════════════════════════════════════════════════════════════════════════════

def test_pipe_stdin_stdout(csv_file):
    csv_text = csv_file.read_text()
    r = run("mask", "--format", "csv", "-c", "email", "-s", "redact",
            input_text=csv_text)
    assert r.returncode == 0
    assert "[EMAIL]" in r.stdout
    assert "alice@example.com" not in r.stdout


# ══════════════════════════════════════════════════════════════════════════════
# error cases
# ══════════════════════════════════════════════════════════════════════════════

def test_unknown_column_exits(csv_file, tmp_path):
    r = run("mask", str(csv_file), "-c", "does_not_exist", "-s", "redact",
            "-o", str(tmp_path / "out.csv"))
    assert r.returncode != 0


def test_unknown_strategy_exits(csv_file, tmp_path):
    r = run("mask", str(csv_file), "-c", "email", "-s", "notreal",
            "-o", str(tmp_path / "out.csv"))
    assert r.returncode != 0


def test_no_columns_no_auto_exits(csv_file, tmp_path):
    r = run("mask", str(csv_file), "-s", "redact",
            "-o", str(tmp_path / "out.csv"))
    assert r.returncode != 0
