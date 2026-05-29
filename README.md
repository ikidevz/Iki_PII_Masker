# Iki_PII_Masker

> **Do one thing well: mask PII data.**

A production-grade, pipe-friendly CLI tool and Python library for data
engineers and analysts who need to sanitize datasets fast — without wrestling
with config files or heavyweight frameworks.

```bash
pii_masker mask data.csv --auto --strategy fake -o clean.csv
```

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)
![Engine](https://img.shields.io/badge/engine-Polars%20%7C%20Pandas%20%7C%20DuckDB-orange)

---

## Features

| Feature                  | Details                                                    |
| ------------------------ | ---------------------------------------------------------- |
| **6 masking strategies** | `fake`, `redact`, `hash`, `null`, `partial`, `keep`        |
| **Reversible masking**   | AES-256-GCM — restore originals anytime with `--key`       |
| **Auto-detect PII**      | `--auto` flags columns by name heuristics (10 PII types)   |
| **Multi-engine**         | Polars (default), Pandas, or DuckDB — swap with `--engine` |
| **5 file formats**       | CSV, Parquet, JSON, NDJSON, Excel                          |
| **Pipe-friendly**        | stdin → stdout, zero config required                       |
| **Reproducible fakes**   | `--seed` for deterministic output in CI/testing            |
| **Dry run + report**     | Preview masking plan before touching any data              |
| **PII detector**         | `detect` subcommand scans columns and prints sample values |
| **Python façade API**    | Import by feature — no internal sub-packages exposed       |

---

## Installation

```bash
# Recommended: install from source in editable mode
pip install -e .

# Or from PyPI
pip install pii-masker
```

**Requirements:** Python 3.9+

**Core dependencies:** `rich`, `polars`, `pandas`, `faker`,
`cryptography`, `pyarrow`, `openpyxl`, `duckdb`

**CLI framework:** `argparse` (stdlib — no extra install needed)

---

## Subcommands

| Command    | Purpose                                           |
| ---------- | ------------------------------------------------- |
| `mask`     | Apply a masking strategy to one or more columns   |
| `unmask`   | Decrypt AES-GCM masked columns back to originals  |
| `detect`   | Scan a file and suggest which columns contain PII |
| `examples` | Print a cheat-sheet of usage patterns             |

---

## Quick Start

### Step 0 — Detect PII first

Before masking anything, run `detect` to see what the tool finds and review
sample values:

```bash
pii_masker detect data.csv
```

```
┌─────────────┬─────────────┬──────────────────────────────────────────────────┐
│ Column      │ PII Type    │ Sample Values                                    │
├─────────────┼─────────────┼──────────────────────────────────────────────────┤
│ id          │ —           │ 1, 2, 3                                          │
│ full_name   │ name        │ Alice Smith, Bob Jones, Carol White              │
│ email       │ email       │ alice@example.com, bob@corp.org, carol@test.net  │
│ phone       │ phone       │ +1-555-0100, +1-555-0101, +1-555-0102            │
│ credit_card │ credit_card │ 4111111111111234, 5500005555555559               │
│ revenue     │ —           │ 1200.50, 980.00, 750.00                          │
└─────────────┴─────────────┴──────────────────────────────────────────────────┘

Suggested: pii_masker mask data.csv --columns full_name:email:phone:credit_card --strategy fake
```

### Mask with realistic fake data

```bash
pii_masker mask data.csv --columns email:full_name:phone --strategy fake -o masked.csv
```

### Auto-detect and redact (Parquet, Polars engine)

```bash
pii_masker mask data.parquet --auto --strategy redact --engine polars -o clean.parquet
```

### Reversible masking

Encrypt columns so they can be restored later with the same key:

```bash
# Mask
pii_masker mask data.csv \
  --columns user_id:email \
  --reversible \
  --key "my-secret-key-2024" \
  -o masked.csv

# Restore
pii_masker unmask masked.csv \
  --columns user_id:email \
  --key "my-secret-key-2024" \
  -o restored.csv
```

Encrypted values are stored as `ENC:<base64-token>` — safe to round-trip
through CSV, Parquet, and JSON.

### Pipe-friendly

```bash
# Inline in a pipeline
cat raw.csv | pii_masker mask --format csv --strategy fake > clean.csv

# Chain with other tools
cat data.csv \
  | pii_masker mask --format csv --columns email --strategy redact \
  | gzip > masked.csv.gz
```

### Partial masking

Keep the last N characters, mask the rest with `*`:

```bash
pii_masker mask data.csv \
  --columns credit_card:phone \
  --strategy partial \
  --partial-keep 4 \
  --partial-side right \
  -o masked.csv
```

```
4111111111111234  →  ************1234
+1-555-867-5309   →  *************309
```

### Dry run with report

Preview exactly what would be masked before writing anything:

```bash
pii_masker mask data.csv --auto --strategy fake --dry-run --report
```

```
┌─────────────┬─────────────┬──────────┬───────────────┐
│ Column      │ PII Type    │ Strategy │ Rows Affected │
├─────────────┼─────────────┼──────────┼───────────────┤
│ email       │ email       │ fake     │        50,000 │
│ full_name   │ name        │ fake     │        50,000 │
│ phone       │ phone       │ fake     │        50,000 │
└─────────────┴─────────────┴──────────┴───────────────┘
Rows: 50,000  Columns masked: 3  Time: 0.031s  [DRY RUN — no output written]
```

### Reproducible fake data (CI / snapshot tests)

```bash
pii_masker mask data.csv --columns email:name --strategy fake --seed 42 -o masked.csv
# Identical output on every run — safe for golden-file tests.
```

### Hash with salt

```bash
pii_masker mask data.csv \
  --columns user_id \
  --strategy hash \
  --salt "pepper_$(date +%Y)" \
  -o hashed.csv
```

### Null out sensitive columns

```bash
pii_masker mask report.xlsx \
  --columns ssn:dob \
  --strategy null \
  --engine pandas \
  -o clean.xlsx
```

---

## All Strategies

| Strategy  | Output example     | Reversible?         | Best for                     |
| --------- | ------------------ | ------------------- | ---------------------------- |
| `fake`    | `alice@fake.com`   | No                  | Realistic test/dev data      |
| `redact`  | `[EMAIL]`          | With `--reversible` | Audit logs, shared reports   |
| `hash`    | `SHA:3d7a2c1e9b4f` | With `--reversible` | Join keys, deduplication     |
| `null`    | `null`             | No                  | Dropping PII for analytics   |
| `partial` | `****1234`         | No                  | Card numbers, phone numbers  |
| `keep`    | original value     | N/A                 | Whitelisting non-PII columns |

---

## Full Option Reference

### `pii_masker mask`

```
Arguments:
  [INPUT_FILE]              Input file path. Omit to read from stdin.

Options:
  -o, --output PATH         Output file path. Omit to write to stdout.
  -c, --columns TEXT        Colon-separated column names. e.g. email:name:phone
  -s, --strategy STRATEGY   fake|redact|hash|null|partial|keep  [default: redact]
  -e, --engine ENGINE       polars|pandas|duckdb  [default: polars]
  -f, --format FORMAT       csv|parquet|json|ndjson|excel  (auto-detected from extension)
      --auto                Auto-detect PII columns by name heuristics
      --reversible          Use AES-256-GCM reversible encryption
      --key TEXT            Secret key for reversible masking
      --salt TEXT           Salt prepended before hashing  [default: ""]
      --seed INTEGER        RNG seed for reproducible fake data
      --partial-keep INT    Number of characters to keep  [default: 4]
      --partial-side TEXT   Which side to keep: right|left  [default: right]
      --dry-run             Preview masking plan without writing output
      --report              Print a masking summary table after processing
      --no-progress         Disable the progress bar
```

### `pii_masker unmask`

```
Arguments:
  [INPUT_FILE]              Input file path. Omit to read from stdin.

Options:
  -o, --output PATH         Output file path. Omit to write to stdout.
  -c, --columns TEXT        Colon-separated columns to decrypt  [required]
      --key TEXT            Secret key used during masking  [required]
  -e, --engine ENGINE       polars|pandas|duckdb  [default: polars]
  -f, --format FORMAT       csv|parquet|json|ndjson|excel
```

### `pii_masker detect`

```
Arguments:
  [INPUT_FILE]              Input file path. Omit to read from stdin.

Options:
  -f, --format FORMAT       csv|parquet|json|ndjson|excel
  -e, --engine ENGINE       polars|pandas|duckdb  [default: polars]
      --samples INTEGER     Sample values to show per column  [default: 3]
```

---

## Python API

Every feature is accessible as a clean Python API through the façade module.
Import only what you need — no internal sub-packages, no internal classes.

```python
from Iki_PII_Masker.facade import detect_pii           # scan columns for PII
from Iki_PII_Masker.facade import mask_dataframe        # apply any strategy
from Iki_PII_Masker.facade import unmask_dataframe      # reverse AES masking
from Iki_PII_Masker.facade import load_data, save_data  # file I/O
from Iki_PII_Masker.facade import make_context, make_reversible_context
from Iki_PII_Masker.facade import derive_encryption_key
from Iki_PII_Masker.facade import create_adapter        # polars / pandas / duckdb
from Iki_PII_Masker.facade import report_detection, report_masking
from Iki_PII_Masker.facade import Strategy, Engine, FileFormat
```

### Façade feature reference

| Feature                                               | What it does                                                           |
| ----------------------------------------------------- | ---------------------------------------------------------------------- |
| `detect_pii(columns)`                                 | Scan a column list → `{col: PIIType}` for every PII match              |
| `mask_dataframe(adapter, columns, strategy, context)` | Apply a strategy to named columns; returns elapsed seconds             |
| `unmask_dataframe(adapter, columns, key)`             | Reverse AES-256-GCM masking in-place                                   |
| `load_data(adapter, source, fmt)`                     | Load a file, path, `BytesIO`, or `None` (stdin) into an adapter        |
| `save_data(adapter, dest, fmt)`                       | Write adapter data to a file, `BytesIO`, or `None` (stdout)            |
| `make_context(**kwargs)`                              | Build a plain `MaskingContext` (salt, seed, partial options)           |
| `make_reversible_context(secret)`                     | Build a context that AES-encrypts every value; key derived from secret |
| `derive_encryption_key(secret)`                       | Derive 32-byte AES key from a secret string                            |
| `create_adapter(engine)`                              | Instantiate a Polars, Pandas, or DuckDB adapter                        |
| `report_detection(adapter, detected, file)`           | Print Rich PII detection table with sample values                      |
| `report_masking(adapter, col_map, strategy, elapsed)` | Print Rich masking summary table                                       |

### Python API examples

**Detect PII and print a report:**

```python
from Iki_PII_Masker.facade import create_adapter, load_data, detect_pii, report_detection
from Iki_PII_Masker.facade import Engine
from pathlib import Path

adapter  = create_adapter(Engine.polars)
load_data(adapter, Path("data.csv"))

detected = detect_pii(adapter.columns)
report_detection(adapter, detected, Path("data.csv"), samples=3)
```

**Mask with fake data (reproducible):**

```python
from Iki_PII_Masker.facade import create_adapter, load_data, save_data
from Iki_PII_Masker.facade import mask_dataframe, make_context
from Iki_PII_Masker.facade import Strategy, Engine
from pathlib import Path

adapter = create_adapter(Engine.polars)
load_data(adapter, Path("data.csv"))
mask_dataframe(adapter, "email:full_name:phone", Strategy.fake, make_context(seed=42))
save_data(adapter, Path("masked.csv"))
```

**Auto-detect and redact:**

```python
mask_dataframe(adapter, None, Strategy.redact, auto=True)
```

**Hash with salt:**

```python
mask_dataframe(adapter, "user_id:email", Strategy.hash, make_context(salt="pepper_2024"))
```

**Partial masking — keep last 4 digits:**

```python
mask_dataframe(adapter, "credit_card:phone", Strategy.partial,
               make_context(partial_keep=4, partial_side="right"))
```

**Null out sensitive columns:**

```python
mask_dataframe(adapter, "ssn:dob:password", Strategy.null)
```

**Reversible masking — mask then restore:**

```python
from Iki_PII_Masker.facade import (
    create_adapter, load_data, save_data,
    mask_dataframe, unmask_dataframe,
    make_reversible_context, derive_encryption_key,
    Strategy, Engine,
)
from pathlib import Path

SECRET = "my-production-secret-2024"

# Mask
adapter = create_adapter(Engine.polars)
load_data(adapter, Path("data.csv"))
mask_dataframe(adapter, "email:user_id", Strategy.redact,
               make_reversible_context(SECRET))
save_data(adapter, Path("masked.csv"))

# Restore
key = derive_encryption_key(SECRET)
adapter2 = create_adapter(Engine.polars)
load_data(adapter2, Path("masked.csv"))
unmask_dataframe(adapter2, ["email", "user_id"], key)
save_data(adapter2, Path("restored.csv"))
```

**In-memory pipe (BytesIO):**

```python
import io
from Iki_PII_Masker.facade import create_adapter, load_data, save_data
from Iki_PII_Masker.facade import mask_dataframe, make_context
from Iki_PII_Masker.facade import Strategy, Engine, FileFormat

buf_in = io.BytesIO(open("data.csv", "rb").read())

adapter = create_adapter(Engine.polars)
load_data(adapter, buf_in, FileFormat.csv)
mask_dataframe(adapter, "email:full_name", Strategy.fake, make_context(seed=99))

buf_out = io.BytesIO()
save_data(adapter, buf_out, FileFormat.csv)
```

**Multi-strategy pipeline on a single adapter:**

```python
# Pass 1 — fake names and emails
mask_dataframe(adapter, "email:full_name", Strategy.fake, make_context(seed=42))

# Pass 2 — partial card numbers
mask_dataframe(adapter, "credit_card", Strategy.partial,
               make_context(partial_keep=4, partial_side="right"))

# Pass 3 — null out secrets
mask_dataframe(adapter, "password:ssn", Strategy.null)
```

**Dry run with masking report:**

```python
from Iki_PII_Masker.facade import mask_dataframe, report_masking, Strategy
import time

t0      = time.perf_counter()
mask_dataframe(adapter, None, Strategy.fake, auto=True, dry_run=True)
elapsed = time.perf_counter() - t0

report_masking(adapter, col_map, Strategy.fake, elapsed, dry_run=True)
```

**All three engines:**

```python
for engine in [Engine.polars, Engine.pandas, Engine.duckdb]:
    adapter = create_adapter(engine)
    load_data(adapter, Path("data.csv"))
    mask_dataframe(adapter, "email:full_name", Strategy.redact)
    save_data(adapter, Path(f"masked_{engine.value}.csv"))
```

---

## PII Auto-Detection

The `--auto` flag, `detect` command, and `detect_pii()` function match column
names against regex heuristics for ten built-in PII types:

| PII Type      | Matched column names (examples)                            |
| ------------- | ---------------------------------------------------------- |
| `email`       | `email`, `email_address`, `mail`                           |
| `phone`       | `phone`, `mobile`, `cell`, `telephone`, `contact_number`   |
| `name`        | `full_name`, `first_name`, `last_name`, `username`, `name` |
| `address`     | `address`, `street`, `city`, `state`, `zip`, `postal_code` |
| `ssn`         | `ssn`, `social_security`, `national_id`                    |
| `dob`         | `dob`, `date_of_birth`, `birthdate`, `birthday`            |
| `ip`          | `ip_address`, `ip`, `ipv4`, `ipv6`                         |
| `credit_card` | `credit_card`, `card_number`, `cc_number`, `pan`           |
| `user_id`     | `user_id`, `userid`, `account_id`, `customer_id`           |
| `password`    | `password`, `passwd`, `pwd`                                |

Detection is heuristic. Always review `detect` output on new datasets before
running a masked job in production.

**Register a custom PII type at runtime:**

```python
from Iki_PII_Masker.facade import PIIRegistry, PIIType

PIIRegistry.register(PIIType(
    name="api_key",
    patterns=[r"\bapi_key\b", r"\btoken\b", r"\baccess_key\b"],
    redact_label="[TOKEN]",
    faker_method="uuid4",
))
```

---

## Reversible Masking — How It Works

When `--reversible --key <secret>` is passed (or `make_reversible_context(secret)` in Python):

1. A 32-byte AES key is derived from your secret using SHA-256.
2. Each value is encrypted with **AES-256-GCM** using a random 96-bit nonce.
3. The nonce + ciphertext + GCM tag are base64-encoded as `ENC:<token>` and
   stored in place of the original value.
4. `pii_masker unmask --key <same-secret>` (or `unmask_dataframe`) reverses step 3 → 1.

Because each value gets a fresh random nonce, identical inputs produce
different ciphertext — preventing frequency analysis on the masked dataset.

**Security note — key handling:** The `--key` flag is visible in shell history
and `ps` output. In production, pass the key via an environment variable:

```bash
export MASK_KEY=$(vault kv get -field=key secret/pii-key)
pii_masker mask data.csv --columns email --reversible --key "$MASK_KEY" -o out.csv
```

---

## Performance

Benchmarked on a 10M-row, 500 MB CSV with 5 PII columns:

| Engine | Strategy | Time | Notes                         |
| ------ | -------- | ---- | ----------------------------- |
| Polars | `redact` | ~4s  | Best all-rounder              |
| Polars | `hash`   | ~5s  |                               |
| Polars | `fake`   | ~18s |                               |
| DuckDB | `redact` | ~4s  | Handles files larger than RAM |
| DuckDB | `hash`   | ~5s  |                               |
| DuckDB | `fake`   | ~19s |                               |
| Pandas | `redact` | ~9s  | Use for Excel I/O             |
| Pandas | `fake`   | ~35s |                               |

Polars is the default for speed. Use **DuckDB** (`--engine duckdb`) when your
file is too large to fit in memory — DuckDB scans Parquet and CSV directly from
disk without loading the full dataset. Use **Pandas** (`--engine pandas`) only
when you need Excel I/O or tight ecosystem integration.

---

## Architecture

`pii_masker` is built around four design patterns that keep it easy to extend
without touching existing code:

**Strategy** — each masking algorithm (`RedactStrategy`, `FakeStrategy`, etc.)
is an independent class. Adding a new algorithm means adding one class; no
existing code changes.

**Registry** — `PIIRegistry` is the single source of truth for all PII
metadata (patterns, redact labels, Faker methods). Adding a new PII type is
one entry in one place.

**Adapter** — `PolarsAdapter`, `PandasAdapter`, and `DuckDBAdapter` expose an
identical interface to the rest of the codebase. Swapping or adding an engine
requires one new class.

**Factory** — `StrategyFactory`, `AdapterFactory`, and `FormatRegistry`
centralise all object creation so CLI functions contain zero branching logic.

**Façade** — `facade.py` is the single public door into the Python API.
It re-exports every capability as a named action function so callers never
import from internal sub-packages directly.

### Package layout

```
src/Iki_PII_Masker/
├── facade.py            ← public Python API (import from here)
├── service.py           ← MaskingService orchestrator
├── reporter.py          ← Rich terminal output
├── cli.py               ← argparse CLI entry point
├── app.py               ← CLI command implementations
├── config/
│   ├── enums.py         ← Strategy, Engine, FileFormat
│   ├── registry.py      ← PIIType, PIIRegistry
│   ├── crypto.py        ← AES-256-GCM helpers
│   ├── io.py            ← load/save routing
│   └── utils.py         ← exit_error helper
├── strategies/
│   ├── base.py          ← BaseMaskingStrategy, MaskingContext
│   ├── redact.py
│   ├── fake.py
│   ├── hash.py
│   ├── partial.py
│   ├── null.py
│   ├── keep.py
│   └── factory.py       ← StrategyFactory, FormatRegistry
└── adapters/
    ├── base.py           ← BaseDataFrameAdapter
    ├── polars_adapter.py
    ├── pandas_adapter.py
    ├── duckdb_adapter.py
    └── factory.py        ← AdapterFactory
```

---

## Integration Examples

### dbt post-hook

```bash
dbt run --select sensitive_model && \
  pii_masker mask target/run/sensitive_model.csv \
    --auto --strategy fake \
    -o exports/masked_sensitive_model.csv
```

### Apache Airflow

```python
from airflow.operators.bash import BashOperator

mask_pii = BashOperator(
    task_id="mask_pii",
    bash_command=(
        "pii_masker mask {{ params.input }} "
        "--auto --strategy redact "
        "--engine polars "
        "-o {{ params.output }}"
    ),
    params={"input": "/data/raw.parquet", "output": "/data/masked.parquet"},
)
```

### GitHub Actions — sanitize test fixtures

```yaml
- name: Mask PII in test fixtures
  run: |
    pii_masker mask tests/fixtures/users.csv \
      --columns email:phone:full_name \
      --strategy fake \
      --seed 42 \
      -o tests/fixtures/users_masked.csv
```

### Pre-commit hook — block raw PII from being committed

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: mask-pii
      name: Mask PII in fixture files
      language: system
      entry: pii_masker mask --auto --strategy redact --dry-run --report
      files: tests/fixtures/.*\.(csv|parquet)$
```

---

## Testing

The test suite lives in `tests/` and covers all layers — strategies, registry,
adapters, service, and CLI end-to-end.

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all 119 tests
python -m pytest

# Run with coverage report
python -m pytest --cov=pii_masker --cov-report=term-missing
```

| Test file            | Scope                                  | Tests   |
| -------------------- | -------------------------------------- | ------- |
| `test_strategies.py` | Unit — all 6 masking strategies        | 35      |
| `test_registry.py`   | Unit — PIIRegistry + FormatRegistry    | 15      |
| `test_adapters.py`   | Integration — Polars / Pandas / DuckDB | 34      |
| `test_service.py`    | Unit — MaskingService business logic   | 10      |
| `test_cli.py`        | End-to-end — real CLI via subprocess   | 25      |
| **Total**            |                                        | **119** |

---

## Examples

### Generate sample data first

```bash
python examples/generate_sample_data.py          # creates examples/data/sample.*
python examples/generate_sample_data.py --rows 50000  # larger dataset
```

### Python API examples (14 examples)

```bash
python examples/run_examples.py
```

All 14 examples use the façade API — each example imports only the feature it
needs:

| #   | Example                                    | Façade imports used                                  |
| --- | ------------------------------------------ | ---------------------------------------------------- |
| 01  | Detect PII columns                         | `detect_pii`, `report_detection`                     |
| 02  | Redact explicit columns                    | `mask_dataframe`, `Strategy.redact`                  |
| 03  | Auto-detect + redact                       | `mask_dataframe` with `auto=True`                    |
| 04  | Fake data with seed                        | `mask_dataframe`, `make_context(seed=42)`            |
| 05  | Hash with salt                             | `mask_dataframe`, `make_context(salt=...)`           |
| 06  | Partial masking — keep last 4 digits       | `mask_dataframe`, `make_context(partial_keep=4)`     |
| 07  | Null out sensitive columns                 | `mask_dataframe`, `Strategy.null`                    |
| 08  | Reversible AES-256-GCM mask + unmask       | `make_reversible_context`, `unmask_dataframe`        |
| 09  | All three engines side-by-side             | `create_adapter`, `Engine.polars/pandas/duckdb`      |
| 10  | Parquet round-trip                         | `load_data`, `save_data`, `FileFormat.parquet`       |
| 11  | Pipe simulation (stdin → stdout in memory) | `load_data(buf_in, FileFormat.csv)`                  |
| 12  | Dry run + masking report                   | `mask_dataframe(dry_run=True)`, `report_masking`     |
| 13  | Keep strategy (whitelist passthrough)      | `mask_dataframe`, `Strategy.keep`                    |
| 14  | Multi-strategy pipeline on one adapter     | Multiple `mask_dataframe` passes on the same adapter |

### Bash examples

```bash
bash examples/run_examples.sh
```

---

## Contributing

1. Fork the repo and create a feature branch.
2. Add or update tests in `tests/` — run `python -m pytest` before pushing.
3. To register a new PII type, add a `PIIType(...)` entry to `PIIRegistry._types` — no other file needs to change.
4. To add a new masking strategy, subclass `BaseMaskingStrategy`, implement `_apply()`, register it in `StrategyFactory`, and add the enum value to `Strategy`.
5. To add a new engine, subclass `BaseDataFrameAdapter`, implement all 7 methods, and register it in `AdapterFactory` and the `Engine` enum.
6. All public Python API additions go through `facade.py` — internal classes are not part of the public surface.

---

## License

MIT — see `LICENSE` for full text.
