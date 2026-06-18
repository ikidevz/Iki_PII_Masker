# Iki_PII_Masker

> **Do one thing well: mask PII data.**

A production-grade, pipe-friendly CLI tool and Python library for data
engineers and analysts who need to sanitize datasets fast — without wrestling
with config files or heavyweight frameworks.

![img](assets/readme.png)

```bash
pii_masker mask data.csv --auto --strategy fake -o clean.csv
```

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![License MIT](https://img.shields.io/badge/license-MIT-green)
![Engine](https://img.shields.io/badge/engine-Polars%20%7C%20Pandas%20%7C%20DuckDB%20%7C%20SQLAlchemy-orange)

---

## Features

| Feature                   | Details                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **10 masking strategies** | `fake`, `redact`, `hash`, `null`, `partial`, `keep`, `tokenize`, `pseudonymize`, `generalize`, `mask_format` |
| **Reversible masking**    | AES-256-GCM — restore originals anytime with `--key`                                                         |
| **Dual PII detection**    | Column-name heuristics + cell-value scanning (`detect_pii_by_value`)                                         |
| **Multi-engine**          | Polars, Pandas, DuckDB, SQLAlchemy (live DB), XML, JSONPath                                                  |
| **6 file formats**        | CSV, Parquet, JSON, NDJSON, Excel, XML                                                                       |
| **Pipe-friendly**         | stdin → stdout, zero config required                                                                         |
| **Reproducible fakes**    | `--seed` for deterministic output in CI/testing                                                              |
| **Dry run + report**      | Preview masking plan before touching any data                                                                |
| **PII detector**          | `detect` subcommand scans columns and cell values, prints sample values                                      |
| **Profile-driven config** | `ProfileConfig` + `ColumnRuleMap` — load masking rules from YAML or Python dict                              |
| **Python façade API**     | Import by feature — no internal sub-packages exposed                                                         |

---

## Installation

```bash
# from PyPI
pip install iki-pii-masker
```

**Requirements:** Python 3.9+

**Core dependencies:** `rich`, `polars`, `pandas`, `faker`,
`cryptography`, `pyarrow`, `openpyxl`, `duckdb`

**Optional extras:**

```bash
pip install sqlalchemy psycopg2-binary   # SQLAlchemy adapter (live database)
pip install jsonpath-ng                  # JSONPath adapter (nested JSON)
pip install pyyaml                       # ProfileConfig YAML support
# XML uses stdlib xml.etree — no install needed (lxml optional for speed)
```

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
cat raw.csv | pii_masker mask --format csv --strategy fake > clean.csv

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

### Reproducible fake data (CI / snapshot tests)

```bash
pii_masker mask data.csv --columns email:name --strategy fake --seed 42 -o masked.csv
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

| Strategy       | Output example     | Reversible?         | Best for                                         |
| -------------- | ------------------ | ------------------- | ------------------------------------------------ |
| `fake`         | `alice@fake.com`   | No                  | Realistic test/dev data                          |
| `redact`       | `[EMAIL]`          | With `--reversible` | Audit logs, shared reports                       |
| `hash`         | `SHA:3d7a2c1e9b4f` | With `--reversible` | Join keys, deduplication                         |
| `null`         | `null`             | No                  | Dropping PII for analytics                       |
| `partial`      | `****1234`         | No                  | Card numbers, phone numbers                      |
| `keep`         | original value     | N/A                 | Whitelisting non-PII columns                     |
| `tokenize`     | `TOK-3d7a2c1e`     | Via token table     | Stable opaque tokens; cross-run lookup possible  |
| `pseudonymize` | `Barbara Clark`    | Via mapping dict    | Consistent fakes — same input → same fake output |
| `generalize`   | `30-40` / `1990`   | No                  | Analytics bucketing — ages, dates, zip codes     |
| `mask_format`  | `xxxx@xxxxxxx.xxx` | No                  | Format-preserving masking; keeps separators      |

### New strategy details

**`tokenize`** — replaces each value with a stable `TOK-<hex>` token. The same
input always maps to the same token within a run. Access the lookup table via
`TokenizeStrategy.token_table` or reverse a token with `.detokenize(token)`.

**`pseudonymize`** — like `fake` but consistent: the same real name always
becomes the same fake name. This preserves referential integrity across tables
— a `user_id` that appears in five tables will map to the same fake ID in all
five after masking.

**`generalize`** — coarsens precise values into broader ranges. Numerics become
range buckets (`34` → `30-40`), dates are truncated to year or month
(`1990-07-15` → `1990`), and strings are prefix-masked (`SW1A2AA` → `SW1****`).

**`mask_format`** — replaces alphanumeric characters with `*` while keeping
structural separators (`.`, `-`, `@`, spaces, brackets) in place. An email like
`john@corp.com` becomes `xxxx@xxxx.xxx` — the shape is preserved so
format-sensitive downstream systems still parse it correctly.

---

## Full Option Reference

### `pii_masker mask`

```
Arguments:
  [INPUT_FILE]              Input file path. Omit to read from stdin.

Options:
  -o, --output PATH         Output file path. Omit to write to stdout.
  -c, --columns TEXT        Colon-separated column names. e.g. email:name:phone
  -s, --strategy STRATEGY   fake|redact|hash|null|partial|keep|
                            tokenize|pseudonymize|generalize|mask_format
                            [default: redact]
  -e, --engine ENGINE       polars|pandas|duckdb  [default: polars]
  -f, --format FORMAT       csv|parquet|json|ndjson|excel|xml
                            (auto-detected from extension)
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

Every feature is accessible through the façade module.
Import only what you need — no internal sub-packages, no internal classes.

```python
from Iki_PII_Masker.facade import detect_pii              # column-name PII detection
from Iki_PII_Masker.facade import detect_pii_by_value     # cell-value PII detection
from Iki_PII_Masker.facade import mask_dataframe           # apply any strategy
from Iki_PII_Masker.facade import unmask_dataframe         # reverse AES masking
from Iki_PII_Masker.facade import load_data, save_data     # file I/O
from Iki_PII_Masker.facade import make_context, make_reversible_context
from Iki_PII_Masker.facade import derive_encryption_key
from Iki_PII_Masker.facade import create_adapter           # polars / pandas / duckdb
from Iki_PII_Masker.facade import create_sql_adapter       # live relational database
from Iki_PII_Masker.facade import create_xml_adapter       # XML documents
from Iki_PII_Masker.facade import create_jsonpath_adapter  # nested JSON
from Iki_PII_Masker.facade import report_detection, report_masking
from Iki_PII_Masker.facade import ProfileConfig, ColumnRuleMap
from Iki_PII_Masker.facade import Strategy, Engine, FileFormat
```

### Façade feature reference

| Feature                                                | What it does                                                           |
| ------------------------------------------------------ | ---------------------------------------------------------------------- |
| `detect_pii(columns)`                                  | Scan column _names_ → `{col: PIIType}` for every PII match             |
| `detect_pii_by_value(adapter, sample_rows, threshold)` | Scan actual cell _values_ — catches generic column names like `col_7`  |
| `mask_dataframe(adapter, columns, strategy, context)`  | Apply any of 10 strategies to named columns; returns elapsed seconds   |
| `unmask_dataframe(adapter, columns, key)`              | Reverse AES-256-GCM masking in-place                                   |
| `load_data(adapter, source, fmt)`                      | Load a file, path, `BytesIO`, or `None` (stdin) into an adapter        |
| `save_data(adapter, dest, fmt)`                        | Write adapter data to a file, `BytesIO`, or `None` (stdout)            |
| `make_context(**kwargs)`                               | Build a plain `MaskingContext` (salt, seed, partial options)           |
| `make_reversible_context(secret)`                      | Build a context that AES-encrypts every value; key derived from secret |
| `derive_encryption_key(secret)`                        | Derive 32-byte AES key from a secret string                            |
| `create_adapter(engine)`                               | Instantiate a Polars, Pandas, or DuckDB adapter                        |
| `create_sql_adapter(url, table)`                       | Mask a live database table via SQLAlchemy                              |
| `create_xml_adapter(xpath, fields)`                    | Mask XML documents by XPath row selector                               |
| `create_jsonpath_adapter(paths)`                       | Mask nested JSON by JSONPath expressions                               |
| `ProfileConfig.from_yaml(path)`                        | Load masking rules from a YAML file                                    |
| `ProfileConfig.from_dict(data)`                        | Build masking rules from a Python dict                                 |
| `ColumnRuleMap({col: Strategy})`                       | Per-column strategy map with a single `.apply(adapter)` call           |
| `report_detection(adapter, detected, file)`            | Print Rich PII detection table with sample values                      |
| `report_masking(adapter, col_map, strategy, elapsed)`  | Print Rich masking summary table                                       |

### Detection

**Column-name detection** (fast, zero I/O):

```python
from Iki_PII_Masker.facade import detect_pii, report_detection
from Iki_PII_Masker.facade import create_adapter, load_data, Engine
from pathlib import Path

adapter  = create_adapter(Engine.polars)
load_data(adapter, Path("data.csv"))

detected = detect_pii(adapter.columns)
report_detection(adapter, detected, Path("data.csv"), samples=3)
```

**Cell-value detection** (catches generic column names like `col_7`):

```python
from Iki_PII_Masker.facade import detect_pii, detect_pii_by_value

name_hits  = detect_pii(adapter.columns)
value_hits = detect_pii_by_value(adapter, sample_rows=100, existing=name_hits)
all_found  = {**name_hits, **value_hits}
```

### Masking strategies

**Fake data (reproducible):**

```python
from Iki_PII_Masker.facade import mask_dataframe, make_context, Strategy

mask_dataframe(adapter, "email:full_name:phone", Strategy.fake, make_context(seed=42))
```

**Pseudonymize — consistent fakes (preserves referential integrity):**

```python
# Same "Alice Smith" in every table → same fake name everywhere
mask_dataframe(adapter, "full_name:email", Strategy.pseudonymize, make_context(seed=1))
```

**Tokenize — stable opaque tokens:**

```python
# user_id → TOK-3d7a2c1e  (same input = same token within the run)
mask_dataframe(adapter, "user_id", Strategy.tokenize)
```

**Generalize — coarsen to ranges / year buckets:**

```python
# 34 → "30-40",  1990-07-15 → "1990",  SW1A2AA → "SW1****"
mask_dataframe(adapter, "age:dob:zip", Strategy.generalize)
```

**MaskFormat — preserve structural separators:**

```python
# john@corp.com → xxxx@xxxx.xxx,  4111-1234-5678-9000 → ****-****-****-****
mask_dataframe(adapter, "email:credit_card", Strategy.mask_format)
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
    mask_dataframe, unmask_dataframe,
    make_reversible_context, derive_encryption_key, Strategy,
)

SECRET = "my-production-secret-2024"

mask_dataframe(adapter, "email:user_id", Strategy.redact,
               make_reversible_context(SECRET))
save_data(adapter, Path("masked.csv"))

# Restore
key = derive_encryption_key(SECRET)
load_data(adapter2, Path("masked.csv"))
unmask_dataframe(adapter2, ["email", "user_id"], key)
```

**Multi-strategy pipeline on one adapter:**

```python
mask_dataframe(adapter, "email:full_name",  Strategy.pseudonymize, make_context(seed=42))
mask_dataframe(adapter, "credit_card",      Strategy.mask_format)
mask_dataframe(adapter, "dob:age",          Strategy.generalize)
mask_dataframe(adapter, "user_id",          Strategy.tokenize)
mask_dataframe(adapter, "password:ssn",     Strategy.null)
```

### Adapters

**Standard adapters (Polars / Pandas / DuckDB):**

```python
from Iki_PII_Masker.facade import create_adapter, Engine

adapter = create_adapter(Engine.polars)   # fastest general-purpose
adapter = create_adapter(Engine.pandas)   # use for Excel I/O
adapter = create_adapter(Engine.duckdb)   # use for files larger than RAM
```

**SQLAlchemy adapter — mask a live database table:**

```python
from Iki_PII_Masker.facade import create_sql_adapter, mask_dataframe, Strategy

# Requires: pip install sqlalchemy psycopg2-binary
adapter = create_sql_adapter(
    url="postgresql+psycopg2://user:pass@localhost/mydb",
    table="users",
    id_column="id",
    chunk_size=500,
)
adapter.load()   # fetches all rows into memory
mask_dataframe(adapter, "email:phone", Strategy.fake)
adapter.save()   # writes batched UPDATEs back to the database
```

Supported databases: PostgreSQL, MySQL, MariaDB, SQLite, MS SQL Server, Oracle
(anything with a SQLAlchemy driver).

**XML adapter — mask XML documents by XPath:**

```python
from Iki_PII_Masker.facade import create_xml_adapter, load_data, save_data, mask_dataframe

# Requires no extra install — uses stdlib xml.etree (or lxml if installed)
adapter = create_xml_adapter(
    xpath="//user",                      # repeating row element
    pii_fields=["email", "phone", "name"],
)
load_data(adapter, Path("users.xml"))
mask_dataframe(adapter, "email:phone:name", Strategy.fake)
save_data(adapter, Path("masked.xml"))
```

**JSONPath adapter — mask nested JSON:**

```python
from Iki_PII_Masker.facade import create_jsonpath_adapter

# Requires: pip install jsonpath-ng
adapter = create_jsonpath_adapter({
    "email": "$.users[*].contact.email",
    "phone": "$.users[*].contact.phone",
})
load_data(adapter, Path("data.json"))
mask_dataframe(adapter, "email:phone", Strategy.redact)
save_data(adapter, Path("masked.json"))
```

### Profile-driven masking

**`ColumnRuleMap`** — apply per-column strategies in a single call:

```python
from Iki_PII_Masker.facade import ColumnRuleMap, Strategy, make_context

rules = ColumnRuleMap({
    "email":       Strategy.fake,
    "full_name":   Strategy.pseudonymize,
    "credit_card": Strategy.partial,
    "ssn":         Strategy.null,
    "user_id":     Strategy.hash,
})
rules.apply(adapter, make_context(seed=42))
```

**`ProfileConfig`** — load rules from a YAML file:

```yaml
# masking_profile.yaml
engine: polars
strategy: redact # default for auto-detected columns
seed: 42
auto: true # also auto-detect any PII not listed below
columns:
  email: fake
  full_name: pseudonymize
  credit_card: partial
  ssn: null
  user_id: tokenize
  dob: generalize
  phone: mask_format
```

```python
from Iki_PII_Masker.facade import ProfileConfig, create_adapter

profile = ProfileConfig.from_yaml("masking_profile.yaml")
adapter = create_adapter(profile.engine)
load_data(adapter, Path("data.csv"))
profile.apply(adapter)
save_data(adapter, Path("masked.csv"))
```

Or build a profile in Python without a file:

```python
profile = ProfileConfig.from_dict({
    "engine":   "polars",
    "strategy": "redact",
    "seed":     42,
    "auto":     True,
    "columns": {
        "email":     "fake",
        "ssn":       "null",
        "user_id":   "tokenize",
        "full_name": "pseudonymize",
    },
})
profile.apply(adapter)
```

Save a profile back to YAML for reuse:

```python
profile.to_yaml("masking_profile.yaml")
```

### In-memory pipe (BytesIO)

```python
import io
from Iki_PII_Masker.facade import create_adapter, load_data, save_data
from Iki_PII_Masker.facade import mask_dataframe, make_context, Strategy, Engine, FileFormat

buf_in  = io.BytesIO(open("data.csv", "rb").read())
adapter = create_adapter(Engine.polars)
load_data(adapter, buf_in, FileFormat.csv)
mask_dataframe(adapter, "email:full_name", Strategy.fake, make_context(seed=99))

buf_out = io.BytesIO()
save_data(adapter, buf_out, FileFormat.csv)
```

---

## PII Auto-Detection

### Column-name detection

The `--auto` flag, `detect` command, and `detect_pii()` match column names
against regex heuristics for ten built-in PII types:

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

### Cell-value detection

`detect_pii_by_value()` scans actual cell values with regex patterns — it
catches columns with generic names (`col_7`, `field_2`) that still contain
Social Security numbers, credit card numbers, emails, and so on.

```python
from Iki_PII_Masker.facade import detect_pii, detect_pii_by_value

# Step 1 — fast name-based scan
name_hits  = detect_pii(adapter.columns)

# Step 2 — deeper value scan for anything missed
value_hits = detect_pii_by_value(adapter, sample_rows=100, threshold=0.3)

# Combined results
all_found  = {**name_hits, **value_hits}
```

`threshold` is the fraction of sampled non-null values that must match a
pattern before a column is flagged (default `0.3` = 30 %).

### Register a custom PII type

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

| Engine | Strategy       | Time | Notes                         |
| ------ | -------------- | ---- | ----------------------------- |
| Polars | `redact`       | ~4s  | Best all-rounder              |
| Polars | `hash`         | ~5s  |                               |
| Polars | `fake`         | ~18s |                               |
| Polars | `pseudonymize` | ~19s | Slightly slower than fake     |
| Polars | `tokenize`     | ~6s  | Fast — SHA-256 based          |
| Polars | `generalize`   | ~5s  |                               |
| Polars | `mask_format`  | ~6s  |                               |
| DuckDB | `redact`       | ~4s  | Handles files larger than RAM |
| DuckDB | `fake`         | ~19s |                               |
| Pandas | `redact`       | ~9s  | Use for Excel I/O             |
| Pandas | `fake`         | ~35s |                               |

Polars is the default for speed. Use **DuckDB** when your file is too large to
fit in memory. Use **Pandas** only when you need Excel I/O or tight ecosystem
integration. Use **SQLAlchemy** for masking data directly in a live database
without exporting to files first.

---

## Architecture

`pii_masker` is built around five design patterns that keep it easy to extend
without touching existing code:

**Strategy** — each masking algorithm is an independent class. Adding a new
algorithm means adding one file; no existing code changes.

**Registry** — `PIIRegistry` is the single source of truth for all PII
metadata. Adding a new PII type is one entry in one place.

**Adapter** — all engines expose an identical interface to the rest of the
codebase. Swapping or adding an engine requires one new class.

**Factory** — `StrategyFactory`, `AdapterFactory`, and `FormatRegistry`
centralise all object creation so CLI functions contain zero branching logic.

**Façade** — `facade.py` is the single public door into the Python API.
Every capability is exposed as a named action function so callers never import
from internal sub-packages directly.

### Package layout

```
src/Iki_PII_Masker/
├── facade.py                  ← public Python API (import from here)
├── service.py                 ← MaskingService orchestrator
├── reporter.py                ← Rich terminal output
├── cli.py                     ← argparse CLI entry point
├── app.py                     ← CLI command implementations
├── config/
│   ├── enums.py               ← Strategy, Engine, FileFormat
│   ├── registry.py            ← PIIType, PIIRegistry
│   ├── crypto.py              ← AES-256-GCM helpers
│   ├── io.py                  ← load/save routing
│   ├── value_detector.py      ← ValuePatternDetector (cell-value PII scan)
│   ├── xml_io.py              ← XMLAdapter
│   ├── jsonpath_io.py         ← JSONPathAdapter
│   ├── profile.py             ← ProfileConfig, ColumnRuleMap
│   └── utils.py               ← exit_error helper
├── strategies/
│   ├── base.py                ← BaseMaskingStrategy, MaskingContext
│   ├── redact.py
│   ├── fake.py
│   ├── hash.py
│   ├── partial.py
│   ├── null.py
│   ├── keep.py
│   ├── tokenize.py            ← TokenizeStrategy
│   ├── pseudonymize.py        ← PseudonymizeStrategy
│   ├── generalize.py          ← GeneralizeStrategy
│   ├── mask_format.py         ← MaskFormatStrategy
│   └── factory.py             ← StrategyFactory, FormatRegistry
└── adapters/
    ├── base.py                ← BaseDataFrameAdapter
    ├── polars_adapter.py
    ├── pandas_adapter.py
    ├── duckdb_adapter.py
    ├── sqlalchemy_adapter.py  ← SQLAlchemyAdapter
    └── factory.py             ← AdapterFactory
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

### Profile-driven CI masking

```yaml
# .github/workflows/mask.yml
- name: Apply masking profile
  run: |
    python - <<'EOF'
    from Iki_PII_Masker.facade import ProfileConfig, create_adapter, load_data, save_data
    from pathlib import Path

    profile = ProfileConfig.from_yaml("masking_profile.yaml")
    adapter = create_adapter(profile.engine)
    load_data(adapter, Path("data/raw.csv"))
    profile.apply(adapter)
    save_data(adapter, Path("data/masked.csv"))
    EOF
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

### Mask a PostgreSQL table directly

```python
from Iki_PII_Masker.facade import (
    create_sql_adapter, mask_dataframe, Strategy, make_context
)

adapter = create_sql_adapter(
    url="postgresql+psycopg2://user:pass@localhost/prod",
    table="customers",
)
adapter.load()
mask_dataframe(adapter, "email:phone:full_name", Strategy.fake, make_context(seed=42))
adapter.save()
```

---

## Testing

The test suite lives in `tests/` and covers all layers.

```bash
# Install dev dependencies
pip install -e ".[dev]"
pip install sqlalchemy jsonpath-ng pyyaml    # optional adapters

# Run all 207 tests
python -m pytest

# Run with coverage report
python -m pytest --cov=pii_masker --cov-report=term-missing

# Run a single file
python -m pytest tests/test_strategies.py -v
```

| Test file            | Scope                                                           | Tests   |
| -------------------- | --------------------------------------------------------------- | ------- |
| `test_strategies.py` | Unit — all 10 masking strategies                                | 77      |
| `test_registry.py`   | Unit — PIIRegistry, FormatRegistry, ValuePatternDetector        | 23      |
| `test_adapters.py`   | Integration — Polars, Pandas, DuckDB, SQLAlchemy, XML, JSONPath | 56      |
| `test_service.py`    | Unit — MaskingService + façade wrapper                          | 19      |
| `test_profile.py`    | Unit — ProfileConfig + ColumnRuleMap                            | 17      |
| `test_cli.py`        | End-to-end — real CLI via subprocess                            | 15      |
| **Total**            |                                                                 | **207** |

---

## Examples

### Generate sample data first

```bash
python examples/generate_sample_data.py          # creates examples/data/sample.*
python examples/generate_sample_data.py --rows 50000
```

### Python API examples (22 examples)

```bash
python examples/run_examples.py
```

| #   | Example                                     | Façade feature used                                |
| --- | ------------------------------------------- | -------------------------------------------------- |
| 01  | Detect PII by column name                   | `detect_pii`, `report_detection`                   |
| 02  | Detect PII by cell values                   | `detect_pii_by_value`                              |
| 03  | Redact explicit columns                     | `mask_dataframe`, `Strategy.redact`                |
| 04  | Fake data with seed                         | `mask_dataframe`, `make_context(seed=42)`          |
| 05  | Pseudonymize — consistent fakes             | `Strategy.pseudonymize`                            |
| 06  | Tokenize — stable opaque tokens             | `Strategy.tokenize`                                |
| 07  | Generalize — ranges and year buckets        | `Strategy.generalize`                              |
| 08  | MaskFormat — preserve structural separators | `Strategy.mask_format`                             |
| 09  | Hash with salt                              | `Strategy.hash`, `make_context(salt=...)`          |
| 10  | Partial masking — keep last 4 digits        | `Strategy.partial`, `make_context(partial_keep=4)` |
| 11  | Null out sensitive columns                  | `Strategy.null`                                    |
| 12  | Reversible AES-256-GCM mask + unmask        | `make_reversible_context`, `unmask_dataframe`      |
| 13  | All three standard engines                  | `create_adapter`, `Engine.polars/pandas/duckdb`    |
| 14  | SQLAlchemy — mask a live SQLite table       | `create_sql_adapter`                               |
| 15  | XML adapter — XPath-based masking           | `create_xml_adapter`                               |
| 16  | JSONPath adapter — nested JSON masking      | `create_jsonpath_adapter`                          |
| 17  | ColumnRuleMap — per-column strategy map     | `ColumnRuleMap`                                    |
| 18  | ProfileConfig from dict                     | `ProfileConfig.from_dict`                          |
| 19  | ProfileConfig from YAML file                | `ProfileConfig.from_yaml`, `profile.to_yaml`       |
| 20  | Pipe simulation — BytesIO in-memory         | `load_data(buf, FileFormat.csv)`                   |
| 21  | Dry run + masking report                    | `mask_dataframe(dry_run=True)`, `report_masking`   |
| 22  | Multi-strategy pipeline on one adapter      | Multiple `mask_dataframe` passes                   |

---

## Contributing

1. Fork the repo and create a feature branch.
2. Add or update tests in `tests/` — run `python -m pytest` before pushing.
3. To register a new PII type, add a `PIIType(...)` entry to `PIIRegistry._types` — no other file needs to change.
4. To add a new masking strategy, subclass `BaseMaskingStrategy`, implement `_apply()`, register it in `StrategyFactory`, and add the enum value to `Strategy`.
5. To add a new engine, subclass `BaseDataFrameAdapter`, implement all required methods, and register it in `AdapterFactory` and the `Engine` enum.
6. All public Python API additions go through `facade.py` — internal classes are not part of the public surface.
7. New optional adapters (SQLAlchemy, XML, JSONPath) live in `config/` or `adapters/` and are imported lazily inside their factory functions so the core package has no extra hard dependencies.

---

## License

MIT — see `LICENSE` for full text.
