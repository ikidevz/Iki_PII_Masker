#!/usr/bin/env bash
# =============================================================================
# run_examples.sh — Runnable examples for every pii_masker feature.
#
# Usage:
#   cd <project_root>
#   bash examples/run_examples.sh
#
# Prerequisites:
#   pip install -e .
#   python examples/generate_sample_data.py
# =============================================================================

set -euo pipefail

DATA="examples/data/sample.csv"
OUT="examples/output"
TOOL="pii_masker"

mkdir -p "$OUT"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  pii_masker — live examples"
echo "══════════════════════════════════════════════════════"
echo ""

# ── 0. Detect PII columns ─────────────────────────────────────────────────────
echo "▶  0. Detect PII columns in sample.csv"
$TOOL detect "$DATA"
echo ""

# ── 1. Redact with auto-detect ────────────────────────────────────────────────
echo "▶  1. Auto-detect + redact → output/redacted.csv"
$TOOL mask "$DATA" \
    --auto \
    --strategy redact \
    --engine polars \
    --no-progress \
    -o "$OUT/redacted.csv"
echo "   First row preview:"
head -2 "$OUT/redacted.csv"
echo ""

# ── 2. Fake data (realistic replacements) ────────────────────────────────────
echo "▶  2. Fake data masking → output/faked.csv"
$TOOL mask "$DATA" \
    --columns "email:full_name:phone" \
    --strategy fake \
    --seed 42 \
    --no-progress \
    -o "$OUT/faked.csv"
echo "   Email column (first 3 rows):"
python3 -c "
import csv
with open('$OUT/faked.csv') as f:
    for i, row in enumerate(csv.DictReader(f)):
        if i >= 3: break
        print(f'   {row[\"email\"]}')
"
echo ""

# ── 3. Hash with salt ─────────────────────────────────────────────────────────
echo "▶  3. Hash user_id + email with salt → output/hashed.csv"
$TOOL mask "$DATA" \
    --columns "user_id:email" \
    --strategy hash \
    --salt "pepper_2024" \
    --no-progress \
    -o "$OUT/hashed.csv"
echo "   user_id column (first 3 rows):"
python3 -c "
import csv
with open('$OUT/hashed.csv') as f:
    for i, row in enumerate(csv.DictReader(f)):
        if i >= 3: break
        print(f'   {row[\"user_id\"]}')
"
echo ""

# ── 4. Partial masking ────────────────────────────────────────────────────────
echo "▶  4. Partial masking — keep last 4 digits of credit_card"
$TOOL mask "$DATA" \
    --columns "credit_card" \
    --strategy partial \
    --partial-keep 4 \
    --partial-side right \
    --no-progress \
    -o "$OUT/partial.csv"
echo "   credit_card column (first 3 rows):"
python3 -c "
import csv
with open('$OUT/partial.csv') as f:
    for i, row in enumerate(csv.DictReader(f)):
        if i >= 3: break
        print(f'   {row[\"credit_card\"]}')
"
echo ""

# ── 5. Null out sensitive columns ─────────────────────────────────────────────
echo "▶  5. Null out ssn + dob → output/nulled.csv"
$TOOL mask "$DATA" \
    --columns "ssn:dob" \
    --strategy null \
    --no-progress \
    -o "$OUT/nulled.csv"
echo ""

# ── 6. Reversible masking + unmask ────────────────────────────────────────────
echo "▶  6. Reversible masking → output/reversible.csv"
$TOOL mask "$DATA" \
    --columns "email:user_id" \
    --strategy redact \
    --reversible \
    --key "my-production-secret-2024" \
    --no-progress \
    -o "$OUT/reversible.csv"
echo "   Encrypted email (first row):"
python3 -c "
import csv
with open('$OUT/reversible.csv') as f:
    row = next(csv.DictReader(f))
    print(f'   {row[\"email\"][:60]}...')
"

echo ""
echo "▶  6b. Unmask reversible.csv → output/unmasked.csv"
$TOOL unmask "$OUT/reversible.csv" \
    --columns "email:user_id" \
    --key "my-production-secret-2024" \
    -o "$OUT/unmasked.csv"
echo "   Restored email (first row):"
python3 -c "
import csv
with open('$OUT/unmasked.csv') as f:
    row = next(csv.DictReader(f))
    print(f'   {row[\"email\"]}')
"
echo ""

# ── 7. DuckDB engine ──────────────────────────────────────────────────────────
echo "▶  7. DuckDB engine (large-file ready) → output/duckdb_redacted.csv"
$TOOL mask "$DATA" \
    --auto \
    --strategy redact \
    --engine duckdb \
    --no-progress \
    -o "$OUT/duckdb_redacted.csv"
echo ""

# ── 8. Pipe example ───────────────────────────────────────────────────────────
echo "▶  8. Pipe: cat | pii_masker | head"
cat "$DATA" \
    | $TOOL mask \
        --format csv \
        --columns "email:full_name" \
        --strategy fake \
        --seed 99 \
        --no-progress \
    | head -4
echo ""

# ── 9. Parquet round-trip ─────────────────────────────────────────────────────
echo "▶  9. Parquet: mask → output/masked.parquet"
$TOOL mask "examples/data/sample.parquet" \
    --auto \
    --strategy redact \
    --engine polars \
    --no-progress \
    -o "$OUT/masked.parquet"
echo ""

# ── 10. Dry run + report ──────────────────────────────────────────────────────
echo "▶  10. Dry run + report (no file written)"
$TOOL mask "$DATA" \
    --auto \
    --strategy fake \
    --dry-run \
    --report \
    --no-progress
echo ""

echo "══════════════════════════════════════════════════════"
echo "  All examples completed.  Output files in: $OUT/"
echo "══════════════════════════════════════════════════════"