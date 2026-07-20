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
echo "▶  3b. PBKDF2 hash user_id + email with secret key → output/pbkdf2_hashed.csv"
$TOOL mask "$DATA" \
    --columns "user_id:email" \
    --strategy pbkdf2 \
    --key "super_secret_pbkdf2_key_2024" \
    --no-progress \
    -o "$OUT/pbkdf2_hashed.csv"
echo "   user_id column (first 3 rows):"
python3 -c "
import csv
with open('$OUT/pbkdf2_hashed.csv') as f:
    for i, row in enumerate(csv.DictReader(f)):
        if i >= 3: break
        print(f'   {row["user_id"]}')
"
echo ""

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

echo "▶  6c. ChaCha20-Poly1305 reversible masking -> output/reversible_chacha.csv"
$TOOL mask "$DATA" \
    --columns "email:user_id" \
    --strategy redact \
    --reversible \
    --reversible-cipher chacha20-poly1305 \
    --key "my-production-secret-2024" \
    --no-progress \
    -o "$OUT/reversible_chacha.csv"
echo "   Encrypted email (first row):"
python3 -c "
import csv
with open('$OUT/reversible_chacha.csv') as f:
    row = next(csv.DictReader(f))
    print(f'   {row["email"][:60]}...')
"
echo ""

# ── 6d. AWS KMS envelope reversible masking ──────
echo "▶  6d. AWS KMS envelope reversible masking -> output/kms_reversible.csv"
$TOOL mask "$DATA" \
    --columns "email:user_id" \
    --strategy redact \
    --reversible \
    --reversible-cipher kms-envelope \
    --kms-provider aws \
    --kms-key-id alias/my-key \
    --kms-region us-east-1 \
    --kms-encryption-context purpose=pii-mask \
    --no-progress \
    -o "$OUT/kms_reversible.csv"
echo "   Encrypted email (first row):"
python3 -c "
import csv
with open('$OUT/kms_reversible.csv') as f:
    row = next(csv.DictReader(f))
    print(f'   {row["email"][:60]}...')
"
echo ""
echo "▶  6d. Unmask kms_reversible.csv -> output/kms_restored.csv"
$TOOL unmask "$OUT/kms_reversible.csv" \
    --columns "email:user_id" \
    --kms-provider aws \
    --kms-region us-east-1 \
    --kms-encryption-context purpose=pii-mask \
    -o "$OUT/kms_restored.csv"
echo "   Restored email (first row):"
python3 -c "
import csv
with open('$OUT/kms_restored.csv') as f:
    row = next(csv.DictReader(f))
    print(f'   {row["email"]}')
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

# ── 11. Pseudonymize — consistent fake replacements ─────────────────────────
echo "▶  11. Pseudonymize → output/pseudonymized.csv"
$TOOL mask "$DATA" \
    --columns "email:full_name" \
    --strategy pseudonymize \
    --seed 42 \
    --no-progress \
    -o "$OUT/pseudonymized.csv"
echo "   Pseudonymized values (first 3 rows):"
python3 -c "import csv; f=open('$OUT/pseudonymized.csv'); r=csv.DictReader(f); row=next(r); print(f'   {row[\"full_name\"]} | {row[\"email\"]}')"
echo ""
# ── 12. Tokenize — stable opaque tokens ────────────────────────────────────
echo "▶  12. Tokenize → output/tokenized.csv"
$TOOL mask "$DATA" \
    --columns "user_id:email" \
    --strategy tokenize \
    --no-progress \
    -o "$OUT/tokenized.csv"
echo "   Tokenized values (first row):"
python3 -c "import csv; f=open('$OUT/tokenized.csv'); r=csv.DictReader(f); row=next(r); print(f'   {row[\"user_id\"]} | {row[\"email\"]}')"
echo ""
# ── 13. Generalize — numeric ranges and date buckets ───────────────────────
echo "▶  13. Generalize → output/generalized.csv"
$TOOL mask "$DATA" \
    --columns "age:revenue:dob" \
    --strategy generalize \
    --no-progress \
    -o "$OUT/generalized.csv"
echo "   Generalized values (first 3 rows):"
python3 -c "import csv; f=open('$OUT/generalized.csv'); r=csv.DictReader(f); [print(f'   {row[\"age\"]} | {row[\"revenue\"]} | {row[\"dob\"]}') for _, row in zip(range(3), r)]"
echo ""
# ── 14. NER redaction — free-text entity masking (optional spaCy) ──────────

if python3 -c "import spacy" >/dev/null 2>&1; then
  echo "▶  14. NER redaction → output/ner_redacted.csv"
  $TOOL mask "$DATA" \
      --columns "notes" \
      --strategy ner_redact \
      --no-progress \
      -o "$OUT/ner_redacted.csv"
  echo "   Notes column (first 3 rows):"
  python3 -c "import csv; f=open('$OUT/ner_redacted.csv'); r=csv.DictReader(f); [print(f'   {row[\"notes\"]}') for _, row in zip(range(3), r)]"
else
  echo "▶  14. NER redaction skipped — install spaCy and run: pip install spacy && python -m spacy download en_core_web_sm"
fi

echo ""
# ── 15. MaskFormat — preserve separators ───────────────────────────────────
echo "▶  15. MaskFormat → output/mask_format.csv"
$TOOL mask "$DATA" \
    --columns "email:phone:credit_card" \
    --strategy mask_format \
    --no-progress \
    -o "$OUT/mask_format.csv"
echo "   MaskFormat output (first row):"
python3 -c "import csv; f=open('$OUT/mask_format.csv'); r=csv.DictReader(f); row=next(r); print(f'   {row[\"email\"]} | {row[\"phone\"]} | {row[\"credit_card\"]}')"
echo ""
# ── 15. Keep strategy — preserve selected columns ─────────────────────────
echo "▶  15. Keep strategy → output/keep.csv"
$TOOL mask "$DATA" \
    --columns "email:full_name:phone" \
    --strategy keep \
    --no-progress \
    -o "$OUT/keep.csv"
echo "   Keep strategy preserves original values."
echo ""
# ── 16. Truncate — preserve prefix, discard remainder ──────────────────────
echo "▶  16. Truncate → output/truncate.csv"
$TOOL mask "$DATA" \
    --columns "email:full_name" \
    --strategy truncate \
    --no-progress \
    -o "$OUT/truncate.csv"
echo "   Truncated values (first row):"
python3 -c "import csv; f=open('$OUT/truncate.csv'); r=csv.DictReader(f); row=next(r); print(f'   {row[\"email\"]} | {row[\"full_name\"]}')"
echo ""
# ── 17. Shuffle — randomize values within a column ─────────────────────────
echo "▶  17. Shuffle → output/shuffled.csv"
$TOOL mask "$DATA" \
    --columns "email" \
    --strategy shuffle \
    --seed 123 \
    --no-progress \
    -o "$OUT/shuffled.csv"
echo "   Shuffled email values (first 3 rows):"
python3 -c "import csv; f=open('$OUT/shuffled.csv'); r=csv.DictReader(f); [print(f'   {row[\"email\"]}') for _, row in zip(range(3), r)]"
echo ""
# ── 18. Anonymize — anonymous placeholders ─────────────────────────────────
echo "▶  18. Anonymize → output/anonymized.csv"
$TOOL mask "$DATA" \
    --columns "full_name:email" \
    --strategy anonymize \
    --seed 24 \
    --no-progress \
    -o "$OUT/anonymized.csv"
echo "   Anonymized values (first 3 rows):"
python3 -c "import csv; f=open('$OUT/anonymized.csv'); r=csv.DictReader(f); [print(f'   {row[\"full_name\"]} | {row[\"email\"]}') for _, row in zip(range(3), r)]"
echo ""
# ── 19. Bucketize — coarse value ranges ──────────────────────────────────
echo "▶  19. Bucketize → output/bucketized.csv"
$TOOL mask "$DATA" \
    --columns "age" \
    --strategy bucketize \
    --no-progress \
    -o "$OUT/bucketized.csv"
echo "   Bucketized age values (first 3 rows):"
python3 -c "import csv; f=open('$OUT/bucketized.csv'); r=csv.DictReader(f); [print(f'   {row[\"age\"]}') for _, row in zip(range(3), r)]"
echo ""
# ── 20. Salted hash — keyed deterministic hash ────────────────────────────
echo "▶  20. Salted hash → output/salted_hash.csv"
$TOOL mask "$DATA" \
    --columns "user_id:email" \
    --strategy salted_hash \
    --key "salted-secret-2026" \
    --no-progress \
    -o "$OUT/salted_hash.csv"
echo "   Salted hash output (first 3 rows):"
python3 -c "import csv; f=open('$OUT/salted_hash.csv'); r=csv.DictReader(f); [print(f'   {row[\"user_id\"]} | {row[\"email\"]}') for _, row in zip(range(3), r)]"
echo ""
# ── 21. HMAC hash — keyed deterministic hash ─────────────────────────────
echo "▶  21. HMAC hash → output/hmac_hash.csv"
$TOOL mask "$DATA" \
    --columns "user_id:email" \
    --strategy hmac \
    --key "hmac-secret-2026" \
    --no-progress \
    -o "$OUT/hmac_hash.csv"
echo "   HMAC hash output (first 3 rows):"
python3 -c "import csv; f=open('$OUT/hmac_hash.csv'); r=csv.DictReader(f); [print(f'   {row[\"user_id\"]} | {row[\"email\"]}') for _, row in zip(range(3), r)]"
echo ""
# ── 22. Verify output — ensure no PII remains ───────────────────────────
echo "▶  22. Verify output → output/verified.csv"
$TOOL mask "$DATA" \
    --columns "email:user_id" \
    --strategy redact \
    --verify \
    --no-progress \
    -o "$OUT/verified.csv"
echo "   Verified output written to $OUT/verified.csv"
echo ""
# ── 23. Profile YAML — load masking rules from a profile ───────────────────
echo "▶  23. Profile YAML → output/profile_yaml.csv"
if python3 -c "import yaml" >/dev/null 2>&1; then
  cat <<'YAML' > "$OUT/profile.yaml"
engine: polars
strategy: redact
auto: false
columns:
  email: fake
  phone: mask_format
  dob: generalize
  user_id: tokenize
YAML
  pii_masker validate-profile "$OUT/profile.yaml"
  $TOOL mask "$DATA" \
      --profile "$OUT/profile.yaml" \
      --no-progress \
      -o "$OUT/profile_yaml.csv"
  echo "   Profile-based masking output written to $OUT/profile_yaml.csv"
else
  echo "   Skip profile YAML examples — install pyyaml."
fi
echo ""
echo "══════════════════════════════════════════════════════"
echo "══════════════════════════════════════════════════════"
echo "  All examples completed.  Output files in: $OUT/"
echo "══════════════════════════════════════════════════════"