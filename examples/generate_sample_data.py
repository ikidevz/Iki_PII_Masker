#!/usr/bin/env python3
"""
generate_sample_data.py — Generate realistic sample datasets for pii_masker examples.

Outputs:
    examples/data/sample.csv
    examples/data/sample.parquet
    examples/data/sample.json
    examples/data/sample.ndjson

Usage:
    python examples/generate_sample_data.py
    python examples/generate_sample_data.py --rows 10000
"""

import argparse
import json
import sys
from pathlib import Path

# ── optional deps ─────────────────────────────────────────────────────────────
try:
    import polars as pl
except ImportError:
    sys.exit("polars is required: pip install polars")

try:
    from faker import Faker
except ImportError:
    sys.exit("faker is required: pip install faker")


def generate(rows: int, seed: int) -> pl.DataFrame:
    Faker.seed(seed)
    fake = Faker()

    data = {
        "id":          list(range(1, rows + 1)),
        "full_name":   [fake.name() for _ in range(rows)],
        "email":       [fake.email() for _ in range(rows)],
        "phone":       [fake.phone_number() for _ in range(rows)],
        "age":         [fake.random_int(min=18, max=80) for _ in range(rows)],
        "dob":         [str(fake.date_of_birth()) for _ in range(rows)],
        "ssn":         [fake.ssn() for _ in range(rows)],
        "address":     [fake.address().replace("\n", ", ") for _ in range(rows)],
        "ip_address":  [fake.ipv4() for _ in range(rows)],
        "credit_card": [fake.credit_card_number() for _ in range(rows)],
        "user_id":     [f"usr_{fake.uuid4()[:8]}" for _ in range(rows)],
        "password":    [fake.password() for _ in range(rows)],
        "department":  [fake.job() for _ in range(rows)],
        "revenue":     [round(fake.pyfloat(min_value=100, max_value=50000, right_digits=2), 2)
                        for _ in range(rows)],
        "country":     [fake.country_code() for _ in range(rows)],
        "created_at":  [str(fake.date_time_this_decade()) for _ in range(rows)],
    }
    return pl.DataFrame(data)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate sample PII datasets.")
    parser.add_argument("--rows", type=int, default=1000,
                        help="Number of rows (default: 1000)")
    parser.add_argument("--seed", type=int, default=42,
                        help="RNG seed (default: 42)")
    parser.add_argument("--out",  type=Path,
                        default=Path(__file__).parent / "data",
                        help="Output directory")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    df = generate(args.rows, args.seed)

    # CSV
    csv_path = args.out / "sample.csv"
    df.write_csv(csv_path)
    print(f"✓ {csv_path}  ({args.rows} rows)")

    # Parquet
    parquet_path = args.out / "sample.parquet"
    df.write_parquet(parquet_path)
    print(f"✓ {parquet_path}")

    # JSON
    json_path = args.out / "sample.json"
    df.write_json(json_path)
    print(f"✓ {json_path}")

    # NDJSON
    ndjson_path = args.out / "sample.ndjson"
    df.write_ndjson(ndjson_path)
    print(f"✓ {ndjson_path}")

    print(f"\nColumns: {', '.join(df.columns)}")
    print(f"PII columns: full_name, email, phone, dob, ssn, address, ip_address, "
          f"credit_card, user_id, password, age")
    print(f"\nNext step:")
    print(f"  python examples/run_examples.py")


if __name__ == "__main__":
    main()
