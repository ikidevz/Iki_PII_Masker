from enum import Enum


class Strategy(str, Enum):
    redact = "redact"
    hash = "hash"
    fake = "fake"
    null = "null"
    partial = "partial"
    keep = "keep"


class Engine(str, Enum):
    polars = "polars"
    pandas = "pandas"
    duckdb = "duckdb"


class FileFormat(str, Enum):
    csv = "csv"
    parquet = "parquet"
    json = "json"
    ndjson = "ndjson"
    excel = "excel"
