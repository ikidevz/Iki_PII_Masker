from enum import Enum


class Strategy(str, Enum):
    redact = "redact"
    hash = "hash"
    fake = "fake"
    null = "null"
    partial = "partial"
    keep = "keep"
    tokenize = "tokenize"
    pseudonymize = "pseudonymize"
    generalize = "generalize"
    mask_format = "mask_format"


class Engine(str, Enum):
    polars = "polars"
    pandas = "pandas"
    duckdb = "duckdb"
    sql = "sql"       # SQLAlchemyAdapter
    xml = "xml"       # XMLAdapter
    jsonpath = "jsonpath"  # JSONPathAdapter


class FileFormat(str, Enum):
    csv = "csv"
    parquet = "parquet"
    json = "json"
    ndjson = "ndjson"
    excel = "excel"
    xml = "xml"
