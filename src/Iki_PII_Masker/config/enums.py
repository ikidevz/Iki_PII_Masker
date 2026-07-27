from enum import Enum


class Strategy(str, Enum):
    redact = "redact"
    hash = "hash"
    pbkdf2 = "pbkdf2"
    salted_hash = "salted_hash"
    hmac = "hmac"
    fake = "fake"
    null = "null"
    partial = "partial"
    truncate = "truncate"
    keep = "keep"
    tokenize = "tokenize"
    pseudonymize = "pseudonymize"
    shuffle = "shuffle"
    anonymize = "anonymize"
    perturb = "perturb"
    bucketize = "bucketize"
    generalize = "generalize"
    mask_format = "mask_format"
    ner_redact = "ner_redact"


class Engine(str, Enum):
    polars = "polars"
    pandas = "pandas"
    duckdb = "duckdb"
    sql = "sql"       # SQLAlchemyAdapter
    xml = "xml"       # XMLAdapter
    jsonpath = "jsonpath"  # JSONPathAdapter


class VaultBackend(str, Enum):
    sqlite = "sqlite"
    sqlalchemy = "sqlalchemy"


class FileFormat(str, Enum):
    csv = "csv"
    parquet = "parquet"
    json = "json"
    ndjson = "ndjson"
    excel = "excel"
    xml = "xml"
    feather = "feather"
    orc = "orc"
    pickle = "pickle"
    html = "html"
    fwf = "fwf"
    hdf5 = "hdf5"
    stata = "stata"
    spss = "spss"
    sas = "sas"
    avro = "avro"
    delta = "delta"
    ods = "ods"
    clipboard = "clipboard"
