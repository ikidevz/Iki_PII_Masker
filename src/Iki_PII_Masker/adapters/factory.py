from ..config.enums import Engine
from .base import BaseDataFrameAdapter
from .polars_adapter import PolarsAdapter
from .pandas_adapter import PandasAdapter
from .duckdb_adapter import DuckDBAdapter


class AdapterFactory:
    @staticmethod
    def create(engine: Engine) -> BaseDataFrameAdapter:
        if engine == Engine.polars:
            return PolarsAdapter()
        if engine == Engine.duckdb:
            return DuckDBAdapter()
        return PandasAdapter()
