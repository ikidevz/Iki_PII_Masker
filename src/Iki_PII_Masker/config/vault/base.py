from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

TokenFactory = Callable[[str], str]


class BaseTokenVault(ABC):
    """Abstract persistent token vault interface."""

    @abstractmethod
    def get_or_create(
        self,
        original: str,
        namespace: str,
        token_factory: TokenFactory | None = None,
    ) -> str:
        raise NotImplementedError

    @abstractmethod
    def reverse(self, token: str, namespace: str) -> str | None:
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError
