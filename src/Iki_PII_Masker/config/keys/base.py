from __future__ import annotations

from abc import ABC, abstractmethod


class BaseKeyProvider(ABC):
    """Abstract per-column key provider."""

    @abstractmethod
    def get_key(self, column: str) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def rotate(self, column: str) -> bytes:
        raise NotImplementedError
