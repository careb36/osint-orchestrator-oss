"""Base collector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from orchestrator.models import CollectorName, CollectorResult, Target


class BaseCollector(ABC):
    """Every collector implements this interface."""

    def __init__(self, target: Target) -> None:
        self.target = target

    @property
    @abstractmethod
    def name(self) -> CollectorName: ...

    @abstractmethod
    async def collect(self) -> CollectorResult:
        """
        Run the collection for self.target and return a CollectorResult.

        Must NOT raise — catch tool errors internally and return
        CollectorResult(success=False, error=...).
        """
        ...
