# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BaseStrategy — abstract interface for all sweep strategies.

Strategies are independent, pluggable scan modes. Each one knows how to:
  1. discover() — find candidate requests from a SweepContext
  2. execute() — run its probes and yield SweepEvent objects

Strategies are not aware of the event bus or downstream consumers. They
yield events; the pipeline layer routes them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from commonhuman_sweep.models.context import SweepContext
from commonhuman_sweep.models.events import SweepEvent, SweepRequest


@dataclass
class StrategyResult:
    """Lightweight summary returned after a strategy completes."""

    strategy:      str
    events_emitted: int        = 0
    requests_sent: int         = 0
    errors:        list[str]   = field(default_factory=list)


class BaseStrategy(ABC):
    """
    Abstract base for all sweep strategies.

    Implementations must be independently testable — they accept a SweepContext
    and yield SweepEvent objects. No direct I/O side-effects beyond HTTP.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier used in events and CLI output."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description shown in --help and verbose output."""

    @abstractmethod
    async def discover(self, context: SweepContext) -> list[SweepRequest]:
        """
        Discover the set of candidate requests to probe.

        Called once before execute(). May perform crawling, API spec parsing,
        or any other surface discovery technique. The result is a list of
        baseline SweepRequest objects that execute() will mutate.
        """

    @abstractmethod
    async def execute(self, context: SweepContext) -> AsyncIterator[SweepEvent]:
        """
        Execute the strategy and yield SweepEvent objects.

        Implementations should be fully async. They receive the full SweepContext
        (including any URLs discovered by discover()) and yield events as they
        are produced — not after the entire run completes.
        """

    # ------------------------------------------------------------------
    # Shared utilities available to all strategies
    # ------------------------------------------------------------------

    def _make_event(
        self,
        request: SweepRequest,
        response,
        classification,
        target: str,
        mutation_type: str = "",
        parameter: str = "",
        extra: dict | None = None,
    ) -> SweepEvent:
        from commonhuman_sweep.models.events import Confidence, SweepEvent

        event_name = "sweep_result"
        if any(s.value.startswith("anomal") for s in classification.signals):
            event_name = "sweep_anomaly"

        return SweepEvent(
            event=event_name,
            target=target,
            request=request,
            response=response,
            signals=classification.signals,
            confidence=classification.confidence,
            strategy=self.name,
            mutation=mutation_type,
            parameter=parameter,
            extra=extra or {},
        )
