# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
FuzzOrchestrator — top-level sweep pipeline coordinator.

Owns the EventRouter, instantiates the selected strategy, drives execution,
and delivers a SweepResult. All routing to downstream integrations (StingXSS,
BreachSQL, PhaseAccess) happens through EventHandlers registered on the router.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator

from commonhuman_sweep.models.context import SweepContext
from commonhuman_sweep.models.events import Confidence, Signal, SweepEvent, SweepResult
from commonhuman_sweep.pipeline.event_router import EventHandler, EventRouter
from commonhuman_sweep.strategies.base_strategy import BaseStrategy

log = logging.getLogger("sweep.orchestrator")


class FuzzOrchestrator:
    """
    Drives the sweep pipeline from start to finish.

    Usage:
        orchestrator = FuzzOrchestrator(context, strategy)
        orchestrator.register_handler(EventHandler("cli_output", print_event))
        result = await orchestrator.run()
    """

    def __init__(self, context: SweepContext, strategy: BaseStrategy) -> None:
        self._ctx      = context
        self._strategy = strategy
        self._router   = EventRouter()
        self._result   = SweepResult(
            target=context.target,
            strategy=strategy.name,
        )

    # ------------------------------------------------------------------
    # Handler registration (delegated to router)
    # ------------------------------------------------------------------

    def register_handler(self, handler: EventHandler) -> None:
        self._router.subscribe(handler)

    def register_bridge(self, bridge: object) -> None:
        """Register a bridge object if it exposes an EventHandler interface."""
        if hasattr(bridge, "as_handler"):
            self._router.subscribe(bridge.as_handler())  # type: ignore[attr-defined]
        else:
            raise TypeError(f"{bridge!r} does not expose as_handler()")

    # ------------------------------------------------------------------
    # Main run
    # ------------------------------------------------------------------

    async def run(self) -> SweepResult:
        log.info("Starting sweep: target=%s strategy=%s", self._ctx.target, self._strategy.name)

        async with self._router:
            async for event in self._strategy.execute(self._ctx):
                await self._router.emit(event)
                self._collect(event)

        self._result.finish()
        log.info(
            "Sweep complete: %d events (%d interesting) in %.1fs",
            len(self._result.events),
            len(self._result.interesting_events),
            self._result.duration_s,
        )
        return self._result

    # ------------------------------------------------------------------
    # Streaming interface (yields events AND routes them)
    # ------------------------------------------------------------------

    async def stream(self) -> AsyncIterator[SweepEvent]:
        """
        Yield events as they are produced while also routing them to handlers.

        Useful for CLI live output. The caller receives events in real time;
        the router delivers them to registered handlers concurrently.
        """
        async with self._router:
            async for event in self._strategy.execute(self._ctx):
                await self._router.emit(event)
                self._collect(event)
                yield event
        self._result.finish()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _collect(self, event: SweepEvent) -> None:
        self._result.events.append(event)
        self._result.requests_sent += 1
        if event.event == "sweep_baseline":
            self._result.endpoints_found += 1


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

async def run_sweep(context: SweepContext, handlers: list[EventHandler] | None = None) -> SweepResult:
    """
    One-shot sweep: build orchestrator, wire handlers, run, return result.

    Integrations can pre-build handlers and pass them here, or register
    bridges on the orchestrator directly.
    """
    from commonhuman_sweep.strategies import get_strategy

    strategy_cls = get_strategy(context.options.strategy)
    orchestrator = FuzzOrchestrator(context, strategy_cls())

    for handler in (handlers or []):
        orchestrator.register_handler(handler)

    # Auto-wire configured bridges
    if context.options.emit_to_stingxss:
        _try_wire_bridge(orchestrator, "commonhuman_sweep.integrations.stingxss_bridge", "StingXSSBridge")
    if context.options.emit_to_breachsql:
        _try_wire_bridge(orchestrator, "commonhuman_sweep.integrations.breachsql_bridge", "BreachSQLBridge")
    if context.options.emit_to_phaseaccess:
        _try_wire_bridge(orchestrator, "commonhuman_sweep.integrations.phaseaccess_bridge", "PhaseAccessBridge")

    return await orchestrator.run()


def _try_wire_bridge(orchestrator: FuzzOrchestrator, module_path: str, cls_name: str) -> None:
    try:
        import importlib
        mod = importlib.import_module(module_path)
        cls = getattr(mod, cls_name)
        orchestrator.register_handler(cls().as_handler())
    except ImportError:
        pass   # optional dependency not installed
    except Exception as exc:  # noqa: BLE001
        log.debug("Could not wire bridge %s: %r", cls_name, exc)
