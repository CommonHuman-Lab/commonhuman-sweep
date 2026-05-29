# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
EventRouter — async pub/sub event bus for the sweep pipeline.

The sweep engine emits SweepEvent objects into the router. Downstream
consumers (StingXSS bridge, BreachSQL bridge, PhaseAccess bridge, live
CLI output) subscribe with filter predicates and async handler coroutines.

Design:
  - Zero external dependencies (stdlib asyncio only)
  - Handlers run concurrently per event (fan-out)
  - Handler failures are isolated — one bad handler never drops events to others
  - Filter predicates let each subscriber opt-in to only the signals it cares about
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from commonhuman_sweep.models.events import SweepEvent

log = logging.getLogger("sweep.event_router")

EventHandlerFn = Callable[[SweepEvent], Coroutine[Any, Any, None]]
FilterFn       = Callable[[SweepEvent], bool]


@dataclass
class EventHandler:
    """A named, optionally filtered async event handler."""

    name:     str
    fn:       EventHandlerFn
    filter:   FilterFn | None = None

    async def handle(self, event: SweepEvent) -> None:
        if self.filter and not self.filter(event):
            return
        try:
            await self.fn(event)
        except Exception as exc:  # noqa: BLE001
            log.warning("Handler '%s' raised %r for event %s", self.name, exc, event.event)


class EventRouter:
    """
    Async event bus with fan-out delivery and isolated handler failure.

    Usage:
        router = EventRouter()
        router.subscribe(EventHandler("my_handler", my_async_fn, filter=lambda e: e.confidence == "high"))

        async with router:
            await router.emit(event)
    """

    def __init__(self) -> None:
        self._handlers: list[EventHandler]      = []
        self._queue:    asyncio.Queue[SweepEvent | None] = asyncio.Queue()
        self._task:     asyncio.Task | None      = None
        self._counts:   dict[str, int]           = {}

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def subscribe(self, handler: EventHandler) -> None:
        self._handlers.append(handler)

    def unsubscribe(self, name: str) -> None:
        self._handlers = [h for h in self._handlers if h.name != name]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "EventRouter":
        self._task = asyncio.create_task(self._dispatch_loop())
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._queue.put(None)     # sentinel — signals end of stream
        if self._task:
            await self._task

    # ------------------------------------------------------------------
    # Emission
    # ------------------------------------------------------------------

    async def emit(self, event: SweepEvent) -> None:
        """Enqueue an event for fan-out delivery to all subscribers."""
        self._counts[event.event] = self._counts.get(event.event, 0) + 1
        await self._queue.put(event)

    async def emit_immediate(self, event: SweepEvent) -> None:
        """Bypass the queue and deliver to all handlers immediately (for tests)."""
        await asyncio.gather(*(h.handle(event) for h in self._handlers))

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    @property
    def emitted_count(self) -> int:
        return sum(self._counts.values())

    def stats(self) -> dict[str, int]:
        return dict(self._counts)

    # ------------------------------------------------------------------
    # Internal dispatch loop
    # ------------------------------------------------------------------

    async def _dispatch_loop(self) -> None:
        while True:
            event = await self._queue.get()
            if event is None:
                break
            if self._handlers:
                await asyncio.gather(*(h.handle(event) for h in self._handlers))
            self._queue.task_done()
