# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for EventRouter — pub/sub fan-out, filtering, and isolation."""

from __future__ import annotations

import pytest

from commonhuman_sweep.models.events import Confidence, Signal, SweepEvent, SweepRequest, SweepResponse
from commonhuman_sweep.pipeline.event_router import EventHandler, EventRouter


def _evt(confidence: Confidence = Confidence.LOW,
         signals: list[Signal] | None = None,
         event: str = "sweep_result") -> SweepEvent:
    req  = SweepRequest(method="GET", url="http://example.com/")
    resp = SweepResponse(status=200)
    return SweepEvent(
        event=event,
        target="http://example.com",
        request=req,
        response=resp,
        signals=signals or [],
        confidence=confidence,
    )


class TestEventRouterFanOut:
    async def test_single_handler_receives_event(self):
        received = []

        async def _handler(e: SweepEvent) -> None:
            received.append(e)

        router = EventRouter()
        router.subscribe(EventHandler("h1", _handler))

        async with router:
            await router.emit(_evt())

        assert len(received) == 1

    async def test_multiple_handlers_all_receive(self):
        log: list[str] = []

        async def _h1(e: SweepEvent) -> None:
            log.append("h1")

        async def _h2(e: SweepEvent) -> None:
            log.append("h2")

        router = EventRouter()
        router.subscribe(EventHandler("h1", _h1))
        router.subscribe(EventHandler("h2", _h2))

        async with router:
            await router.emit(_evt())

        assert "h1" in log
        assert "h2" in log

    async def test_filter_blocks_non_matching_events(self):
        received = []

        async def _handler(e: SweepEvent) -> None:
            received.append(e)

        router = EventRouter()
        router.subscribe(EventHandler(
            "high_only",
            _handler,
            filter=lambda e: e.confidence == Confidence.HIGH,
        ))

        async with router:
            await router.emit(_evt(confidence=Confidence.LOW))
            await router.emit(_evt(confidence=Confidence.HIGH))

        assert len(received) == 1
        assert received[0].confidence == Confidence.HIGH

    async def test_signal_filter(self):
        received = []

        async def _handler(e: SweepEvent) -> None:
            received.append(e)

        router = EventRouter()
        router.subscribe(EventHandler(
            "idor_only",
            _handler,
            filter=lambda e: e.has_signal(Signal.POSSIBLE_IDOR),
        ))

        async with router:
            await router.emit(_evt(signals=[Signal.SERVER_ERROR]))
            await router.emit(_evt(signals=[Signal.POSSIBLE_IDOR]))

        assert len(received) == 1

    async def test_failing_handler_does_not_drop_other_handlers(self):
        received = []

        async def _bad(e: SweepEvent) -> None:
            raise RuntimeError("intentional failure")

        async def _good(e: SweepEvent) -> None:
            received.append(e)

        router = EventRouter()
        router.subscribe(EventHandler("bad", _bad))
        router.subscribe(EventHandler("good", _good))

        async with router:
            await router.emit(_evt())

        assert len(received) == 1

    async def test_emit_count_tracked(self):
        async def _noop(e: SweepEvent) -> None:
            pass

        router = EventRouter()
        router.subscribe(EventHandler("noop", _noop))

        async with router:
            await router.emit(_evt())
            await router.emit(_evt())
            await router.emit(_evt())

        assert router.emitted_count == 3

    async def test_stats_by_event_type(self):
        async def _noop(e: SweepEvent) -> None:
            pass

        router = EventRouter()
        router.subscribe(EventHandler("noop", _noop))

        async with router:
            await router.emit(_evt(event="sweep_result"))
            await router.emit(_evt(event="sweep_baseline"))

        stats = router.stats()
        assert stats.get("sweep_result", 0) == 1
        assert stats.get("sweep_baseline", 0) == 1

    async def test_unsubscribe_removes_handler(self):
        received = []

        async def _handler(e: SweepEvent) -> None:
            received.append(e)

        router = EventRouter()
        router.subscribe(EventHandler("h1", _handler))
        router.unsubscribe("h1")

        async with router:
            await router.emit(_evt())

        assert len(received) == 0

    async def test_emit_immediate_bypasses_queue(self):
        received = []

        async def _handler(e: SweepEvent) -> None:
            received.append(e)

        router = EventRouter()
        router.subscribe(EventHandler("h", _handler))
        await router.emit_immediate(_evt())
        assert len(received) == 1

    async def test_multiple_events_preserve_order(self):
        order: list[str] = []

        async def _handler(e: SweepEvent) -> None:
            order.append(e.event)

        router = EventRouter()
        router.subscribe(EventHandler("h", _handler))

        events = [_evt(event=f"evt_{i}") for i in range(5)]
        async with router:
            for e in events:
                await router.emit(e)

        assert order == [f"evt_{i}" for i in range(5)]

    async def test_no_handlers_emits_without_error(self):
        router = EventRouter()
        async with router:
            await router.emit(_evt())   # should not raise
        assert router.emitted_count == 1


class TestEventHandler:
    async def test_handler_with_no_filter_always_handles(self):
        received = []

        async def _fn(e: SweepEvent) -> None:
            received.append(e)

        handler = EventHandler("h", _fn)
        await handler.handle(_evt(confidence=Confidence.LOW))
        await handler.handle(_evt(confidence=Confidence.HIGH))
        assert len(received) == 2

    async def test_handler_with_filter_skips_non_matching(self):
        received = []

        async def _fn(e: SweepEvent) -> None:
            received.append(e)

        handler = EventHandler(
            "h", _fn,
            filter=lambda e: e.confidence == Confidence.HIGH,
        )
        await handler.handle(_evt(confidence=Confidence.LOW))
        await handler.handle(_evt(confidence=Confidence.HIGH))
        assert len(received) == 1

    async def test_handler_exception_is_swallowed(self):
        async def _bad(e: SweepEvent) -> None:
            raise ValueError("oops")

        handler = EventHandler("bad", _bad)
        # Must not raise — handler isolation is a guarantee
        await handler.handle(_evt())

    async def test_handler_name_identifies_it(self):
        async def _fn(e: SweepEvent) -> None:
            pass

        handler = EventHandler("my_handler", _fn)
        assert handler.name == "my_handler"
