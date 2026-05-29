# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
ExecutionLayer — async HTTP execution with rate-limiting and connection pooling.

Uses httpx for async HTTP/1.1 + HTTP/2 support. Wraps results in SweepResponse
so the intelligence layer always receives a normalised object even when network
errors occur.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator

import httpx

from commonhuman_sweep.models.context import SweepContext
from commonhuman_sweep.models.events import SweepRequest, SweepResponse


class ExecutionLayer:
    """Async HTTP executor with concurrency control and structured response wrapping."""

    def __init__(self, context: SweepContext) -> None:
        self._ctx = context
        opts = context.options
        self._semaphore = asyncio.Semaphore(opts.concurrency)
        self._delay = opts.delay
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "ExecutionLayer":
        opts = self._ctx.options
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(opts.timeout),
            verify=opts.verify_ssl,
            follow_redirects=opts.follow_redirects,
            proxies=opts.proxy or None,
            headers=self._ctx.base_headers(),
            http2=True,
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Single request
    # ------------------------------------------------------------------

    async def execute(self, request: SweepRequest) -> SweepResponse:
        assert self._client is not None, "ExecutionLayer must be used as async context manager"

        async with self._semaphore:
            if self._delay > 0:
                await asyncio.sleep(self._delay)
            return await self._send(request)

    # ------------------------------------------------------------------
    # Batch execution — yields (request, response) pairs as they complete
    # ------------------------------------------------------------------

    async def execute_batch(
        self,
        requests: list[SweepRequest],
    ) -> AsyncIterator[tuple[SweepRequest, SweepResponse]]:
        tasks = [asyncio.create_task(self._wrap(r)) for r in requests]
        for coro in asyncio.as_completed(tasks):
            yield await coro

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _wrap(self, request: SweepRequest) -> tuple[SweepRequest, SweepResponse]:
        return request, await self.execute(request)

    async def _send(self, request: SweepRequest) -> SweepResponse:
        try:
            t0 = time.monotonic()
            resp = await self._client.request(  # type: ignore[union-attr]
                method=request.method,
                url=request.url,
                headers=request.headers,
                content=request.body.encode() if request.body else None,
            )
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            body = resp.text
            return SweepResponse(
                status=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                elapsed_ms=elapsed_ms,
            )
        except httpx.TimeoutException:
            return SweepResponse(status=0, error="timeout")
        except httpx.ConnectError as exc:
            return SweepResponse(status=0, error=f"connect_error: {exc}")
        except Exception as exc:  # noqa: BLE001
            return SweepResponse(status=0, error=f"error: {exc}")
