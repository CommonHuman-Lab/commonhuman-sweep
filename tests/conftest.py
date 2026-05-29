# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Shared fixtures for commonhuman-sweep tests.

Network guard
─────────────
An autouse session fixture patches httpx.AsyncClient.send() so that any test
that accidentally reaches real HTTP fails immediately with a clear error rather
than hitting a live host.  Tests that need to simulate HTTP responses should
use the ``mock_httpx`` fixture (or patch their own transport inline).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from commonhuman_sweep.models.context import AuthContext, SweepContext, SweepOptions
from commonhuman_sweep.models.events import Confidence, Signal, SweepEvent, SweepRequest, SweepResponse


# ---------------------------------------------------------------------------
# Global network guard
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _block_real_http(monkeypatch):
    """
    Prevent any test from making a real outbound HTTP request.

    If a test instantiates httpx.AsyncClient and calls .send() without
    mocking, it will raise RuntimeError instead of hitting the network.
    Override by using the ``mock_httpx`` fixture or patching explicitly.
    """
    async def _guard(*args, **kwargs):
        raise RuntimeError(
            "Real HTTP call attempted in a test.  "
            "Use the mock_httpx fixture or patch httpx.AsyncClient explicitly."
        )

    monkeypatch.setattr(httpx.AsyncClient, "send", _guard)


# ---------------------------------------------------------------------------
# HTTP mock helper
# ---------------------------------------------------------------------------

def _mock_http_response(
    status: int = 200,
    body: str = "",
    content_type: str = "application/json",
) -> httpx.Response:
    """Build a fake httpx.Response without a real connection."""
    return httpx.Response(
        status_code=status,
        headers={"content-type": content_type},
        content=body.encode(),
    )


@pytest.fixture
def mock_httpx():
    """
    Patch httpx.AsyncClient.request to return a configurable fake response.

    Usage::

        async def test_something(mock_httpx):
            mock_httpx.return_value = _mock_http_response(200, '{"id":1}')
            ...
    """
    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as m:
        m.return_value = _mock_http_response(200, "{}")
        yield m


# ---------------------------------------------------------------------------
# SweepContext fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def bare_context() -> SweepContext:
    """Minimal context — no crawl, concurrency 1."""
    return SweepContext(
        target="http://example.com",
        options=SweepOptions(crawl=False, concurrency=1),
    )


@pytest.fixture
def api_context() -> SweepContext:
    """Context targeting a REST path with an integer ID."""
    return SweepContext(
        target="http://example.com/api/users/42",
        options=SweepOptions(crawl=False, concurrency=1),
    )


@pytest.fixture
def authed_context() -> SweepContext:
    """Context with a primary bearer session and a secondary session."""
    auth = AuthContext.from_bearer("token_a_secret")
    auth.alt_credential = "Bearer token_b_secret"
    auth.alt_label = "session_b"
    return SweepContext(
        target="http://example.com/profile",
        options=SweepOptions(crawl=False),
        auth=auth,
    )


# ---------------------------------------------------------------------------
# Response fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ok_response() -> SweepResponse:
    return SweepResponse(status=200, body='{"id": 1, "name": "Alice"}',
                         headers={"content-type": "application/json"})


@pytest.fixture
def not_found_response() -> SweepResponse:
    return SweepResponse(status=404, body="Not Found",
                         headers={"content-type": "text/plain"})


@pytest.fixture
def server_error_response() -> SweepResponse:
    return SweepResponse(status=500, body="Internal Server Error",
                         headers={"content-type": "text/plain"})


@pytest.fixture
def base_request() -> SweepRequest:
    return SweepRequest(method="GET", url="http://example.com/api/users/1",
                        headers={"Authorization": "Bearer token"})
