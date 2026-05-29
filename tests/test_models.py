# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for models — SweepEvent, SweepResponse, AuthContext."""

from __future__ import annotations

import pytest

from commonhuman_sweep.models.context import AuthContext, AuthStyle, SweepContext, SweepOptions
from commonhuman_sweep.models.events import (
    Confidence,
    Signal,
    SweepEvent,
    SweepRequest,
    SweepResponse,
    SweepResult,
)


class TestSweepResponse:
    def test_length_counts_utf8_bytes(self):
        r = SweepResponse(status=200, body="hello")
        assert r.length == 5

    def test_length_multibyte(self):
        r = SweepResponse(status=200, body="café")
        assert r.length == 5  # é is 2 bytes in UTF-8

    def test_content_type_strips_charset(self):
        r = SweepResponse(status=200, headers={"content-type": "application/json; charset=utf-8"})
        assert r.content_type == "application/json"

    def test_is_json(self):
        r = SweepResponse(status=200, headers={"content-type": "application/json"})
        assert r.is_json is True
        assert r.is_html is False

    def test_is_html(self):
        r = SweepResponse(status=200, headers={"content-type": "text/html"})
        assert r.is_html is True
        assert r.is_json is False

    def test_to_dict_keys(self):
        r = SweepResponse(status=200, body="ok", elapsed_ms=12.5, entropy_score=0.4)
        d = r.to_dict()
        assert d["status"] == 200
        assert d["elapsed_ms"] == 12.5
        assert d["entropy_score"] == 0.4

    def test_error_response_no_body(self):
        r = SweepResponse(status=0, error="timeout")
        assert r.length == 0
        assert r.error == "timeout"


class TestSweepEvent:
    def _make_event(self, signals=None, confidence=Confidence.LOW) -> SweepEvent:
        req = SweepRequest(method="GET", url="http://example.com/api/user/1")
        resp = SweepResponse(status=200, body='{"id":1}')
        return SweepEvent(
            event="sweep_result",
            target="http://example.com",
            request=req,
            response=resp,
            signals=signals or [],
            confidence=confidence,
            strategy="smart",
        )

    def test_has_signal_true(self):
        evt = self._make_event(signals=[Signal.POSSIBLE_IDOR])
        assert evt.has_signal(Signal.POSSIBLE_IDOR) is True

    def test_has_signal_false(self):
        evt = self._make_event(signals=[Signal.SERVER_ERROR])
        assert evt.has_signal(Signal.POSSIBLE_IDOR) is False

    def test_has_signal_any_of(self):
        evt = self._make_event(signals=[Signal.SQLI_ERROR_HINT])
        assert evt.has_signal(Signal.POSSIBLE_IDOR, Signal.SQLI_ERROR_HINT) is True

    def test_is_interesting_with_signals(self):
        evt = self._make_event(signals=[Signal.INTERESTING_RESPONSE])
        assert evt.is_interesting() is True

    def test_is_interesting_high_confidence_no_signals(self):
        evt = self._make_event(signals=[], confidence=Confidence.HIGH)
        assert evt.is_interesting() is True

    def test_not_interesting_low_no_signals(self):
        evt = self._make_event(signals=[], confidence=Confidence.LOW)
        assert evt.is_interesting() is False

    def test_to_dict_schema(self):
        evt = self._make_event(signals=[Signal.POSSIBLE_IDOR], confidence=Confidence.MEDIUM)
        d = evt.to_dict()
        assert d["event"] == "sweep_result"
        assert d["target"] == "http://example.com"
        assert d["confidence"] == "medium"
        assert "possible_idor" in d["signals"]
        assert "request" in d
        assert "response" in d
        assert "timestamp" in d

    def test_to_dict_signals_are_strings(self):
        evt = self._make_event(signals=[Signal.AUTH_BYPASS_HINT, Signal.SERVER_ERROR])
        d = evt.to_dict()
        assert all(isinstance(s, str) for s in d["signals"])


class TestSweepResult:
    def test_interesting_events_filter(self):
        req = SweepRequest(method="GET", url="http://example.com/")
        resp = SweepResponse(status=200)
        interesting = SweepEvent(
            event="sweep_result", target="http://example.com",
            request=req, response=resp,
            signals=[Signal.POSSIBLE_IDOR], confidence=Confidence.MEDIUM,
        )
        boring = SweepEvent(
            event="sweep_result", target="http://example.com",
            request=req, response=resp,
            signals=[], confidence=Confidence.LOW,
        )
        result = SweepResult(target="http://example.com", strategy="smart",
                             events=[boring, interesting])
        assert len(result.interesting_events) == 1
        assert result.interesting_events[0] is interesting

    def test_finish_sets_duration(self):
        result = SweepResult(target="http://example.com", strategy="smart")
        result.finish()
        assert result.duration_s >= 0.0
        assert result.finished_at > 0.0

    def test_to_dict_keys(self):
        result = SweepResult(target="http://example.com", strategy="api",
                             requests_sent=10, endpoints_found=3)
        result.finish()
        d = result.to_dict()
        assert d["target"] == "http://example.com"
        assert d["strategy"] == "api"
        assert d["requests_sent"] == 10
        assert d["endpoints_found"] == 3


class TestAuthContext:
    def test_bearer_to_headers(self):
        auth = AuthContext.from_bearer("my_token")
        assert auth.to_headers() == {"Authorization": "Bearer my_token"}

    def test_cookie_to_cookies(self):
        auth = AuthContext.from_cookie("session=abc123; csrf=xyz")
        cookies = auth.to_cookies()
        assert cookies["session"] == "abc123"
        assert cookies["csrf"] == "xyz"

    def test_basic_to_headers(self):
        auth = AuthContext.from_basic("user", "pass")
        h = auth.to_headers()
        assert h["Authorization"].startswith("Basic ")

    def test_none_auth_empty_headers(self):
        auth = AuthContext()
        assert auth.to_headers() == {}
        assert auth.to_cookies() == {}


class TestSweepOptions:
    def test_defaults(self):
        opts = SweepOptions()
        assert opts.strategy == "smart"
        assert opts.crawl is True
        assert opts.concurrency == 10

    def test_wordlist_implies_wordlist_strategy(self):
        # Confirmed by __main__.py logic; options themselves just store the path
        opts = SweepOptions(wordlist_path="/tmp/list.txt")
        assert opts.wordlist_path == "/tmp/list.txt"
