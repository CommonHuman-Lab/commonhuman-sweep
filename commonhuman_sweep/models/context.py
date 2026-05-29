# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Sweep configuration and per-request context models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthStyle(str, Enum):
    NONE   = "none"
    BEARER = "bearer"
    COOKIE = "cookie"
    BASIC  = "basic"
    APIKEY = "apikey"


@dataclass
class AuthContext:
    """Describes how the sweep authenticates requests."""

    style:       AuthStyle = AuthStyle.NONE
    credential:  str = ""
    header_name: str = "Authorization"
    cookie_name: str = ""

    # Optional secondary session for cross-session comparisons (auth boundary strategy).
    alt_credential: str = ""
    alt_label:      str = "session_b"

    @classmethod
    def from_bearer(cls, token: str) -> "AuthContext":
        return cls(style=AuthStyle.BEARER, credential=f"Bearer {token}")

    @classmethod
    def from_cookie(cls, cookie_str: str) -> "AuthContext":
        return cls(style=AuthStyle.COOKIE, credential=cookie_str)

    @classmethod
    def from_basic(cls, user: str, password: str) -> "AuthContext":
        import base64
        encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
        return cls(style=AuthStyle.BASIC, credential=f"Basic {encoded}")

    def to_headers(self) -> dict[str, str]:
        if self.style == AuthStyle.BEARER:
            return {self.header_name: self.credential}
        if self.style == AuthStyle.BASIC:
            return {self.header_name: self.credential}
        if self.style == AuthStyle.APIKEY:
            return {self.header_name: self.credential}
        return {}

    def to_cookies(self) -> dict[str, str]:
        if self.style == AuthStyle.COOKIE and self.credential:
            return _parse_cookie_str(self.credential)
        return {}


@dataclass
class SweepOptions:
    """Runtime options for a sweep run."""

    # Scope
    max_pages:   int   = 50
    max_depth:   int   = 3
    concurrency: int   = 10
    timeout:     float = 15.0
    delay:       float = 0.0

    # Behaviour
    crawl:           bool = True
    follow_redirects: bool = True
    verify_ssl:      bool = False
    proxy:           str  = ""

    # Mutation controls
    wordlist_path:   str  = ""
    mutation_depth:  int  = 2   # how many mutation hops per endpoint
    ai_blend:        bool = False

    # Strategy overrides
    strategy: str = "smart"  # "smart" | "api" | "auth" | "wordlist"

    # Signals to downstream tools
    emit_to_stingxss:    bool = True
    emit_to_breachsql:   bool = True
    emit_to_phaseaccess: bool = True

    # Reporting
    output:  str  = ""
    verbose: bool = False
    quiet:   bool = False

    # Extra raw headers / exclude patterns
    extra_headers:    dict[str, str]  = field(default_factory=dict)
    exclude_patterns: list[str]       = field(default_factory=list)


@dataclass
class SweepContext:
    """Full configuration bundle passed to strategies and the orchestrator."""

    target:  str
    options: SweepOptions    = field(default_factory=SweepOptions)
    auth:    AuthContext      = field(default_factory=AuthContext)

    # Discovered during pre-scan phase; strategies may populate this.
    discovered_urls:   list[str]              = field(default_factory=list)
    harvested_ids:     dict[str, list[str]]   = field(default_factory=dict)
    api_spec_path:     str                    = ""

    def base_headers(self) -> dict[str, str]:
        h = {"User-Agent": "CommonHuman-Sweep/0.1", **self.options.extra_headers}
        h.update(self.auth.to_headers())
        return h

    def base_cookies(self) -> dict[str, str]:
        return self.auth.to_cookies()


@dataclass
class RequestContext:
    """Per-request metadata attached alongside a SweepRequest."""

    strategy:        str
    mutation_type:   str
    mutation_source: str   # e.g. "wordlist", "structural", "harvested_id"
    parameter:       str   = ""
    original_value:  str   = ""
    extra:           dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_cookie_str(cookie_str: str) -> dict[str, str]:
    """Parse 'name=value; name2=value2' into a dict."""
    result: dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            result[k.strip()] = v.strip()
    return result
