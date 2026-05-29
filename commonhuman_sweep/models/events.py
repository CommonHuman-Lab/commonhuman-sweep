# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Core event and result models for commonhuman-sweep.

SweepEvent is the atomic unit of output from the sweep engine.
It carries a fully described request/response pair, classified signals,
and enough context for downstream tools to act without querying the engine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class Signal(str, Enum):
    """Classified response signals emitted by the intelligence layer."""

    # Structure / auth signals
    INTERESTING_RESPONSE     = "interesting_response"
    ANOMALOUS_STATUS         = "anomalous_status"
    ANOMALOUS_LENGTH         = "anomalous_length"
    ANOMALOUS_CONTENT        = "anomalous_content"
    AUTH_BYPASS_HINT         = "auth_bypass_hint"

    # Object / resource signals
    POSSIBLE_IDOR            = "possible_idor"
    RESOURCE_EXISTS          = "resource_exists"
    RESOURCE_FORBIDDEN       = "resource_forbidden"
    RESOURCE_ENUMERABLE      = "resource_enumerable"

    # Injection surface signals
    XSS_REFLECTION_HINT      = "xss_reflection_hint"
    SQLI_ERROR_HINT          = "sqli_error_hint"
    SQLI_TIMING_HINT         = "sqli_timing_hint"
    SERVER_ERROR             = "server_error"
    STACK_TRACE_LEAKED       = "stack_trace_leaked"
    DEBUG_INFO_LEAKED        = "debug_info_leaked"

    # API surface signals
    API_ENDPOINT_FOUND       = "api_endpoint_found"
    API_VERB_MISMATCH        = "api_verb_mismatch"
    API_SCHEMA_EXPOSED        = "api_schema_exposed"
    MASS_ASSIGNMENT_HINT     = "mass_assignment_hint"

    # Traversal / path signals
    PATH_TRAVERSAL_HINT      = "path_traversal_hint"
    OPEN_REDIRECT_HINT       = "open_redirect_hint"

    # Info
    RESPONSE_IDENTICAL       = "response_identical"
    BASELINE_ESTABLISHED     = "baseline_established"


@dataclass
class SweepRequest:
    """A single HTTP request as constructed by the sweep engine."""

    method:   str
    url:      str
    headers:  dict[str, str]   = field(default_factory=dict)
    body:     str | None       = None
    params:   dict[str, str]   = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method":  self.method,
            "url":     self.url,
            "headers": self.headers,
            "body":    self.body,
            "params":  self.params,
        }


@dataclass
class SweepResponse:
    """A classified HTTP response."""

    status:        int
    headers:       dict[str, str]   = field(default_factory=dict)
    body:          str              = ""
    elapsed_ms:    float            = 0.0
    entropy_score: float            = 0.0    # 0.0–1.0; higher = more information-dense
    fingerprint:   str              = ""     # structural hash (status+ct+schema shape)
    error:         str | None       = None   # set when request failed entirely

    @property
    def length(self) -> int:
        return len(self.body.encode("utf-8", errors="replace"))

    @property
    def content_type(self) -> str:
        ct = self.headers.get("content-type", self.headers.get("Content-Type", ""))
        return ct.split(";")[0].strip()

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type

    def to_dict(self) -> dict[str, Any]:
        return {
            "status":        self.status,
            "length":        self.length,
            "content_type":  self.content_type,
            "entropy_score": round(self.entropy_score, 4),
            "fingerprint":   self.fingerprint,
            "elapsed_ms":    round(self.elapsed_ms, 1),
        }


@dataclass
class SweepEvent:
    """
    Atomic event emitted by the sweep engine.

    This is the contract that downstream consumers (StingXSS, BreachSQL,
    PhaseAccess) subscribe to. The schema is stable; add fields via 'extra'.
    """

    event:      str              # "sweep_result" | "sweep_anomaly" | "sweep_baseline"
    target:     str              # root target URL
    request:    SweepRequest
    response:   SweepResponse
    signals:    list[Signal]     = field(default_factory=list)
    confidence: Confidence       = Confidence.LOW
    strategy:   str              = ""
    mutation:   str              = ""   # mutation type that produced this request
    parameter:  str              = ""   # parameter under test
    timestamp:  float            = field(default_factory=time.time)
    extra:      dict[str, Any]   = field(default_factory=dict)

    # ---- serialisation ----

    def to_dict(self) -> dict[str, Any]:
        return {
            "event":      self.event,
            "target":     self.target,
            "request":    self.request.to_dict(),
            "response":   self.response.to_dict(),
            "signals":    [s.value for s in self.signals],
            "confidence": self.confidence.value,
            "strategy":   self.strategy,
            "mutation":   self.mutation,
            "parameter":  self.parameter,
            "timestamp":  self.timestamp,
            **self.extra,
        }

    def has_signal(self, *signals: Signal) -> bool:
        return any(s in self.signals for s in signals)

    def is_interesting(self) -> bool:
        return self.confidence in (Confidence.MEDIUM, Confidence.HIGH) or bool(self.signals)


@dataclass
class SweepResult:
    """Aggregated result after an entire sweep run completes."""

    target:          str
    strategy:        str
    events:          list[SweepEvent]    = field(default_factory=list)
    errors:          list[str]           = field(default_factory=list)
    started_at:      float               = field(default_factory=time.time)
    finished_at:     float               = 0.0
    duration_s:      float               = 0.0
    requests_sent:   int                 = 0
    endpoints_found: int                 = 0

    def finish(self) -> "SweepResult":
        self.finished_at = time.time()
        self.duration_s  = round(self.finished_at - self.started_at, 2)
        return self

    @property
    def interesting_events(self) -> list[SweepEvent]:
        return [e for e in self.events if e.is_interesting()]

    @property
    def high_confidence_events(self) -> list[SweepEvent]:
        return [e for e in self.events if e.confidence == Confidence.HIGH]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target":          self.target,
            "strategy":        self.strategy,
            "duration_s":      self.duration_s,
            "requests_sent":   self.requests_sent,
            "endpoints_found": self.endpoints_found,
            "total_events":    len(self.events),
            "interesting":     len(self.interesting_events),
            "errors":          self.errors,
        }
