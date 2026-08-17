# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
ResponseClassifier — compute entropy, fingerprint, and extract signals from responses.

This is the first stage of the intelligence layer. Every SweepResponse passes
through here before reaching the AnomalyDetector or SimilarityEngine.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field

from commonhuman_sweep.models.events import Confidence, Signal, SweepRequest, SweepResponse


# ---------------------------------------------------------------------------
# Signals: patterns that trigger interesting-response classification
# ---------------------------------------------------------------------------

_ERROR_PATTERNS: list[tuple[re.Pattern, Signal]] = [
    (re.compile(r"(sql syntax|syntax error|mysql_fetch|ORA-\d+|pg_query|sqlite3\.)", re.I),
     Signal.SQLI_ERROR_HINT),
    (re.compile(r"(traceback|stack trace|exception in|NullPointerException|undefined method)", re.I),
     Signal.STACK_TRACE_LEAKED),
    (re.compile(r"(debug=true|APP_DEBUG|DEBUG_MODE|X-Debug-Token)", re.I),
     Signal.DEBUG_INFO_LEAKED),
    (re.compile(r"(<script[\s>])", re.I),
     Signal.XSS_REFLECTION_HINT),
]

_INTERESTING_HEADERS: dict[str, Signal] = {
    "x-debug-token":    Signal.DEBUG_INFO_LEAKED,
    "x-debug-token-link": Signal.DEBUG_INFO_LEAKED,
    "x-powered-by":     Signal.DEBUG_INFO_LEAKED,
}

_AUTH_BYPASS_STATUSES = {200, 201, 202, 204}
_SERVER_ERROR_STATUSES = {500, 502, 503}

_MASS_ASSIGNMENT_FIELDS = re.compile(
    r'"(is_admin|admin|role|privilege|permission|superuser|owner|group)"', re.I
)


@dataclass
class ResponseClassification:
    """Output of the classifier for a single response."""

    fingerprint:   str            # structural hash
    entropy_score: float          # 0.0–1.0
    signals:       list[Signal]   = field(default_factory=list)
    confidence:    Confidence     = Confidence.LOW
    interesting:   bool           = False


class ResponseClassifier:
    """
    Classify responses by entropy, structural fingerprint, and signal extraction.

    Enriches SweepResponse objects in-place (sets entropy_score, fingerprint)
    and returns a ResponseClassification for the calling layer.
    """

    def classify(
        self,
        request: SweepRequest,
        response: SweepResponse,
        baseline: SweepResponse | None = None,
    ) -> ResponseClassification:
        # Always enrich the response object
        response.entropy_score = self.compute_entropy(response.body)
        response.fingerprint   = self._fingerprint(response)

        signals    = self._extract_signals(request, response, baseline)
        confidence = self._score_confidence(signals, response, baseline)

        cls = ResponseClassification(
            fingerprint=response.fingerprint,
            entropy_score=response.entropy_score,
            signals=signals,
            confidence=confidence,
            interesting=bool(signals) or confidence != Confidence.LOW,
        )
        return cls

    # ------------------------------------------------------------------
    # Entropy
    # ------------------------------------------------------------------

    def compute_entropy(self, content: str) -> float:
        """Shannon entropy normalised to [0.0, 1.0] over byte distribution."""
        if not content:
            return 0.0
        data = content.encode("utf-8", errors="replace")
        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        n = len(data)
        entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
        # Max entropy for 256 symbols is log2(256) = 8.0 bits
        return min(entropy / 8.0, 1.0)

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    def _fingerprint(self, r: SweepResponse) -> str:
        """
        Structural fingerprint: status + content-type + JSON schema shape.

        Two responses with the same fingerprint have identical structural
        signatures even if their content differs (e.g. different user data).
        """
        ct = r.content_type
        shape = ""
        if r.is_json:
            shape = _json_shape(r.body)
        raw = f"{r.status}:{ct}:{shape}:{len(r.body) // 100}"
        return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:12]

    # ------------------------------------------------------------------
    # Signal extraction
    # ------------------------------------------------------------------

    def _extract_signals(
        self,
        req: SweepRequest,
        resp: SweepResponse,
        baseline: SweepResponse | None,
    ) -> list[Signal]:
        signals: list[Signal] = []

        # Error-based signals from body patterns
        for pattern, signal in _ERROR_PATTERNS:
            if pattern.search(resp.body):
                signals.append(signal)

        # Server errors
        if resp.status in _SERVER_ERROR_STATUSES:
            signals.append(Signal.SERVER_ERROR)

        # Auth bypass: was forbidden/401, now is 2xx
        if baseline and baseline.status in (401, 403) and resp.status in _AUTH_BYPASS_STATUSES:
            signals.append(Signal.AUTH_BYPASS_HINT)

        # Forbidden resource
        if resp.status == 403:
            signals.append(Signal.RESOURCE_FORBIDDEN)

        # Possible IDOR: same endpoint returns different content with mutated ID
        if baseline and resp.status == 200 and baseline.status == 200:
            if resp.fingerprint == baseline.fingerprint and resp.body != baseline.body:
                signals.append(Signal.POSSIBLE_IDOR)

        # Mass assignment hints in response body
        if _MASS_ASSIGNMENT_FIELDS.search(resp.body):
            signals.append(Signal.MASS_ASSIGNMENT_HINT)

        # Interesting header signals
        for header_name, signal in _INTERESTING_HEADERS.items():
            if header_name in {k.lower() for k in resp.headers}:
                signals.append(signal)

        # Reflection probe — if the request URL contains a probe string and it
        # appears in the response, flag as XSS reflection hint.
        if req.url and "<script>" in req.url and "<script>" in resp.body.lower():
            if Signal.XSS_REFLECTION_HINT not in signals:
                signals.append(Signal.XSS_REFLECTION_HINT)

        # API schema exposure
        if resp.status == 200 and resp.is_json:
            body_lower = resp.body.lower()
            if any(k in body_lower for k in ('"swagger"', '"openapi"', '"paths":', '"info":')):
                signals.append(Signal.API_SCHEMA_EXPOSED)

        return list(dict.fromkeys(signals))  # deduplicate, preserve order

    # ------------------------------------------------------------------
    # Confidence scoring
    # ------------------------------------------------------------------

    def _score_confidence(
        self,
        signals: list[Signal],
        resp: SweepResponse,
        baseline: SweepResponse | None,
    ) -> Confidence:
        high_signals = {
            Signal.SQLI_ERROR_HINT,
            Signal.AUTH_BYPASS_HINT,
            Signal.STACK_TRACE_LEAKED,
            Signal.MASS_ASSIGNMENT_HINT,
            Signal.API_SCHEMA_EXPOSED,
        }
        medium_signals = {
            Signal.POSSIBLE_IDOR,
            Signal.XSS_REFLECTION_HINT,
            Signal.DEBUG_INFO_LEAKED,
            Signal.PATH_TRAVERSAL_HINT,
            Signal.SERVER_ERROR,
        }

        if any(s in high_signals for s in signals):
            return Confidence.HIGH
        if any(s in medium_signals for s in signals):
            return Confidence.MEDIUM
        if signals:
            return Confidence.LOW
        return Confidence.LOW


# ---------------------------------------------------------------------------
# JSON shape helper
# ---------------------------------------------------------------------------

def _json_shape(body: str) -> str:
    """
    Return a canonical representation of the top-level JSON schema shape.

    {"id": 1, "name": "Alice"} → '{"id":"int","name":"str"}'
    This lets us fingerprint structure without being sensitive to values.
    """
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return ""
    return _shape_of(doc)


def _shape_of(obj: object, depth: int = 0) -> str:
    if depth > 3:
        return "..."
    if isinstance(obj, dict):
        inner = ",".join(f'"{k}":{_shape_of(v, depth + 1)}' for k, v in sorted(obj.items()))
        return "{" + inner + "}"
    if isinstance(obj, list):
        if obj:
            return f"[{_shape_of(obj[0], depth + 1)}]"
        return "[]"
    if isinstance(obj, bool):
        return "bool"
    if isinstance(obj, int):
        return "int"
    if isinstance(obj, float):
        return "float"
    if isinstance(obj, str):
        return "str"
    return "null"
