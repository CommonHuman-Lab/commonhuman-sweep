# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
AnomalyDetector — statistical baseline tracking and deviation scoring.

Maintains per-URL-pattern statistics (status distribution, length distribution,
response time) and scores incoming responses against the learned baseline.

This replaces naive "200 = valid" logic with a statistical model that flags
responses that deviate from what the target normally returns for a given path.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from commonhuman_sweep.models.events import SweepResponse


# Normalise path IDs to a pattern token so /api/users/1 and /api/users/2
# share the same baseline bucket.
_ID_TOKEN_RE = re.compile(
    r"(/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|(/)\d+"
    r"|(/)[0-9a-f]{32,64}"
, re.I)


@dataclass
class _Bucket:
    """Running statistics for one URL pattern."""

    status_counts:  Counter      = field(default_factory=Counter)
    lengths:        list[int]    = field(default_factory=list)
    times:          list[float]  = field(default_factory=list)
    fingerprints:   Counter      = field(default_factory=Counter)
    n:              int          = 0

    def update(self, resp: SweepResponse) -> None:
        self.status_counts[resp.status] += 1
        self.lengths.append(resp.length)
        self.times.append(resp.elapsed_ms)
        if resp.fingerprint:
            self.fingerprints[resp.fingerprint] += 1
        self.n += 1

    def dominant_status(self) -> int:
        return self.status_counts.most_common(1)[0][0] if self.status_counts else 200

    def mean_length(self) -> float:
        return sum(self.lengths) / len(self.lengths) if self.lengths else 0.0

    def stddev_length(self) -> float:
        if len(self.lengths) < 2:
            return 0.0
        mean = self.mean_length()
        return math.sqrt(sum((x - mean) ** 2 for x in self.lengths) / len(self.lengths))

    def mean_time(self) -> float:
        return sum(self.times) / len(self.times) if self.times else 0.0

    def dominant_fingerprint(self) -> str | None:
        return self.fingerprints.most_common(1)[0][0] if self.fingerprints else None


class AnomalyDetector:
    """
    Learns the statistical baseline for each URL pattern and scores deviations.

    Usage:
        detector = AnomalyDetector()
        detector.train(url, baseline_response)    # after each baseline request
        score = detector.score(url, candidate)    # during mutation phase
        if detector.is_anomalous(url, candidate): ...
    """

    def __init__(self) -> None:
        self._buckets: dict[str, _Bucket] = defaultdict(_Bucket)

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, url: str, response: SweepResponse) -> None:
        """Feed a baseline response into the detector's model."""
        if response.error:
            return
        self._buckets[_normalise_url(url)].update(response)

    def train_batch(self, pairs: list[tuple[str, SweepResponse]]) -> None:
        for url, resp in pairs:
            self.train(url, resp)

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def score(self, url: str, response: SweepResponse) -> float:
        """
        Return an anomaly score in [0.0, 1.0].

        0.0 = perfectly normal
        1.0 = completely unlike anything seen before
        """
        if response.error:
            return 0.5   # failed requests are mildly interesting

        bucket = self._buckets.get(_normalise_url(url))
        if bucket is None or bucket.n == 0:
            return 0.0   # no baseline — cannot judge

        score = 0.0
        weight_sum = 0.0

        # Status code deviation (high weight)
        if response.status != bucket.dominant_status():
            status_score = self._status_score(response.status, bucket.dominant_status())
            score       += 0.40 * status_score
        weight_sum += 0.40

        # Length deviation (medium weight — use z-score capped at 3σ)
        if bucket.lengths:
            mean = bucket.mean_length()
            std  = bucket.stddev_length()
            if std > 0:
                z = abs(response.length - mean) / std
                score += 0.30 * min(z / 3.0, 1.0)
        weight_sum += 0.30

        # Fingerprint deviation (medium weight)
        dom_fp = bucket.dominant_fingerprint()
        if dom_fp and response.fingerprint != dom_fp:
            score += 0.20
        weight_sum += 0.20

        # Timing anomaly (low weight — slow response = possible time-based SQLi)
        if bucket.times:
            mean_t = bucket.mean_time()
            if mean_t > 0 and response.elapsed_ms > mean_t * 5:
                score += 0.10
        weight_sum += 0.10

        return round(score / weight_sum * weight_sum, 4)  # normalised

    def is_anomalous(self, url: str, response: SweepResponse, threshold: float = 0.35) -> bool:
        return self.score(url, response) >= threshold

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _status_score(self, candidate: int, baseline: int) -> float:
        """Score how 'different' two status codes are."""
        if candidate == baseline:
            return 0.0
        # Same class (both 2xx, both 4xx, etc.) is a minor deviation.
        if candidate // 100 == baseline // 100:
            return 0.3
        # 200 vs 4xx/5xx is a major deviation.
        if candidate == 200 and baseline in (401, 403, 404):
            return 1.0
        if baseline == 200 and candidate in (401, 403):
            return 0.8
        if baseline == 200 and candidate in (500, 502, 503):
            return 0.9
        return 0.5

    def summary(self, url: str) -> dict:
        bucket = self._buckets.get(_normalise_url(url))
        if not bucket:
            return {"url": url, "trained": False}
        return {
            "url":               url,
            "trained":           True,
            "n":                 bucket.n,
            "dominant_status":   bucket.dominant_status(),
            "mean_length":       round(bucket.mean_length()),
            "stddev_length":     round(bucket.stddev_length()),
            "dominant_fingerprint": bucket.dominant_fingerprint(),
        }


def _normalise_url(url: str) -> str:
    """Replace ID tokens with <ID> so similar paths share a bucket."""
    return _ID_TOKEN_RE.sub(r"\1<ID>", url)
