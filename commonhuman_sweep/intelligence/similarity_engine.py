# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
SimilarityEngine — response clustering and diff computation.

Determines whether two responses are structurally the same class (same
endpoint behaviour with different data) vs fundamentally different.
Clustering reduces noise: if 50 ID probes all return the same structure,
only anomalous ones are surfaced.
"""

from __future__ import annotations

import re
from collections import Counter

from commonhuman_sweep.models.events import SweepResponse


_WHITESPACE_RE = re.compile(r"\s+")
_DYNAMIC_RE    = re.compile(
    r'("(?:id|uuid|token|created|updated|timestamp|date|time)":\s*)'
    r'("?[^,}\]"]+?"?)',
    re.I,
)


class SimilarityEngine:
    """Compute pairwise similarity and cluster a list of responses."""

    # ------------------------------------------------------------------
    # Pairwise similarity
    # ------------------------------------------------------------------

    def compute_similarity(self, a: SweepResponse, b: SweepResponse) -> float:
        """
        Return a similarity score in [0.0, 1.0].

        Factors:
          - status code match (0.3 weight)
          - content-type match (0.2 weight)
          - structural fingerprint match (0.3 weight)
          - token overlap of normalised body (0.2 weight)
        """
        if a.error or b.error:
            return 1.0 if (a.error == b.error) else 0.0

        score = 0.0
        score += 0.30 if a.status == b.status else 0.0
        score += 0.20 if a.content_type == b.content_type else 0.0
        score += 0.30 if a.fingerprint and a.fingerprint == b.fingerprint else 0.0
        score += 0.20 * self._token_overlap(a.body, b.body)
        return round(score, 4)

    def is_same_class(self, a: SweepResponse, b: SweepResponse, threshold: float = 0.75) -> bool:
        return self.compute_similarity(a, b) >= threshold

    # ------------------------------------------------------------------
    # Diff computation
    # ------------------------------------------------------------------

    def diff(self, baseline: SweepResponse, candidate: SweepResponse) -> dict:
        """Return a structured diff summary between two responses."""
        status_changed   = baseline.status != candidate.status
        length_delta     = candidate.length - baseline.length
        length_ratio     = candidate.length / baseline.length if baseline.length else 0.0
        fp_changed       = baseline.fingerprint != candidate.fingerprint
        similarity       = self.compute_similarity(baseline, candidate)

        return {
            "status_changed":  status_changed,
            "status_baseline": baseline.status,
            "status_candidate": candidate.status,
            "length_delta":    length_delta,
            "length_ratio":    round(length_ratio, 4),
            "fingerprint_changed": fp_changed,
            "similarity":      similarity,
            "significant":     similarity < 0.6 or status_changed,
        }

    # ------------------------------------------------------------------
    # Clustering
    # ------------------------------------------------------------------

    def cluster(
        self,
        responses: list[SweepResponse],
        threshold: float = 0.75,
    ) -> list[list[SweepResponse]]:
        """
        Group responses into clusters where members are mutually similar.

        Uses a greedy single-pass algorithm (O(n²) worst case, acceptable
        for the response counts produced by a sweep run — typically < 1000).
        """
        clusters: list[list[SweepResponse]] = []
        assigned: set[int] = set()

        for i, resp in enumerate(responses):
            if i in assigned:
                continue
            cluster = [resp]
            assigned.add(i)
            for j in range(i + 1, len(responses)):
                if j not in assigned and self.is_same_class(resp, responses[j], threshold):
                    cluster.append(responses[j])
                    assigned.add(j)
            clusters.append(cluster)

        return clusters

    def representative(self, cluster: list[SweepResponse]) -> SweepResponse:
        """Return the most 'average' response from a cluster (highest pairwise sum)."""
        if len(cluster) == 1:
            return cluster[0]
        best, best_score = cluster[0], 0.0
        for resp in cluster:
            score = sum(self.compute_similarity(resp, other) for other in cluster)
            if score > best_score:
                best, best_score = resp, score
        return best

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _token_overlap(self, a: str, b: str) -> float:
        """Jaccard similarity over word tokens of normalised bodies."""
        na, nb = _normalise_body(a), _normalise_body(b)
        if not na and not nb:
            return 1.0
        if not na or not nb:
            return 0.0
        set_a = Counter(na.split())
        set_b = Counter(nb.split())
        intersection = sum((set_a & set_b).values())
        union        = sum((set_a | set_b).values())
        return intersection / union if union else 0.0


def _normalise_body(body: str) -> str:
    """Strip dynamic fields so structural comparison is stable across runs."""
    normalised = _DYNAMIC_RE.sub(r'\1"<VALUE>"', body)
    normalised = _WHITESPACE_RE.sub(" ", normalised).strip()
    return normalised[:4096]   # cap for performance
