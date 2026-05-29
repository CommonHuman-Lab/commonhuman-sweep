# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for the intelligence layer — classifier, similarity, anomaly detector."""

from __future__ import annotations

import pytest

from commonhuman_sweep.intelligence.anomaly_detector import AnomalyDetector, _normalise_url
from commonhuman_sweep.intelligence.response_classifier import ResponseClassifier, _json_shape
from commonhuman_sweep.intelligence.similarity_engine import SimilarityEngine
from commonhuman_sweep.models.events import Confidence, Signal, SweepRequest, SweepResponse


def _req(url: str = "http://example.com/api/user/1") -> SweepRequest:
    return SweepRequest(method="GET", url=url)


def _resp(status: int = 200, body: str = "", ct: str = "application/json") -> SweepResponse:
    return SweepResponse(status=status, body=body,
                         headers={"content-type": ct})


# ---------------------------------------------------------------------------
# ResponseClassifier
# ---------------------------------------------------------------------------

class TestEntropy:
    clf = ResponseClassifier()

    def test_empty_body_zero_entropy(self):
        assert self.clf.compute_entropy("") == 0.0

    def test_uniform_body_high_entropy(self):
        # All unique characters → high entropy
        body = "".join(chr(i) for i in range(128))
        score = self.clf.compute_entropy(body)
        assert score > 0.7

    def test_repetitive_body_low_entropy(self):
        score = self.clf.compute_entropy("aaaaaaaaaa")
        assert score < 0.2

    def test_entropy_bounded(self):
        for body in ["hello", '{"id":1}', "<html>test</html>", "A" * 1000]:
            score = self.clf.compute_entropy(body)
            assert 0.0 <= score <= 1.0


class TestFingerprint:
    clf = ResponseClassifier()

    def test_same_structure_same_fingerprint(self):
        r1 = _resp(body='{"id": 1, "name": "Alice"}')
        r2 = _resp(body='{"id": 2, "name": "Bob"}')
        self.clf.classify(_req(), r1)
        self.clf.classify(_req(), r2)
        assert r1.fingerprint == r2.fingerprint

    def test_different_structure_different_fingerprint(self):
        r1 = _resp(body='{"id": 1}')
        r2 = _resp(body='{"id": 1, "extra": "field"}')
        self.clf.classify(_req(), r1)
        self.clf.classify(_req(), r2)
        assert r1.fingerprint != r2.fingerprint

    def test_different_status_different_fingerprint(self):
        r1 = _resp(status=200, body="ok")
        r2 = _resp(status=404, body="ok")
        self.clf.classify(_req(), r1)
        self.clf.classify(_req(), r2)
        assert r1.fingerprint != r2.fingerprint


class TestSignalExtraction:
    clf = ResponseClassifier()

    def test_sqli_error_hint(self):
        resp = _resp(500, "You have an error in your SQL syntax near SELECT")
        cls = self.clf.classify(_req(), resp)
        assert Signal.SQLI_ERROR_HINT in cls.signals

    def test_stack_trace_leaked(self):
        resp = _resp(500, "Traceback (most recent call last):\n  File main.py")
        cls = self.clf.classify(_req(), resp)
        assert Signal.STACK_TRACE_LEAKED in cls.signals

    def test_server_error_signal(self):
        resp = _resp(500, "Internal Server Error")
        cls = self.clf.classify(_req(), resp)
        assert Signal.SERVER_ERROR in cls.signals

    def test_xss_reflection_hint(self):
        req = _req("http://example.com/search?q=<script>alert(1)</script>")
        resp = _resp(200, "Results for: <script>alert(1)</script>", ct="text/html")
        cls = self.clf.classify(req, resp)
        assert Signal.XSS_REFLECTION_HINT in cls.signals

    def test_mass_assignment_hint(self):
        resp = _resp(200, '{"id": 1, "is_admin": true, "name": "Alice"}')
        cls = self.clf.classify(_req(), resp)
        assert Signal.MASS_ASSIGNMENT_HINT in cls.signals

    def test_possible_idor_same_fingerprint_different_body(self):
        baseline = _resp(200, '{"id": 1, "name": "Alice"}')
        mutated  = _resp(200, '{"id": 2, "name": "Bob"}')
        self.clf.classify(_req(), baseline)
        mutated.fingerprint = baseline.fingerprint   # same structure
        cls = self.clf.classify(_req(), mutated, baseline=baseline)
        assert Signal.POSSIBLE_IDOR in cls.signals

    def test_auth_bypass_hint(self):
        baseline = _resp(403, "Forbidden")
        mutated  = _resp(200, '{"secret": "data"}')
        cls = self.clf.classify(_req(), mutated, baseline=baseline)
        assert Signal.AUTH_BYPASS_HINT in cls.signals

    def test_forbidden_signal(self):
        resp = _resp(403, "Forbidden")
        cls = self.clf.classify(_req(), resp)
        assert Signal.RESOURCE_FORBIDDEN in cls.signals

    def test_no_spurious_signals_on_clean_response(self):
        resp = _resp(200, '{"id": 1, "name": "Alice"}')
        cls = self.clf.classify(_req(), resp)
        bad_signals = {Signal.SQLI_ERROR_HINT, Signal.STACK_TRACE_LEAKED,
                       Signal.XSS_REFLECTION_HINT, Signal.SERVER_ERROR}
        assert not bad_signals.intersection(cls.signals)

    def test_api_schema_exposed(self):
        body = '{"openapi": "3.0.0", "info": {"title": "API"}, "paths": {}}'
        resp = _resp(200, body)
        cls = self.clf.classify(_req(), resp)
        assert Signal.API_SCHEMA_EXPOSED in cls.signals


class TestConfidenceScoring:
    clf = ResponseClassifier()

    def test_sqli_error_is_high_confidence(self):
        resp = _resp(500, "SQL syntax error ORA-00907")
        cls = self.clf.classify(_req(), resp)
        assert cls.confidence == Confidence.HIGH

    def test_possible_idor_is_medium(self):
        baseline = _resp(200, '{"id": 1, "name": "Alice"}')
        mutated  = _resp(200, '{"id": 2, "name": "Bob"}')
        self.clf.classify(_req(), baseline)
        mutated.fingerprint = baseline.fingerprint
        cls = self.clf.classify(_req(), mutated, baseline=baseline)
        assert cls.confidence == Confidence.MEDIUM

    def test_no_signals_is_low(self):
        resp = _resp(200, '{"status": "ok"}')
        cls = self.clf.classify(_req(), resp)
        assert cls.confidence == Confidence.LOW


class TestJsonShape:
    def test_flat_object(self):
        shape = _json_shape('{"id": 1, "name": "Alice"}')
        assert '"id":int' in shape
        assert '"name":str' in shape

    def test_nested_object(self):
        shape = _json_shape('{"user": {"id": 1}}')
        assert "user" in shape

    def test_array(self):
        shape = _json_shape('[{"id": 1}]')
        assert shape.startswith("[")

    def test_invalid_json_returns_empty(self):
        assert _json_shape("not json") == ""


# ---------------------------------------------------------------------------
# SimilarityEngine
# ---------------------------------------------------------------------------

class TestSimilarityEngine:
    sim = SimilarityEngine()
    clf = ResponseClassifier()

    def _classified(self, status: int, body: str, ct: str = "application/json") -> SweepResponse:
        """Return a response that has been run through the classifier (fingerprint set)."""
        r = _resp(status, body, ct)
        self.clf.classify(_req(), r)
        return r

    def test_identical_classified_responses_max_similarity(self):
        # Fingerprints must be set for full score — classify first
        r = self._classified(200, '{"id":1}')
        assert self.sim.compute_similarity(r, r) == 1.0

    def test_same_structure_classified_high_similarity(self):
        r1 = self._classified(200, '{"id":1,"name":"Alice"}')
        r2 = self._classified(200, '{"id":2,"name":"Bob"}')
        score = self.sim.compute_similarity(r1, r2)
        assert score >= 0.75   # same status + ct + fingerprint

    def test_same_status_content_type_high_similarity(self):
        r1 = _resp(200, '{"id":1,"name":"Alice"}')
        r2 = _resp(200, '{"id":2,"name":"Bob"}')
        score = self.sim.compute_similarity(r1, r2)
        assert score >= 0.5    # status + ct match without fingerprint

    def test_different_status_low_similarity(self):
        r1 = _resp(200, '{"id":1}')
        r2 = _resp(404, "Not Found", ct="text/plain")
        score = self.sim.compute_similarity(r1, r2)
        assert score < 0.5

    def test_is_same_class_classified_similar_responses(self):
        r1 = self._classified(200, '{"id":1,"name":"Alice"}')
        r2 = self._classified(200, '{"id":2,"name":"Bob"}')
        assert self.sim.is_same_class(r1, r2) is True

    def test_is_same_class_different_responses(self):
        r1 = _resp(200, '{"id":1}')
        r2 = _resp(500, "Internal Error", ct="text/plain")
        assert self.sim.is_same_class(r1, r2) is False

    def test_diff_detects_status_change(self):
        baseline  = _resp(200, '{"id":1}')
        candidate = _resp(403, "Forbidden", ct="text/plain")
        diff = self.sim.diff(baseline, candidate)
        assert diff["status_changed"] is True
        assert diff["significant"] is True

    def test_diff_no_change(self):
        r = _resp(200, '{"id":1}')
        diff = self.sim.diff(r, r)
        assert diff["status_changed"] is False
        assert diff["length_delta"] == 0

    def test_cluster_groups_classified_similar(self):
        responses = [
            self._classified(200, '{"id":1,"name":"Alice"}'),
            self._classified(200, '{"id":2,"name":"Bob"}'),
            self._classified(404, "Not Found", ct="text/plain"),
        ]
        clusters = self.sim.cluster(responses)
        # The two 200 JSON responses share a fingerprint → one cluster; 404 → another
        assert len(clusters) == 2

    def test_representative_returns_a_member(self):
        responses = [_resp(200, '{"id":1}'), _resp(200, '{"id":2}')]
        rep = self.sim.representative(responses)
        assert rep in responses


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------

class TestAnomalyDetector:
    def test_no_baseline_returns_zero(self):
        det = AnomalyDetector()
        resp = _resp(200, '{"id":1}')
        assert det.score("http://example.com/api/user/1", resp) == 0.0

    def test_identical_to_baseline_low_score(self):
        det = AnomalyDetector()
        resp = _resp(200, '{"id":1}')
        det.train("http://example.com/api/user/1", resp)
        assert det.score("http://example.com/api/user/1", resp) < 0.3

    def test_different_status_high_score(self):
        det = AnomalyDetector()
        baseline = _resp(200, '{"id":1}')
        det.train("http://example.com/api/user/1", baseline)
        candidate = _resp(403, "Forbidden", ct="text/plain")
        score = det.score("http://example.com/api/user/1", candidate)
        assert score > 0.3

    def test_is_anomalous_on_status_change(self):
        det = AnomalyDetector()
        det.train("http://example.com/item/1", _resp(200, '{"id":1}'))
        det.train("http://example.com/item/2", _resp(200, '{"id":2}'))
        assert det.is_anomalous("http://example.com/item/3", _resp(500, "Error")) is True

    def test_not_anomalous_when_consistent(self):
        det = AnomalyDetector()
        for i in range(5):
            det.train(f"http://example.com/item/{i}", _resp(200, f'{{"id":{i}}}'))
        assert det.is_anomalous("http://example.com/item/99", _resp(200, '{"id":99}')) is False

    def test_url_normalisation_buckets_ids_together(self):
        assert _normalise_url("http://example.com/api/users/123") == \
               _normalise_url("http://example.com/api/users/456")

    def test_url_normalisation_preserves_static(self):
        assert _normalise_url("http://example.com/api/users") == \
               "http://example.com/api/users"

    def test_error_response_gets_midpoint_score(self):
        det = AnomalyDetector()
        det.train("http://example.com/", _resp(200, "ok"))
        r = SweepResponse(status=0, error="timeout")
        assert det.score("http://example.com/", r) == 0.5

    def test_train_batch(self):
        det = AnomalyDetector()
        pairs = [
            ("http://example.com/a", _resp(200, '{"x":1}')),
            ("http://example.com/b", _resp(404, "nf")),
        ]
        det.train_batch(pairs)
        assert det.summary("http://example.com/a")["trained"] is True
        assert det.summary("http://example.com/b")["dominant_status"] == 404
