# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
AuthBoundaryStrategy — authentication boundary and privilege escalation exploration.

Tests three axes of auth failure:
  1. Horizontal — user A accessing user B's objects (IDOR)
  2. Vertical — user accessing admin/elevated endpoints
  3. Auth bypass — unauthenticated access to protected routes

Works in two modes:
  - Single-session: strips auth and probes for bypass
  - Dual-session: uses context.auth.alt_credential to compare sessions A vs B
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from commonhuman_sweep.engine.execution_layer import ExecutionLayer
from commonhuman_sweep.engine.mutation_engine import MutationEngine, MutationType
from commonhuman_sweep.engine.request_builder import RequestBuilder
from commonhuman_sweep.intelligence.anomaly_detector import AnomalyDetector
from commonhuman_sweep.intelligence.response_classifier import ResponseClassifier
from commonhuman_sweep.intelligence.similarity_engine import SimilarityEngine
from commonhuman_sweep.models.context import SweepContext
from commonhuman_sweep.models.events import (
    Confidence,
    Signal,
    SweepEvent,
    SweepRequest,
    SweepResponse,
)
from commonhuman_sweep.strategies.base_strategy import BaseStrategy


class AuthBoundaryStrategy(BaseStrategy):
    """
    Auth boundary and privilege escalation exploration.

    Pairs with PhaseAccess when its events are routed downstream for full
    IDOR confirmation. Sweep finds candidates; PhaseAccess confirms them.
    """

    name        = "auth"
    description = "Auth bypass, IDOR discovery, and privilege escalation boundary testing"

    def __init__(self) -> None:
        self._classifier = ResponseClassifier()
        self._detector   = AnomalyDetector()
        self._similarity = SimilarityEngine()
        self._engine     = MutationEngine()

    async def discover(self, context: SweepContext) -> list[SweepRequest]:
        builder = RequestBuilder(context)
        urls: list[str] = []

        if context.options.crawl:
            try:
                from commonhuman_core.crawler import crawl
                from commonhuman_core.http import HttpClient

                client = HttpClient(
                    timeout=int(context.options.timeout),
                    proxy=context.options.proxy or None,
                    headers=context.base_headers(),
                    verify_ssl=context.options.verify_ssl,
                )
                result = crawl(context.target, client,
                               max_pages=context.options.max_pages,
                               max_depth=context.options.max_depth)
                client.close()
                urls.extend(result.visited_urls)
                # Harvest IDs from responses for IDOR probing
                for url in result.visited_urls:
                    _harvest_ids_from_url(url, context.harvested_ids)
            except Exception:  # noqa: BLE001
                pass

        if not urls:
            urls = [context.target]

        context.discovered_urls = urls
        return [builder.build_baseline(u) for u in urls]

    async def execute(self, context: SweepContext) -> AsyncIterator[SweepEvent]:
        builder     = RequestBuilder(context)
        dual_session = bool(context.auth.alt_credential)

        async with ExecutionLayer(context) as exec_layer:
            candidates = await self.discover(context)
            baselines: dict[str, SweepResponse] = {}

            # Baseline with primary session
            for req in candidates:
                resp = await exec_layer.execute(req)
                self._classifier.classify(req, resp)
                self._detector.train(req.url, resp)
                baselines[req.url] = resp

            for req in candidates:
                baseline = baselines.get(req.url)

                # 1. Auth strip — unauthenticated access probe
                async for event in self._probe_auth_strip(
                    req, baseline, context, exec_layer, builder
                ):
                    yield event

                # 2. Dual-session horizontal access test
                if dual_session:
                    async for event in self._probe_dual_session(
                        req, baseline, context, exec_layer, builder
                    ):
                        yield event

                # 3. IDOR — id mutation on path/params with harvested IDs
                async for event in self._probe_idor_candidates(
                    req, baseline, context, exec_layer, builder
                ):
                    yield event

    # ------------------------------------------------------------------
    # Auth strip probes
    # ------------------------------------------------------------------

    async def _probe_auth_strip(
        self,
        req: SweepRequest,
        baseline: SweepResponse | None,
        context: SweepContext,
        exec_layer: ExecutionLayer,
        builder: RequestBuilder,
    ) -> AsyncIterator[SweepEvent]:
        from commonhuman_sweep.engine.mutation_engine import Mutation, MutationLocation

        # Skip if baseline was already unauthenticated (no interesting baseline)
        if baseline and baseline.status in (401, 403, 404):
            return

        strip_mutation = Mutation(
            location=MutationLocation.AUTH_CONTEXT,
            mutation_type=MutationType.AUTH_STRIP,
            mutated_value="__STRIP__",
            parameter="_REMOVE_AUTH_",
        )
        stripped_req  = builder.apply(req, strip_mutation)
        stripped_resp = await exec_layer.execute(stripped_req)
        cls           = self._classifier.classify(stripped_req, stripped_resp, baseline)

        # Flag if stripped request gets same or better access than authenticated
        if baseline and stripped_resp.status in (200, 201, 204):
            if baseline.status in (200, 201, 204):
                diff = self._similarity.diff(baseline, stripped_resp)
                if not diff["significant"]:
                    cls.signals.append(Signal.AUTH_BYPASS_HINT)
                    cls.confidence = Confidence.HIGH

        if cls.interesting:
            yield self._make_event(
                request=stripped_req,
                response=stripped_resp,
                classification=cls,
                target=context.target,
                mutation_type=MutationType.AUTH_STRIP.value,
            )

    # ------------------------------------------------------------------
    # Dual-session horizontal access test
    # ------------------------------------------------------------------

    async def _probe_dual_session(
        self,
        req: SweepRequest,
        baseline: SweepResponse | None,
        context: SweepContext,
        exec_layer: ExecutionLayer,
        builder: RequestBuilder,
    ) -> AsyncIterator[SweepEvent]:
        from commonhuman_sweep.engine.mutation_engine import Mutation, MutationLocation

        swap_mutation = Mutation(
            location=MutationLocation.AUTH_CONTEXT,
            mutation_type=MutationType.AUTH_SWAP,
            mutated_value="__ALT__",
            parameter="_SWAP_AUTH_",
        )
        alt_req  = builder.apply(req, swap_mutation)
        alt_resp = await exec_layer.execute(alt_req)
        cls      = self._classifier.classify(alt_req, alt_resp, baseline)

        # IDOR: same structure, different content under alt session
        if (
            baseline
            and alt_resp.status == 200
            and baseline.status == 200
            and alt_resp.fingerprint == baseline.fingerprint
            and alt_resp.body != baseline.body
        ):
            cls.signals.append(Signal.POSSIBLE_IDOR)
            cls.confidence = Confidence.HIGH

        if cls.interesting:
            yield self._make_event(
                request=alt_req,
                response=alt_resp,
                classification=cls,
                target=context.target,
                mutation_type=MutationType.AUTH_SWAP.value,
                extra={"session": context.auth.alt_label},
            )

    # ------------------------------------------------------------------
    # IDOR candidate probes using harvested IDs
    # ------------------------------------------------------------------

    async def _probe_idor_candidates(
        self,
        req: SweepRequest,
        baseline: SweepResponse | None,
        context: SweepContext,
        exec_layer: ExecutionLayer,
        builder: RequestBuilder,
    ) -> AsyncIterator[SweepEvent]:
        structure = self._engine.analyse(req.url, method=req.method, body=req.body,
                                          headers=req.headers)
        async for mutation in self._engine.generate(
            structure,
            harvested_ids=context.harvested_ids,
            depth=1,
        ):
            # Only ID-based mutations for this strategy
            if mutation.source != "harvested":
                continue
            mutated = builder.apply(req, mutation)
            resp    = await exec_layer.execute(mutated)
            cls     = self._classifier.classify(mutated, resp, baseline)

            if baseline and resp.status == 200 and baseline.status == 200:
                diff = self._similarity.diff(baseline, resp)
                if not diff["significant"] and resp.body != baseline.body:
                    cls.signals.append(Signal.POSSIBLE_IDOR)
                    cls.confidence = Confidence.MEDIUM

            if cls.interesting:
                yield self._make_event(
                    request=mutated,
                    response=resp,
                    classification=cls,
                    target=context.target,
                    mutation_type=mutation.mutation_type.value,
                    parameter=mutation.parameter,
                )


def _harvest_ids_from_url(url: str, store: dict[str, list[str]]) -> None:
    """Extract integer and UUID IDs from a URL and store in the shared harvest dict."""
    import re
    uuid_re = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
    int_re  = re.compile(r"/(\d+)(?:/|$)")

    for m in uuid_re.findall(url):
        store.setdefault("uuid", []).append(m)
    for m in int_re.findall(url):
        store.setdefault("int", []).append(m)
