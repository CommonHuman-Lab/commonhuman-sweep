# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
SmartFuzzStrategy — the default multi-phase intelligence-driven strategy.

Phase 1 — Discover: crawl the target, harvest URLs, forms, path patterns.
Phase 2 — Baseline: establish response fingerprints for all discovered endpoints.
Phase 3 — Mutate: apply context-aware mutations, emit events for anomalies.
Phase 4 — Classify: filter noise, score results, route to event bus.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from commonhuman_sweep.engine.execution_layer import ExecutionLayer
from commonhuman_sweep.engine.mutation_engine import MutationEngine
from commonhuman_sweep.engine.request_builder import RequestBuilder
from commonhuman_sweep.intelligence.anomaly_detector import AnomalyDetector
from commonhuman_sweep.intelligence.response_classifier import ResponseClassifier
from commonhuman_sweep.models.context import SweepContext
from commonhuman_sweep.models.events import Signal, SweepEvent, SweepRequest, SweepResponse
from commonhuman_sweep.strategies.base_strategy import BaseStrategy


class SmartFuzzStrategy(BaseStrategy):
    """
    Multi-phase, intelligence-driven surface exploration.

    Does NOT iterate wordlists directly. Crawls the target, infers structure,
    generates context-aware mutations, then surfaces only statistically
    anomalous or signal-bearing responses.
    """

    name        = "smart"
    description = "Multi-phase crawl + structural mutation with anomaly detection"

    def __init__(self) -> None:
        self._classifier = ResponseClassifier()
        self._detector   = AnomalyDetector()
        self._engine     = MutationEngine()

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover(self, context: SweepContext) -> list[SweepRequest]:
        """Crawl target and return baseline requests for all discovered URLs."""
        builder  = RequestBuilder(context)
        urls: list[str] = [context.target]

        if context.options.crawl:
            urls.extend(await self._crawl(context))

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)

        context.discovered_urls = unique
        return [builder.build_baseline(u) for u in unique]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def execute(self, context: SweepContext) -> AsyncIterator[SweepEvent]:
        builder  = RequestBuilder(context)
        wordlist = _load_wordlist(context.options.wordlist_path)

        async with ExecutionLayer(context) as exec_layer:
            # Phase 1+2: discover and baseline
            candidates = await self.discover(context)
            baselines: dict[str, SweepResponse] = {}

            for req in candidates:
                resp = await exec_layer.execute(req)
                self._classifier.classify(req, resp)
                self._detector.train(req.url, resp)
                baselines[req.url] = resp
                yield SweepEvent(
                    event="sweep_baseline",
                    target=context.target,
                    request=req,
                    response=resp,
                    signals=[Signal.BASELINE_ESTABLISHED],
                    strategy=self.name,
                )

            # Phase 3: mutate
            for base_req in candidates:
                base_url  = base_req.url
                baseline  = baselines.get(base_url)
                structure = self._engine.analyse(
                    base_url,
                    method=base_req.method,
                    body=base_req.body,
                    headers=base_req.headers,
                )

                async for mutation in self._engine.generate(
                    structure,
                    wordlist=wordlist,
                    harvested_ids=context.harvested_ids,
                    depth=context.options.mutation_depth,
                ):
                    mutated_req = builder.apply(base_req, mutation)
                    mutated_resp = await exec_layer.execute(mutated_req)

                    classification = self._classifier.classify(
                        mutated_req, mutated_resp, baseline=baseline
                    )

                    is_anomalous = self._detector.is_anomalous(base_url, mutated_resp)
                    if classification.interesting or is_anomalous:
                        if is_anomalous and Signal.ANOMALOUS_STATUS not in classification.signals:
                            classification.signals.append(Signal.ANOMALOUS_STATUS)

                        event = self._make_event(
                            request=mutated_req,
                            response=mutated_resp,
                            classification=classification,
                            target=context.target,
                            mutation_type=mutation.mutation_type.value,
                            parameter=mutation.parameter,
                        )
                        yield event

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _crawl(self, context: SweepContext) -> list[str]:
        """Use commonhuman-core crawler to discover URLs."""
        try:
            from commonhuman_core.crawler import crawl
            from commonhuman_core.http import HttpClient

            client = HttpClient(
                timeout=int(context.options.timeout),
                proxy=context.options.proxy or None,
                headers=context.base_headers(),
                verify_ssl=context.options.verify_ssl,
            )
            result = crawl(
                context.target,
                client,
                max_pages=context.options.max_pages,
                max_depth=context.options.max_depth,
            )
            client.close()
            return result.visited_urls
        except Exception:  # noqa: BLE001
            return []


def _load_wordlist(path: str) -> list[str] | None:
    if not path:
        return None
    try:
        with open(path) as fh:
            return [l.rstrip("\n") for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return None
