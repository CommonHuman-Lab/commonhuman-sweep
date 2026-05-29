# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
WordlistStrategy — wordlist-sourced surface exploration.

Accepts an optional wordlist as an input source, but routes every entry
through the MutationEngine's context transformer before execution.
Wordlist entries are NEVER emitted raw as URL targets.

Wordlist flow:
    wordlist entry
        → context classification (what role does this entry fit?)
        → Mutation(location=URL_PATH | QUERY_PARAM, source="wordlist")
        → RequestBuilder.apply()
        → ExecutionLayer.execute()
        → ResponseClassifier → AnomalyDetector
        → SweepEvent (only if interesting)

Response filtering is intelligence-driven, not threshold-based.
A 200 response is not automatically interesting — it must deviate
from the established baseline or trigger a signal pattern.
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


class WordlistStrategy(BaseStrategy):
    """
    Wordlist-sourced path/param exploration with intelligence-driven filtering.

    Accepts an optional wordlist. Without one, falls back to structural
    mutations only. Wordlist entries are transformed through the mutation
    engine — they are never fired as literal URL targets.
    """

    name        = "wordlist"
    description = "Wordlist-sourced exploration with intelligence-driven response filtering"

    def __init__(self) -> None:
        self._classifier = ResponseClassifier()
        self._detector   = AnomalyDetector()
        self._engine     = MutationEngine()

    async def discover(self, context: SweepContext) -> list[SweepRequest]:
        builder = RequestBuilder(context)
        return [builder.build_baseline(context.target)]

    async def execute(self, context: SweepContext) -> AsyncIterator[SweepEvent]:
        wordlist = self._load_wordlist(context.options.wordlist_path)
        if not wordlist:
            import warnings
            warnings.warn(
                "WordlistStrategy: no wordlist provided. "
                "Falling back to structural mutations only.",
                stacklevel=2,
            )

        builder  = RequestBuilder(context)
        base_req = builder.build_baseline(context.target)

        async with ExecutionLayer(context) as exec_layer:
            # Establish baseline
            baseline_resp = await exec_layer.execute(base_req)
            self._classifier.classify(base_req, baseline_resp)
            self._detector.train(context.target, baseline_resp)
            yield SweepEvent(
                event="sweep_baseline",
                target=context.target,
                request=base_req,
                response=baseline_resp,
                signals=[Signal.BASELINE_ESTABLISHED],
                strategy=self.name,
            )

            structure = self._engine.analyse(
                context.target,
                method=base_req.method,
                body=base_req.body,
                headers=base_req.headers,
            )

            # Generate mutations — wordlist entries are transformed, not iterated raw
            async for mutation in self._engine.generate(
                structure,
                wordlist=wordlist,
                depth=context.options.mutation_depth,
            ):
                mutated_req  = builder.apply(base_req, mutation)
                mutated_resp = await exec_layer.execute(mutated_req)
                cls          = self._classifier.classify(mutated_req, mutated_resp, baseline_resp)
                is_anomalous = self._detector.is_anomalous(context.target, mutated_resp)

                # Intelligence-driven filtering: only surface interesting responses
                if cls.interesting or is_anomalous:
                    if is_anomalous and Signal.ANOMALOUS_STATUS not in cls.signals:
                        cls.signals.append(Signal.ANOMALOUS_STATUS)

                    yield self._make_event(
                        request=mutated_req,
                        response=mutated_resp,
                        classification=cls,
                        target=context.target,
                        mutation_type=mutation.mutation_type.value,
                        parameter=mutation.parameter,
                        extra={"wordlist_entry": mutation.mutated_value if mutation.source == "wordlist" else None},
                    )

    # ------------------------------------------------------------------
    # Wordlist loading (delegates to commonhuman-cli shared utility)
    # ------------------------------------------------------------------

    def _load_wordlist(self, path: str) -> list[str] | None:
        if not path:
            return None
        try:
            from commonhuman_cli.entrypoint import load_wordlist
            return load_wordlist(path, sort_by_length=True)
        except SystemExit:
            return None
