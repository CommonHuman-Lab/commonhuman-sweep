# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
APISurfaceStrategy — REST/GraphQL API surface exploration.

Discovers REST endpoints by combining:
  - OpenAPI/Swagger spec parsing (if available at /openapi.json, /swagger.json, etc.)
  - JS source-map recovery
  - HTTP verb coverage testing per discovered resource
  - Pagination + nested resource traversal

Never brute-forces endpoint names. Infers resource structure from what exists.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from commonhuman_sweep.engine.execution_layer import ExecutionLayer
from commonhuman_sweep.engine.mutation_engine import MutationEngine
from commonhuman_sweep.engine.request_builder import RequestBuilder
from commonhuman_sweep.intelligence.anomaly_detector import AnomalyDetector
from commonhuman_sweep.intelligence.response_classifier import ResponseClassifier
from commonhuman_sweep.models.context import SweepContext
from commonhuman_sweep.models.events import (
    Confidence,
    Signal,
    SweepEvent,
    SweepRequest,
    SweepResponse,
)
from commonhuman_sweep.strategies.base_strategy import BaseStrategy


_OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api/openapi.json", "/api/swagger.json", "/docs/openapi.json",
    "/v1/openapi.json", "/api/v1/openapi.json",
]

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/query", "/gql"]

_HTTP_VERBS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


class APISurfaceStrategy(BaseStrategy):
    """
    API surface exploration through spec discovery and verb coverage testing.

    Discovers what endpoints exist, then probes each with all HTTP verbs
    and contextual mutations. Emits signals for verb mismatches, exposed
    schemas, and mass-assignment opportunities.
    """

    name        = "api"
    description = "REST/GraphQL API surface exploration with verb coverage and schema discovery"

    def __init__(self) -> None:
        self._classifier = ResponseClassifier()
        self._detector   = AnomalyDetector()
        self._engine     = MutationEngine()

    async def discover(self, context: SweepContext) -> list[SweepRequest]:
        builder  = RequestBuilder(context)
        urls: list[str] = []

        # Spec-driven discovery
        spec_urls = await self._discover_from_spec(context)
        urls.extend(spec_urls)

        # Crawl-based discovery
        if context.options.crawl and not spec_urls:
            urls.extend(await self._discover_from_crawl(context))

        # GraphQL endpoint probe
        urls.extend(await self._probe_graphql(context))

        if not urls:
            urls = [context.target]

        seen: set[str] = set()
        unique = [u for u in urls if u not in seen and not seen.add(u)]  # type: ignore[func-returns-value]
        context.discovered_urls = unique
        return [builder.build_baseline(u) for u in unique]

    async def execute(self, context: SweepContext) -> AsyncIterator[SweepEvent]:
        builder = RequestBuilder(context)

        async with ExecutionLayer(context) as exec_layer:
            candidates = await self.discover(context)
            baselines: dict[str, SweepResponse] = {}

            # Baseline all discovered endpoints
            for req in candidates:
                resp = await exec_layer.execute(req)
                self._classifier.classify(req, resp)
                self._detector.train(req.url, resp)
                baselines[req.url] = resp

            # Verb coverage test
            for req in candidates:
                baseline = baselines.get(req.url)
                verb_variants = builder.build_verb_variants(req.url, body=req.body)

                for verb_req in verb_variants:
                    if verb_req.method == req.method:
                        continue
                    resp = await exec_layer.execute(verb_req)
                    cls  = self._classifier.classify(verb_req, resp, baseline)

                    # Flag if a non-GET verb returns 200 where GET was baseline
                    if (
                        baseline and baseline.status == 200
                        and resp.status == 200
                        and verb_req.method in ("PUT", "DELETE", "PATCH")
                    ):
                        cls.signals.append(Signal.API_VERB_MISMATCH)
                        cls.confidence = Confidence.HIGH

                    if cls.interesting or self._detector.is_anomalous(req.url, resp):
                        yield self._make_event(
                            request=verb_req,
                            response=resp,
                            classification=cls,
                            target=context.target,
                            mutation_type="http_verb_coverage",
                            parameter="method",
                        )

            # Structural mutations on each endpoint
            for req in candidates:
                baseline  = baselines.get(req.url)
                structure = self._engine.analyse(req.url, method=req.method, body=req.body,
                                                  headers=req.headers)
                async for mutation in self._engine.generate(
                    structure,
                    depth=context.options.mutation_depth,
                ):
                    mutated = builder.apply(req, mutation)
                    resp    = await exec_layer.execute(mutated)
                    cls     = self._classifier.classify(mutated, resp, baseline)

                    if cls.interesting or self._detector.is_anomalous(req.url, resp):
                        yield self._make_event(
                            request=mutated,
                            response=resp,
                            classification=cls,
                            target=context.target,
                            mutation_type=mutation.mutation_type.value,
                            parameter=mutation.parameter,
                        )

    # ------------------------------------------------------------------
    # Spec discovery helpers
    # ------------------------------------------------------------------

    async def _discover_from_spec(self, context: SweepContext) -> list[str]:
        """Try known OpenAPI spec paths and extract endpoint URLs if found."""
        import urllib.parse

        base = context.target.rstrip("/")
        found_urls: list[str] = []

        async with ExecutionLayer(context) as exec_layer:
            for path in _OPENAPI_PATHS:
                req  = SweepRequest(method="GET", url=base + path,
                                    headers=context.base_headers())
                resp = await exec_layer.execute(req)
                if resp.status == 200 and resp.is_json:
                    found_urls.extend(_extract_openapi_urls(base, resp.body))
                    break

        # Fall back to spec path provided in context
        if not found_urls and context.api_spec_path:
            try:
                from commonhuman_core.openapi import load_openapi
                spec = load_openapi(context.api_spec_path)
                found_urls = [base + p for p in spec.paths]
            except Exception:  # noqa: BLE001
                pass

        return found_urls

    async def _discover_from_crawl(self, context: SweepContext) -> list[str]:
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
            # Only API-looking paths (/api/, /v1/, etc.)
            return [u for u in result.visited_urls if _looks_like_api(u)]
        except Exception:  # noqa: BLE001
            return []

    async def _probe_graphql(self, context: SweepContext) -> list[str]:
        """Return GraphQL endpoints that respond to introspection."""
        base  = context.target.rstrip("/")
        found = []

        async with ExecutionLayer(context) as exec_layer:
            for path in _GRAPHQL_PATHS:
                url = base + path
                body = '{"query":"{__typename}"}'
                req  = SweepRequest(
                    method="POST", url=url,
                    headers={**context.base_headers(), "Content-Type": "application/json"},
                    body=body,
                )
                resp = await exec_layer.execute(req)
                if resp.status == 200 and "data" in resp.body:
                    found.append(url)
        return found


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_openapi_urls(base: str, body: str) -> list[str]:
    import json
    try:
        spec = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return []
    paths = spec.get("paths", {})
    return [base + path for path in paths if isinstance(path, str)]


def _looks_like_api(url: str) -> bool:
    import re
    return bool(re.search(r"/(api|v\d+|graphql|rest|service)/", url, re.I))
