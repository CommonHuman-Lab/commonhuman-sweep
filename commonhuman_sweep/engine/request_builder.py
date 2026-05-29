# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
RequestBuilder — constructs concrete SweepRequest objects.

Combines a base SweepContext (target URL, auth, default headers) with a
Mutation produced by the MutationEngine to produce a fully-formed request
that the ExecutionLayer can fire.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING

from commonhuman_sweep.models.context import SweepContext
from commonhuman_sweep.models.events import SweepRequest

if TYPE_CHECKING:
    from commonhuman_sweep.engine.mutation_engine import Mutation, MutationLocation


class RequestBuilder:
    """Applies mutations to a base request to produce SweepRequest instances."""

    def __init__(self, context: SweepContext) -> None:
        self._ctx = context

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_baseline(self, url: str, method: str = "GET", body: str | None = None) -> SweepRequest:
        """Build an unmodified baseline request for the given URL."""
        return SweepRequest(
            method=method,
            url=url,
            headers=self._ctx.base_headers(),
            body=body,
        )

    def apply(self, base: SweepRequest, mutation: "Mutation") -> SweepRequest:
        """Return a new SweepRequest with the mutation applied."""
        from commonhuman_sweep.engine.mutation_engine import MutationLocation

        loc = mutation.location
        handlers = {
            MutationLocation.URL_PATH:      self._mutate_path,
            MutationLocation.QUERY_PARAM:   self._mutate_query,
            MutationLocation.HEADER:        self._mutate_header,
            MutationLocation.BODY_FIELD:    self._mutate_body,
            MutationLocation.AUTH_CONTEXT:  self._mutate_auth,
        }
        handler = handlers.get(loc)
        if handler is None:
            return base
        return handler(base, mutation)

    # ------------------------------------------------------------------
    # Per-location mutators
    # ------------------------------------------------------------------

    def _mutate_path(self, base: SweepRequest, mutation: "Mutation") -> SweepRequest:
        parsed = urllib.parse.urlparse(base.url)
        segments = [s for s in parsed.path.split("/") if s]

        if mutation.parameter and mutation.parameter.isdigit():
            idx = int(mutation.parameter)
            if 0 <= idx < len(segments):
                segments[idx] = mutation.mutated_value
        else:
            segments.append(mutation.mutated_value)

        new_path = "/" + "/".join(segments)
        new_url = parsed._replace(path=new_path).geturl()
        return SweepRequest(
            method=base.method,
            url=new_url,
            headers=dict(base.headers),
            body=base.body,
        )

    def _mutate_query(self, base: SweepRequest, mutation: "Mutation") -> SweepRequest:
        parsed = urllib.parse.urlparse(base.url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if mutation.parameter:
            params[mutation.parameter] = mutation.mutated_value
        new_query = urllib.parse.urlencode(params)
        new_url = parsed._replace(query=new_query).geturl()
        return SweepRequest(
            method=base.method,
            url=new_url,
            headers=dict(base.headers),
            body=base.body,
        )

    def _mutate_header(self, base: SweepRequest, mutation: "Mutation") -> SweepRequest:
        headers = dict(base.headers)
        if mutation.parameter == "_REMOVE_AUTH_":
            headers.pop("Authorization", None)
            headers.pop("Cookie", None)
        elif mutation.parameter:
            headers[mutation.parameter] = mutation.mutated_value
        return SweepRequest(
            method=base.method,
            url=base.url,
            headers=headers,
            body=base.body,
        )

    def _mutate_body(self, base: SweepRequest, mutation: "Mutation") -> SweepRequest:
        body = base.body or "{}"
        try:
            doc = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            doc = {}

        if isinstance(doc, dict) and mutation.parameter:
            _set_nested(doc, mutation.parameter, _coerce(mutation.mutated_value))

        return SweepRequest(
            method=base.method,
            url=base.url,
            headers=dict(base.headers),
            body=json.dumps(doc),
        )

    def _mutate_auth(self, base: SweepRequest, mutation: "Mutation") -> SweepRequest:
        """Strip or swap auth credentials."""
        headers = dict(base.headers)
        if mutation.mutated_value == "__STRIP__":
            headers.pop("Authorization", None)
            headers.pop("Cookie", None)
        elif mutation.mutated_value == "__ALT__" and self._ctx.auth.alt_credential:
            cred = self._ctx.auth.alt_credential
            headers["Authorization"] = cred
        else:
            headers["Authorization"] = mutation.mutated_value
        return SweepRequest(
            method=base.method,
            url=base.url,
            headers=headers,
            body=base.body,
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def build_verb_variants(self, url: str, body: str | None = None) -> list[SweepRequest]:
        """Produce the same URL with all common HTTP verbs."""
        verbs = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        return [
            SweepRequest(method=v, url=url, headers=self._ctx.base_headers(), body=body)
            for v in verbs
        ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _set_nested(doc: dict, path: str, value: object) -> None:
    """Set a value in a nested dict using dot-notation path."""
    parts = path.split(".")
    for part in parts[:-1]:
        doc = doc.setdefault(part, {})
    doc[parts[-1]] = value


def _coerce(value: str) -> object:
    """Try to convert a string mutation value to an appropriate Python type."""
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value
