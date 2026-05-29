# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
MutationEngine — context-aware request mutation.

The engine NEVER blindly iterates a wordlist. Instead it:
  1. Analyses the request structure to infer parameter roles, API style, and ID types.
  2. Generates semantically meaningful mutations per role (boundary tests for integers,
     traversal variants for paths, privilege-escalation probes for auth fields, etc.).
  3. Optionally blends wordlist entries by routing them through context transformation
     rather than emitting them raw.

Wordlist flow:
  wordlist entries → context transformer → Mutation(role-aware) → RequestBuilder
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class MutationLocation(str, Enum):
    URL_PATH     = "url_path"
    QUERY_PARAM  = "query_param"
    HEADER       = "header"
    BODY_FIELD   = "body_field"
    AUTH_CONTEXT = "auth_context"


class MutationType(str, Enum):
    # Path
    PATH_ID_ADJACENT       = "path_id_adjacent"
    PATH_ID_BOUNDARY       = "path_id_boundary"
    PATH_ID_TYPE_CONFUSION = "path_id_type_confusion"
    PATH_TRAVERSAL         = "path_traversal"
    PATH_EXTENSION         = "path_extension"
    PATH_VERSION           = "path_version"
    PATH_WORDLIST          = "path_wordlist"

    # Query param
    PARAM_INT_ADJACENT     = "param_int_adjacent"
    PARAM_INT_BOUNDARY     = "param_int_boundary"
    PARAM_TYPE_CONFUSION   = "param_type_confusion"
    PARAM_TRAVERSAL        = "param_traversal"
    PARAM_INJECT_PROBE     = "param_inject_probe"
    PARAM_WORDLIST         = "param_wordlist"

    # Header
    HEADER_IP_SPOOF        = "header_ip_spoof"
    HEADER_AUTH_STRIP      = "header_auth_strip"
    HEADER_AUTH_TAMPER     = "header_auth_tamper"
    HEADER_CONTENT_TYPE    = "header_content_type"

    # Body
    BODY_FIELD_INJECT      = "body_field_inject"
    BODY_PRIVILEGE_ESCALATE = "body_privilege_escalate"
    BODY_TYPE_CONFUSION    = "body_type_confusion"
    BODY_FIELD_REMOVE      = "body_field_remove"

    # Auth
    AUTH_STRIP             = "auth_strip"
    AUTH_SWAP              = "auth_swap"


# ---------------------------------------------------------------------------
# Structural analysis types
# ---------------------------------------------------------------------------

class PathRole(str, Enum):
    STATIC   = "static"
    ID_INT   = "id_int"
    ID_UUID  = "id_uuid"
    ID_HASH  = "id_hash"
    ID_SLUG  = "id_slug"
    ACTION   = "action"
    VERSION  = "version"
    RESOURCE = "resource"


class ParamRole(str, Enum):
    ID         = "id"
    AUTH       = "auth"
    FILE       = "file"
    FILTER     = "filter"
    PAGINATION = "pagination"
    UNKNOWN    = "unknown"


class APIStyle(str, Enum):
    REST     = "rest"
    GRAPHQL  = "graphql"
    FORM     = "form"
    UNKNOWN  = "unknown"


@dataclass
class PathSegment:
    raw:   str
    index: int
    role:  PathRole


@dataclass
class QueryParam:
    name:            str
    value:           str
    inferred_type:   str   # "int" | "uuid" | "string" | "bool" | "base64" | "unknown"
    role:            ParamRole


@dataclass
class RequestStructure:
    method:           str
    base_url:         str
    path_segments:    list[PathSegment]
    query_params:     list[QueryParam]
    body_fields:      list[str]          # top-level JSON field names, or []
    api_style:        APIStyle
    has_auth:         bool
    content_type:     str


@dataclass
class Mutation:
    location:       MutationLocation
    mutation_type:  MutationType
    mutated_value:  str
    parameter:      str              = ""   # segment index (as str) or param/field name
    original_value: str              = ""
    source:         str              = "structural"   # "structural" | "wordlist" | "harvested"
    extra:          dict[str, Any]   = field(default_factory=dict)


# ---------------------------------------------------------------------------
# MutationEngine
# ---------------------------------------------------------------------------

_UUID_RE   = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_INT_RE    = re.compile(r"^\d+$")
_HASH_RE   = re.compile(r"^[0-9a-f]{32,64}$", re.I)
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_VERSION_RE = re.compile(r"^v\d+$", re.I)

_AUTH_PARAM_NAMES = {"token", "auth", "api_key", "apikey", "key", "secret", "access_token", "jwt"}
_FILE_PARAM_NAMES = {"file", "path", "filename", "filepath", "attachment", "upload", "document"}
_ID_PARAM_NAMES   = {"id", "uid", "user_id", "userid", "account", "object_id", "oid", "pid"}
_PAGE_PARAM_NAMES = {"page", "offset", "limit", "per_page", "size", "cursor", "after", "before"}

_PRIV_ESC_FIELDS  = [
    ("admin", "true"), ("is_admin", "true"), ("role", "admin"), ("is_superuser", "true"),
    ("privilege", "high"), ("permissions", "admin"), ("group", "admins"), ("level", "0"),
    ("status", "active"), ("verified", "true"), ("owner_id", "1"),
]

_IP_SPOOF_HEADERS = {
    "X-Forwarded-For":  "127.0.0.1",
    "X-Real-IP":        "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Remote-Addr":    "127.0.0.1",
    "X-Client-IP":      "127.0.0.1",
    "True-Client-IP":   "127.0.0.1",
    "CF-Connecting-IP": "127.0.0.1",
}

_INJECT_PROBES = [
    "'",          # SQL error probe
    "\"",         # SQL / XSS probe
    "<script>",   # XSS reflection probe
    "{{7*7}}",    # SSTI probe
    "../",        # Path traversal probe
]

_CONTENT_TYPE_VARIANTS = [
    "application/json",
    "application/x-www-form-urlencoded",
    "application/xml",
    "text/plain",
    "multipart/form-data",
]


class MutationEngine:
    """
    Analyse a request URL + body and yield context-aware Mutation objects.

    Wordlists are optional and are consumed as an input source that is
    filtered and transformed through the context analysis — not iterated
    directly as scan targets.
    """

    def analyse(self, url: str, method: str = "GET", body: str | None = None,
                headers: dict[str, str] | None = None) -> RequestStructure:
        """Infer the structural role of every part of the request."""
        parsed = urllib.parse.urlparse(url)
        raw_segments = [s for s in parsed.path.split("/") if s]

        path_segments = [
            PathSegment(raw=seg, index=i, role=_classify_segment(seg))
            for i, seg in enumerate(raw_segments)
        ]
        query_params = [
            QueryParam(
                name=k, value=v,
                inferred_type=_infer_value_type(v),
                role=_classify_param(k),
            )
            for k, v in urllib.parse.parse_qsl(parsed.query)
        ]

        body_fields: list[str] = []
        if body:
            try:
                doc = json.loads(body)
                if isinstance(doc, dict):
                    body_fields = list(doc.keys())
            except (json.JSONDecodeError, ValueError):
                pass

        ct = (headers or {}).get("Content-Type", (headers or {}).get("content-type", ""))
        api_style = _infer_api_style(parsed.path, ct, body)
        has_auth = any(
            k.lower() in ("authorization", "cookie", "x-api-key")
            for k in (headers or {})
        )

        return RequestStructure(
            method=method,
            base_url=url,
            path_segments=path_segments,
            query_params=query_params,
            body_fields=body_fields,
            api_style=api_style,
            has_auth=has_auth,
            content_type=ct,
        )

    async def generate(
        self,
        structure: RequestStructure,
        wordlist: list[str] | None = None,
        harvested_ids: dict[str, list[str]] | None = None,
        depth: int = 2,
    ) -> AsyncIterator[Mutation]:
        """Yield Mutation objects. Caller applies them via RequestBuilder."""
        seen: set[str] = set()

        async def _emit(m: Mutation) -> AsyncIterator[Mutation]:
            key = f"{m.location}:{m.parameter}:{m.mutated_value}"
            if key not in seen:
                seen.add(key)
                yield m

        async for m in self._path_mutations(structure, depth):
            async for x in _emit(m): yield x

        async for m in self._query_mutations(structure, harvested_ids or {}):
            async for x in _emit(m): yield x

        async for m in self._header_mutations(structure):
            async for x in _emit(m): yield x

        async for m in self._body_mutations(structure):
            async for x in _emit(m): yield x

        if structure.has_auth:
            async for m in self._auth_mutations():
                async for x in _emit(m): yield x

        if wordlist:
            async for m in self._wordlist_mutations(structure, wordlist):
                async for x in _emit(m): yield x

    # ------------------------------------------------------------------
    # Path mutations
    # ------------------------------------------------------------------

    async def _path_mutations(
        self, s: RequestStructure, depth: int
    ) -> AsyncIterator[Mutation]:
        for seg in s.path_segments:
            if seg.role == PathRole.ID_INT:
                n = int(seg.raw)
                for adj in _adjacent_ints(n, depth):
                    yield Mutation(
                        location=MutationLocation.URL_PATH,
                        mutation_type=MutationType.PATH_ID_ADJACENT,
                        mutated_value=str(adj),
                        parameter=str(seg.index),
                        original_value=seg.raw,
                    )
                for bv in _boundary_ints():
                    yield Mutation(
                        location=MutationLocation.URL_PATH,
                        mutation_type=MutationType.PATH_ID_BOUNDARY,
                        mutated_value=str(bv),
                        parameter=str(seg.index),
                        original_value=seg.raw,
                    )
                for tc in ("abc", "null", "undefined", "true", "[]", "{}"):
                    yield Mutation(
                        location=MutationLocation.URL_PATH,
                        mutation_type=MutationType.PATH_ID_TYPE_CONFUSION,
                        mutated_value=tc,
                        parameter=str(seg.index),
                        original_value=seg.raw,
                    )

            elif seg.role == PathRole.VERSION:
                for v in _version_variants(seg.raw):
                    yield Mutation(
                        location=MutationLocation.URL_PATH,
                        mutation_type=MutationType.PATH_VERSION,
                        mutated_value=v,
                        parameter=str(seg.index),
                        original_value=seg.raw,
                    )

        # Path traversal — append to current URL
        for trav in _traversal_payloads():
            yield Mutation(
                location=MutationLocation.URL_PATH,
                mutation_type=MutationType.PATH_TRAVERSAL,
                mutated_value=trav,
                source="structural",
            )

        # Extension variants on last static segment
        static = [seg for seg in s.path_segments if seg.role == PathRole.STATIC]
        if static:
            last = static[-1]
            for ext in (".json", ".xml", ".yaml", ".bak", ".php", ".asp", ".txt"):
                yield Mutation(
                    location=MutationLocation.URL_PATH,
                    mutation_type=MutationType.PATH_EXTENSION,
                    mutated_value=last.raw + ext,
                    parameter=str(last.index),
                    original_value=last.raw,
                )

    # ------------------------------------------------------------------
    # Query param mutations
    # ------------------------------------------------------------------

    async def _query_mutations(
        self, s: RequestStructure, harvested_ids: dict[str, list[str]]
    ) -> AsyncIterator[Mutation]:
        for qp in s.query_params:
            if qp.role == ParamRole.ID:
                if qp.inferred_type == "int":
                    n = int(qp.value) if qp.value.isdigit() else 1
                    for adj in _adjacent_ints(n, 3):
                        yield Mutation(
                            location=MutationLocation.QUERY_PARAM,
                            mutation_type=MutationType.PARAM_INT_ADJACENT,
                            mutated_value=str(adj),
                            parameter=qp.name,
                            original_value=qp.value,
                        )
                    for bv in _boundary_ints():
                        yield Mutation(
                            location=MutationLocation.QUERY_PARAM,
                            mutation_type=MutationType.PARAM_INT_BOUNDARY,
                            mutated_value=str(bv),
                            parameter=qp.name,
                            original_value=qp.value,
                        )
                # Inject harvested IDs of matching type
                for harvested in harvested_ids.get(qp.inferred_type, []):
                    if harvested != qp.value:
                        yield Mutation(
                            location=MutationLocation.QUERY_PARAM,
                            mutation_type=MutationType.PARAM_INT_ADJACENT,
                            mutated_value=harvested,
                            parameter=qp.name,
                            original_value=qp.value,
                            source="harvested",
                        )

            if qp.role == ParamRole.FILE:
                for trav in _traversal_payloads():
                    yield Mutation(
                        location=MutationLocation.QUERY_PARAM,
                        mutation_type=MutationType.PARAM_TRAVERSAL,
                        mutated_value=trav,
                        parameter=qp.name,
                        original_value=qp.value,
                    )

            # Lightweight injection probes on all params
            for probe in _INJECT_PROBES:
                yield Mutation(
                    location=MutationLocation.QUERY_PARAM,
                    mutation_type=MutationType.PARAM_INJECT_PROBE,
                    mutated_value=qp.value + probe,
                    parameter=qp.name,
                    original_value=qp.value,
                )

            # Type confusion on all params
            for tc in ("null", "true", "[]", "-1"):
                yield Mutation(
                    location=MutationLocation.QUERY_PARAM,
                    mutation_type=MutationType.PARAM_TYPE_CONFUSION,
                    mutated_value=tc,
                    parameter=qp.name,
                    original_value=qp.value,
                )

    # ------------------------------------------------------------------
    # Header mutations
    # ------------------------------------------------------------------

    async def _header_mutations(self, s: RequestStructure) -> AsyncIterator[Mutation]:
        for header, value in _IP_SPOOF_HEADERS.items():
            yield Mutation(
                location=MutationLocation.HEADER,
                mutation_type=MutationType.HEADER_IP_SPOOF,
                mutated_value=value,
                parameter=header,
            )

        for ct in _CONTENT_TYPE_VARIANTS:
            if ct != s.content_type:
                yield Mutation(
                    location=MutationLocation.HEADER,
                    mutation_type=MutationType.HEADER_CONTENT_TYPE,
                    mutated_value=ct,
                    parameter="Content-Type",
                    original_value=s.content_type,
                )

    # ------------------------------------------------------------------
    # Body mutations
    # ------------------------------------------------------------------

    async def _body_mutations(self, s: RequestStructure) -> AsyncIterator[Mutation]:
        if not s.body_fields and s.api_style != APIStyle.REST:
            return

        # Privilege escalation fields
        for fname, fvalue in _PRIV_ESC_FIELDS:
            yield Mutation(
                location=MutationLocation.BODY_FIELD,
                mutation_type=MutationType.BODY_PRIVILEGE_ESCALATE,
                mutated_value=fvalue,
                parameter=fname,
            )

        # Type confusion on existing fields
        for fname in s.body_fields:
            for tc in ("null", "true", "-1", "[]", "{}"):
                yield Mutation(
                    location=MutationLocation.BODY_FIELD,
                    mutation_type=MutationType.BODY_TYPE_CONFUSION,
                    mutated_value=tc,
                    parameter=fname,
                )
            # Inject probe
            for probe in _INJECT_PROBES[:2]:   # SQL + XSS probes only in body
                yield Mutation(
                    location=MutationLocation.BODY_FIELD,
                    mutation_type=MutationType.BODY_FIELD_INJECT,
                    mutated_value=probe,
                    parameter=fname,
                )

    # ------------------------------------------------------------------
    # Auth mutations
    # ------------------------------------------------------------------

    async def _auth_mutations(self) -> AsyncIterator[Mutation]:
        yield Mutation(
            location=MutationLocation.AUTH_CONTEXT,
            mutation_type=MutationType.AUTH_STRIP,
            mutated_value="__STRIP__",
            parameter="_REMOVE_AUTH_",
        )
        yield Mutation(
            location=MutationLocation.AUTH_CONTEXT,
            mutation_type=MutationType.AUTH_SWAP,
            mutated_value="__ALT__",
            parameter="_SWAP_AUTH_",
        )

    # ------------------------------------------------------------------
    # Wordlist mutations — context-aware transformation
    # ------------------------------------------------------------------

    async def _wordlist_mutations(
        self, s: RequestStructure, wordlist: list[str]
    ) -> AsyncIterator[Mutation]:
        """
        Route wordlist entries through context transformation.

        Entries are not emitted as-is. They are classified against the
        request structure and emitted only where their role matches a
        discovered surface point.
        """
        has_path_ids = any(seg.role in (PathRole.ID_INT,) for seg in s.path_segments)
        has_query_ids = any(qp.role == ParamRole.ID for qp in s.query_params)

        for entry in wordlist:
            entry = entry.strip()
            if not entry or entry.startswith("#"):
                continue

            # Classify the wordlist entry
            entry_type = _infer_value_type(entry)

            # Emit as path segment where appropriate
            if not has_path_ids:
                yield Mutation(
                    location=MutationLocation.URL_PATH,
                    mutation_type=MutationType.PATH_WORDLIST,
                    mutated_value=urllib.parse.quote(entry, safe=""),
                    source="wordlist",
                )

            # Emit as query param on ID-typed params where entry type matches
            if has_query_ids:
                for qp in s.query_params:
                    if qp.role == ParamRole.ID and entry_type == qp.inferred_type:
                        yield Mutation(
                            location=MutationLocation.QUERY_PARAM,
                            mutation_type=MutationType.PARAM_WORDLIST,
                            mutated_value=entry,
                            parameter=qp.name,
                            original_value=qp.value,
                            source="wordlist",
                        )


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _classify_segment(seg: str) -> PathRole:
    if _INT_RE.match(seg):
        return PathRole.ID_INT
    if _UUID_RE.match(seg):
        return PathRole.ID_UUID
    if _HASH_RE.match(seg):
        return PathRole.ID_HASH
    if _VERSION_RE.match(seg):
        return PathRole.VERSION
    if "-" in seg and not seg.startswith("-"):
        return PathRole.ID_SLUG
    return PathRole.STATIC


def _classify_param(name: str) -> ParamRole:
    lname = name.lower().replace("-", "_")
    if lname in _ID_PARAM_NAMES or lname.endswith("_id"):
        return ParamRole.ID
    if lname in _AUTH_PARAM_NAMES:
        return ParamRole.AUTH
    if lname in _FILE_PARAM_NAMES:
        return ParamRole.FILE
    if lname in _PAGE_PARAM_NAMES:
        return ParamRole.PAGINATION
    return ParamRole.UNKNOWN


def _infer_value_type(value: str) -> str:
    if _INT_RE.match(value):
        return "int"
    if _UUID_RE.match(value):
        return "uuid"
    if _HASH_RE.match(value) and len(value) in (32, 40, 64):
        return "hash"
    if _BASE64_RE.match(value):
        return "base64"
    if value.lower() in ("true", "false"):
        return "bool"
    return "string"


def _infer_api_style(path: str, ct: str, body: str | None) -> APIStyle:
    if "graphql" in path.lower():
        return APIStyle.GRAPHQL
    if "json" in ct:
        return APIStyle.REST
    if "form" in ct:
        return APIStyle.FORM
    if body and body.strip().startswith("{"):
        return APIStyle.REST
    return APIStyle.UNKNOWN


# ---------------------------------------------------------------------------
# Value generators
# ---------------------------------------------------------------------------

def _adjacent_ints(n: int, depth: int) -> list[int]:
    result = []
    for delta in range(1, depth + 1):
        result += [n - delta, n + delta]
    return result


def _boundary_ints() -> list[int]:
    return [0, -1, 1, 2**31 - 1, 2**31, 2**32 - 1, 2**63 - 1, 99999999]


def _version_variants(current: str) -> list[str]:
    m = re.match(r"(v)(\d+)$", current, re.I)
    if not m:
        return []
    prefix, num = m.group(1), int(m.group(2))
    return [f"{prefix}{num + 1}", f"{prefix}{max(0, num - 1)}", f"{prefix}0"]


def _traversal_payloads() -> list[str]:
    return [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        "....//etc/passwd",
        "%252e%252e%252fetc%252fpasswd",
    ]
