# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for RequestBuilder — mutation application to SweepRequest objects."""

from __future__ import annotations

import json
import urllib.parse

import pytest

from commonhuman_sweep.engine.mutation_engine import Mutation, MutationLocation, MutationType
from commonhuman_sweep.engine.request_builder import RequestBuilder, _coerce, _set_nested
from commonhuman_sweep.models.context import AuthContext, SweepContext, SweepOptions


def _ctx(target: str = "http://example.com/api/users/1") -> SweepContext:
    return SweepContext(target=target, options=SweepOptions(crawl=False))


def _authed_ctx() -> SweepContext:
    auth = AuthContext.from_bearer("primary_token")
    auth.alt_credential = "Bearer alt_token"
    return SweepContext(
        target="http://example.com/profile",
        options=SweepOptions(crawl=False),
        auth=auth,
    )


class TestBuildBaseline:
    def test_url_and_method(self):
        builder = RequestBuilder(_ctx())
        req = builder.build_baseline("http://example.com/api/users/1")
        assert req.url == "http://example.com/api/users/1"
        assert req.method == "GET"

    def test_includes_base_headers(self):
        builder = RequestBuilder(_authed_ctx())
        req = builder.build_baseline("http://example.com/profile")
        assert "Authorization" in req.headers
        assert req.headers["Authorization"] == "Bearer primary_token"


class TestMutateQueryParam:
    def test_replaces_existing_param(self):
        builder = RequestBuilder(_ctx("http://example.com/search?id=1"))
        base = builder.build_baseline("http://example.com/search?id=1")
        m = Mutation(
            location=MutationLocation.QUERY_PARAM,
            mutation_type=MutationType.PARAM_INT_ADJACENT,
            mutated_value="99",
            parameter="id",
        )
        result = builder.apply(base, m)
        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(result.url).query)
        assert parsed["id"] == ["99"]

    def test_adds_new_param(self):
        builder = RequestBuilder(_ctx("http://example.com/items"))
        base = builder.build_baseline("http://example.com/items")
        m = Mutation(
            location=MutationLocation.QUERY_PARAM,
            mutation_type=MutationType.PARAM_INT_ADJACENT,
            mutated_value="5",
            parameter="page",
        )
        result = builder.apply(base, m)
        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(result.url).query)
        assert parsed["page"] == ["5"]

    def test_does_not_mutate_original(self):
        builder = RequestBuilder(_ctx("http://example.com/search?id=1"))
        base = builder.build_baseline("http://example.com/search?id=1")
        m = Mutation(
            location=MutationLocation.QUERY_PARAM,
            mutation_type=MutationType.PARAM_INT_ADJACENT,
            mutated_value="2",
            parameter="id",
        )
        result = builder.apply(base, m)
        assert base.url != result.url


class TestMutatePath:
    def test_replaces_segment_by_index(self):
        builder = RequestBuilder(_ctx("http://example.com/api/users/1"))
        base = builder.build_baseline("http://example.com/api/users/1")
        m = Mutation(
            location=MutationLocation.URL_PATH,
            mutation_type=MutationType.PATH_ID_ADJACENT,
            mutated_value="2",
            parameter="2",  # segment index
        )
        result = builder.apply(base, m)
        assert result.url.endswith("/2")

    def test_appends_segment_when_no_index(self):
        builder = RequestBuilder(_ctx("http://example.com/api/users"))
        base = builder.build_baseline("http://example.com/api/users")
        m = Mutation(
            location=MutationLocation.URL_PATH,
            mutation_type=MutationType.PATH_WORDLIST,
            mutated_value="admin",
            parameter="",
        )
        result = builder.apply(base, m)
        assert "/admin" in result.url


class TestMutateHeader:
    def test_adds_header(self):
        builder = RequestBuilder(_ctx())
        base = builder.build_baseline("http://example.com/")
        m = Mutation(
            location=MutationLocation.HEADER,
            mutation_type=MutationType.HEADER_IP_SPOOF,
            mutated_value="127.0.0.1",
            parameter="X-Forwarded-For",
        )
        result = builder.apply(base, m)
        assert result.headers["X-Forwarded-For"] == "127.0.0.1"

    def test_strip_auth_removes_authorization(self):
        builder = RequestBuilder(_authed_ctx())
        base = builder.build_baseline("http://example.com/profile")
        m = Mutation(
            location=MutationLocation.HEADER,
            mutation_type=MutationType.HEADER_AUTH_STRIP,
            mutated_value="",
            parameter="_REMOVE_AUTH_",
        )
        result = builder.apply(base, m)
        assert "Authorization" not in result.headers


class TestMutateBody:
    def test_injects_new_field(self):
        builder = RequestBuilder(_ctx("http://example.com/users"))
        base = builder.build_baseline("http://example.com/users")
        base = base.__class__(method="POST", url=base.url, headers=base.headers,
                              body='{"name": "alice"}')
        m = Mutation(
            location=MutationLocation.BODY_FIELD,
            mutation_type=MutationType.BODY_PRIVILEGE_ESCALATE,
            mutated_value="true",
            parameter="admin",
        )
        result = builder.apply(base, m)
        doc = json.loads(result.body)
        assert doc["admin"] is True
        assert doc["name"] == "alice"

    def test_handles_empty_body(self):
        builder = RequestBuilder(_ctx())
        base = builder.build_baseline("http://example.com/")
        m = Mutation(
            location=MutationLocation.BODY_FIELD,
            mutation_type=MutationType.BODY_PRIVILEGE_ESCALATE,
            mutated_value="true",
            parameter="admin",
        )
        result = builder.apply(base, m)
        doc = json.loads(result.body)
        assert doc["admin"] is True


class TestMutateAuth:
    def test_strip_auth(self):
        builder = RequestBuilder(_authed_ctx())
        base = builder.build_baseline("http://example.com/profile")
        m = Mutation(
            location=MutationLocation.AUTH_CONTEXT,
            mutation_type=MutationType.AUTH_STRIP,
            mutated_value="__STRIP__",
            parameter="_REMOVE_AUTH_",
        )
        result = builder.apply(base, m)
        assert "Authorization" not in result.headers

    def test_swap_auth_uses_alt_credential(self):
        builder = RequestBuilder(_authed_ctx())
        base = builder.build_baseline("http://example.com/profile")
        m = Mutation(
            location=MutationLocation.AUTH_CONTEXT,
            mutation_type=MutationType.AUTH_SWAP,
            mutated_value="__ALT__",
            parameter="_SWAP_AUTH_",
        )
        result = builder.apply(base, m)
        assert result.headers["Authorization"] == "Bearer alt_token"


class TestBuildVerbVariants:
    def test_returns_all_common_verbs(self):
        builder = RequestBuilder(_ctx())
        variants = builder.build_verb_variants("http://example.com/api/item/1")
        methods = {r.method for r in variants}
        assert {"GET", "POST", "PUT", "DELETE", "PATCH"}.issubset(methods)

    def test_all_same_url(self):
        builder = RequestBuilder(_ctx())
        variants = builder.build_verb_variants("http://example.com/api/item/1")
        assert all(r.url == "http://example.com/api/item/1" for r in variants)


class TestHelpers:
    def test_coerce_null(self):
        assert _coerce("null") is None

    def test_coerce_bool(self):
        assert _coerce("true") is True
        assert _coerce("false") is False

    def test_coerce_int(self):
        assert _coerce("42") == 42

    def test_coerce_string_passthrough(self):
        assert _coerce("hello") == "hello"

    def test_set_nested_simple(self):
        doc = {}
        _set_nested(doc, "name", "alice")
        assert doc["name"] == "alice"

    def test_set_nested_deep(self):
        doc = {}
        _set_nested(doc, "user.role", "admin")
        assert doc["user"]["role"] == "admin"
