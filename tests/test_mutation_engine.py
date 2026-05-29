# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for MutationEngine — structural analysis and mutation generation."""

from __future__ import annotations

import pytest

from commonhuman_sweep.engine.mutation_engine import (
    APIStyle,
    MutationEngine,
    MutationLocation,
    MutationType,
    ParamRole,
    PathRole,
    _adjacent_ints,
    _boundary_ints,
    _classify_param,
    _classify_segment,
    _infer_value_type,
    _version_variants,
)


class TestSegmentClassification:
    def test_integer_id(self):
        assert _classify_segment("123") == PathRole.ID_INT

    def test_uuid(self):
        assert _classify_segment("550e8400-e29b-41d4-a716-446655440000") == PathRole.ID_UUID

    def test_version(self):
        assert _classify_segment("v1") == PathRole.VERSION
        assert _classify_segment("V2") == PathRole.VERSION

    def test_slug(self):
        assert _classify_segment("my-post-title") == PathRole.ID_SLUG

    def test_hash_md5(self):
        assert _classify_segment("d41d8cd98f00b204e9800998ecf8427e") == PathRole.ID_HASH

    def test_static(self):
        assert _classify_segment("api") == PathRole.STATIC
        assert _classify_segment("users") == PathRole.STATIC


class TestParamClassification:
    def test_id_names(self):
        assert _classify_param("id") == ParamRole.ID
        assert _classify_param("user_id") == ParamRole.ID
        assert _classify_param("uid") == ParamRole.ID

    def test_auth_names(self):
        assert _classify_param("token") == ParamRole.AUTH
        assert _classify_param("api_key") == ParamRole.AUTH

    def test_file_names(self):
        assert _classify_param("file") == ParamRole.FILE
        assert _classify_param("filename") == ParamRole.FILE

    def test_pagination(self):
        assert _classify_param("page") == ParamRole.PAGINATION
        assert _classify_param("limit") == ParamRole.PAGINATION

    def test_unknown(self):
        assert _classify_param("search") == ParamRole.UNKNOWN
        assert _classify_param("format") == ParamRole.UNKNOWN


class TestValueTypeInference:
    def test_integer(self):
        assert _infer_value_type("42") == "int"
        assert _infer_value_type("0") == "int"

    def test_uuid(self):
        assert _infer_value_type("550e8400-e29b-41d4-a716-446655440000") == "uuid"

    def test_boolean(self):
        assert _infer_value_type("true") == "bool"
        assert _infer_value_type("false") == "bool"

    def test_string_fallback(self):
        assert _infer_value_type("hello") == "string"
        assert _infer_value_type("foo-bar") == "string"


class TestValueGenerators:
    def test_adjacent_ints_count(self):
        result = _adjacent_ints(10, depth=2)
        assert 8 in result
        assert 9 in result
        assert 11 in result
        assert 12 in result
        assert len(result) == 4

    def test_adjacent_ints_includes_neighbours(self):
        result = _adjacent_ints(5, depth=1)
        assert 4 in result
        assert 6 in result

    def test_boundary_ints_includes_zero_and_negative(self):
        bounds = _boundary_ints()
        assert 0 in bounds
        assert -1 in bounds

    def test_version_variants(self):
        variants = _version_variants("v1")
        assert "v2" in variants
        assert "v0" in variants


class TestAnalyse:
    engine = MutationEngine()

    def test_path_segments_detected(self):
        s = self.engine.analyse("http://example.com/api/users/123")
        segs = {seg.raw: seg.role for seg in s.path_segments}
        assert segs["api"] == PathRole.STATIC
        assert segs["users"] == PathRole.STATIC
        assert segs["123"] == PathRole.ID_INT

    def test_query_param_detected(self):
        s = self.engine.analyse("http://example.com/search?id=42&format=json")
        params = {p.name: p for p in s.query_params}
        assert params["id"].role == ParamRole.ID
        assert params["id"].inferred_type == "int"
        assert params["format"].role == ParamRole.UNKNOWN

    def test_api_style_rest_from_json_body(self):
        s = self.engine.analyse(
            "http://example.com/api/items",
            method="POST",
            body='{"name": "test"}',
            headers={"Content-Type": "application/json"},
        )
        assert s.api_style == APIStyle.REST

    def test_api_style_graphql_from_path(self):
        s = self.engine.analyse("http://example.com/graphql")
        assert s.api_style == APIStyle.GRAPHQL

    def test_body_fields_extracted(self):
        s = self.engine.analyse(
            "http://example.com/users",
            method="POST",
            body='{"username": "alice", "role": "user"}',
        )
        assert "username" in s.body_fields
        assert "role" in s.body_fields

    def test_auth_detected_from_header(self):
        s = self.engine.analyse(
            "http://example.com/profile",
            headers={"Authorization": "Bearer tok"},
        )
        assert s.has_auth is True

    def test_no_auth(self):
        s = self.engine.analyse("http://example.com/public")
        assert s.has_auth is False


@pytest.mark.asyncio
class TestGenerate:
    engine = MutationEngine()

    async def _collect(self, url, **kwargs):
        structure = self.engine.analyse(url, **kwargs)
        return [m async for m in self.engine.generate(structure, depth=1)]

    async def test_id_path_produces_adjacent_mutations(self):
        mutations = await self._collect("http://example.com/api/users/5")
        path_adj = [m for m in mutations
                    if m.mutation_type == MutationType.PATH_ID_ADJACENT]
        assert len(path_adj) >= 2
        values = {m.mutated_value for m in path_adj}
        assert "4" in values
        assert "6" in values

    async def test_id_path_produces_boundary_mutations(self):
        mutations = await self._collect("http://example.com/api/users/5")
        boundary = [m for m in mutations
                    if m.mutation_type == MutationType.PATH_ID_BOUNDARY]
        assert len(boundary) > 0
        values = {m.mutated_value for m in boundary}
        assert "0" in values
        assert "-1" in values

    async def test_id_path_produces_type_confusion(self):
        mutations = await self._collect("http://example.com/api/users/5")
        tc = [m for m in mutations
              if m.mutation_type == MutationType.PATH_ID_TYPE_CONFUSION]
        assert len(tc) > 0

    async def test_traversal_mutations_present(self):
        mutations = await self._collect("http://example.com/api/users/5")
        trav = [m for m in mutations if m.mutation_type == MutationType.PATH_TRAVERSAL]
        assert len(trav) > 0

    async def test_inject_probe_on_query_param(self):
        mutations = await self._collect("http://example.com/search?id=1")
        probes = [m for m in mutations
                  if m.mutation_type == MutationType.PARAM_INJECT_PROBE
                  and m.parameter == "id"]
        assert len(probes) > 0

    async def test_privilege_escalation_in_body(self):
        mutations = await self._collect(
            "http://example.com/users",
            method="POST",
            body='{"name": "alice"}',
            headers={"Content-Type": "application/json"},
        )
        priv = [m for m in mutations
                if m.mutation_type == MutationType.BODY_PRIVILEGE_ESCALATE]
        assert len(priv) > 0
        field_names = {m.parameter for m in priv}
        assert "admin" in field_names or "role" in field_names

    async def test_auth_strip_when_auth_present(self):
        mutations = await self._collect(
            "http://example.com/profile",
            headers={"Authorization": "Bearer tok"},
        )
        strip = [m for m in mutations if m.mutation_type == MutationType.AUTH_STRIP]
        assert len(strip) == 1

    async def test_no_auth_strip_without_auth(self):
        mutations = await self._collect("http://example.com/public")
        strip = [m for m in mutations if m.mutation_type == MutationType.AUTH_STRIP]
        assert len(strip) == 0

    async def test_no_duplicates(self):
        mutations = await self._collect("http://example.com/api/users/10")
        keys = [(m.location, m.parameter, m.mutated_value) for m in mutations]
        assert len(keys) == len(set(keys)), "Duplicate mutations generated"

    async def test_wordlist_path_mutations(self):
        structure = self.engine.analyse("http://example.com/")
        wordlist = ["admin", "login", "config"]
        mutations = [m async for m in self.engine.generate(structure, wordlist=wordlist)]
        wl = [m for m in mutations if m.source == "wordlist"]
        assert len(wl) >= 3
        wl_values = {m.mutated_value for m in wl}
        assert "admin" in wl_values

    async def test_harvested_ids_used_for_param(self):
        structure = self.engine.analyse("http://example.com/item?id=1")
        harvested = {"int": ["99", "100"]}
        mutations = [m async for m in self.engine.generate(
            structure, harvested_ids=harvested, depth=1
        )]
        harvested_mutations = [m for m in mutations if m.source == "harvested"]
        assert any(m.mutated_value == "99" for m in harvested_mutations)
