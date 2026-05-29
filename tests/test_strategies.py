# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for strategy registry and wordlist strategy behaviour."""

from __future__ import annotations

import pytest

from commonhuman_sweep.strategies import (
    APISurfaceStrategy,
    AuthBoundaryStrategy,
    REGISTRY,
    SmartFuzzStrategy,
    WordlistStrategy,
    get_strategy,
)
from commonhuman_sweep.strategies.wordlist_strategy import WordlistStrategy


class TestRegistry:
    def test_all_expected_strategies_registered(self):
        assert "smart"    in REGISTRY
        assert "api"      in REGISTRY
        assert "auth"     in REGISTRY
        assert "wordlist" in REGISTRY

    def test_no_competitor_names_in_registry(self):
        for key in REGISTRY:
            assert "ffuf" not in key.lower()

    def test_get_strategy_returns_correct_class(self):
        assert get_strategy("smart")    is SmartFuzzStrategy
        assert get_strategy("api")      is APISurfaceStrategy
        assert get_strategy("auth")     is AuthBoundaryStrategy
        assert get_strategy("wordlist") is WordlistStrategy

    def test_get_strategy_case_insensitive(self):
        assert get_strategy("SMART") is SmartFuzzStrategy
        assert get_strategy("Smart") is SmartFuzzStrategy

    def test_get_strategy_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown strategy"):
            get_strategy("nonexistent")

    def test_get_strategy_error_lists_available(self):
        with pytest.raises(ValueError, match="smart"):
            get_strategy("bogus")

    def test_all_strategies_have_name_and_description(self):
        for key, cls in REGISTRY.items():
            instance = cls()
            assert isinstance(instance.name, str) and instance.name
            assert isinstance(instance.description, str) and instance.description

    def test_strategy_name_matches_registry_key(self):
        for key, cls in REGISTRY.items():
            assert cls().name == key


class TestWordlistStrategy:
    def test_name_and_description_no_competitor_mention(self):
        s = WordlistStrategy()
        assert "ffuf" not in s.name.lower()
        assert "ffuf" not in s.description.lower()

    def test_load_wordlist_returns_none_for_empty_path(self):
        s = WordlistStrategy()
        assert s._load_wordlist("") is None

    def test_load_wordlist_returns_none_for_missing_file(self):
        s = WordlistStrategy()
        assert s._load_wordlist("/tmp/this_file_does_not_exist_sweep.txt") is None

    def test_load_wordlist_reads_entries(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("admin\nlogin\nconfig\n# comment\n\n")
        s = WordlistStrategy()
        result = s._load_wordlist(str(wl))
        assert result is not None
        assert "admin" in result
        assert "login" in result
        assert "config" in result

    def test_load_wordlist_skips_comments_and_blanks(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("# comment\n\nadmin\n")
        s = WordlistStrategy()
        result = s._load_wordlist(str(wl))
        assert result == ["admin"]

    def test_load_wordlist_sorted_shortest_first(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("administrator\napi\nlogin\n")
        s = WordlistStrategy()
        result = s._load_wordlist(str(wl))
        assert result[0] == "api"
        assert result[-1] == "administrator"
