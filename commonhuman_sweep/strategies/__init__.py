# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Strategy registry and public exports for commonhuman-sweep."""

from commonhuman_sweep.strategies.base_strategy import BaseStrategy, StrategyResult
from commonhuman_sweep.strategies.smart_fuzz_strategy import SmartFuzzStrategy
from commonhuman_sweep.strategies.api_surface_strategy import APISurfaceStrategy
from commonhuman_sweep.strategies.auth_boundary_strategy import AuthBoundaryStrategy
from commonhuman_sweep.strategies.wordlist_strategy import WordlistStrategy

REGISTRY: dict[str, type[BaseStrategy]] = {
    "smart":    SmartFuzzStrategy,
    "api":      APISurfaceStrategy,
    "auth":     AuthBoundaryStrategy,
    "wordlist": WordlistStrategy,
}


def get_strategy(name: str) -> type[BaseStrategy]:
    """Return the strategy class for the given name, raising ValueError if unknown."""
    try:
        return REGISTRY[name.lower()]
    except KeyError:
        raise ValueError(
            f"Unknown strategy '{name}'. Available: {', '.join(REGISTRY)}"
        ) from None


__all__ = [
    "BaseStrategy",
    "StrategyResult",
    "SmartFuzzStrategy",
    "APISurfaceStrategy",
    "AuthBoundaryStrategy",
    "WordlistStrategy",
    "REGISTRY",
    "get_strategy",
]
