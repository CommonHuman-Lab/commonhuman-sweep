# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
commonhuman-sweep — shared surface exploration and request mutation library.

Foundation package for the CommonHuman-Lab scanner tools (StingXSS, BreachSQL,
PhaseAccess, VaultRip). Provides:

  - Context-aware request mutation engine
  - Response intelligence (entropy, fingerprinting, anomaly detection, similarity)
  - Async event bus and scan orchestration
  - Pluggable scan strategies (smart, api, auth, wordlist)
  - Shared event/signal models used as the scanner tool communication contract
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
