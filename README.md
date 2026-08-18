# commonhuman-sweep

Shared surface exploration and request mutation library for the CommonHuman-Lab scanner tools.

`commonhuman-sweep` is a **foundation package** — it has no CLI of its own. Scanner tools (StingXSS, BreachSQL, PhaseAccess, VaultRip) import it as a library and use its capabilities inside their own pipelines.

---

## What it provides

### Mutation engine

Context-aware HTTP request mutation. Analyses the structure of a URL, body, and headers to infer parameter roles (integer ID, UUID, file path, auth token…), then generates semantically appropriate mutations — adjacent IDs, boundary values, type confusion, path traversal, mass-assignment probes, auth-strip/swap. Wordlists are an optional input source, transformed through the context model rather than iterated raw.

### Response intelligence

- **ResponseClassifier** — Shannon entropy, structural fingerprinting, signal extraction (SQLi errors, stack traces, XSS reflection, IDOR patterns, mass-assignment fields, API schema exposure)
- **SimilarityEngine** — response clustering via weighted Jaccard + fingerprint comparison; `diff()` gives a structured change summary
- **AnomalyDetector** — statistical baseline per URL pattern (normalised to strip ID tokens); scores deviations in status, length, timing, and fingerprint

### Event system

Async pub/sub bus (`EventRouter`) with named, filter-predicate handlers and fan-out delivery. Handler failures are isolated — one broken handler never drops events to others. `FuzzOrchestrator` wires a strategy to the router and collects a `SweepResult`.

### Pluggable strategies

| Key        | Class                  | Purpose                                                  |
| ---------- | ---------------------- | -------------------------------------------------------- |
| `smart`    | `SmartFuzzStrategy`    | Crawl, baseline, structural mutation, anomaly filter     |
| `api`      | `APISurfaceStrategy`   | OpenAPI/GraphQL discovery and HTTP verb coverage         |
| `auth`     | `AuthBoundaryStrategy` | Auth-strip, dual-session IDOR, harvested-ID probing      |
| `wordlist` | `WordlistStrategy`     | Wordlist-sourced exploration with intelligence filtering |

---

## How scanner tools use it

```python
from commonhuman_sweep.models import SweepContext, SweepOptions, Signal
from commonhuman_sweep.pipeline import EventHandler, FuzzOrchestrator
from commonhuman_sweep.strategies import get_strategy

ctx = SweepContext(
    target="https://target.example/api/users/1",
    options=SweepOptions(crawl=False, concurrency=10),
)

async def on_idor_signal(event):
    # hand off to PhaseAccess for confirmation
    ...

strategy = get_strategy("auth")()
orchestrator = FuzzOrchestrator(ctx, strategy)
orchestrator.register_handler(EventHandler(
    "phaseaccess",
    on_idor_signal,
    filter=lambda e: e.has_signal(Signal.POSSIBLE_IDOR),
))
result = await orchestrator.run()
```

### Using the mutation engine directly

```python
from commonhuman_sweep.engine import MutationEngine, RequestBuilder

engine  = MutationEngine()
builder = RequestBuilder(ctx)

structure = engine.analyse("https://target.example/api/users/42?format=json")
async for mutation in engine.generate(structure, depth=2):
    request = builder.apply(builder.build_baseline(ctx.target), mutation)
    # fire with your own HTTP client
```

### Event output contract

`SweepEvent` is the stable output schema consumed by downstream tools:

```json
{
    "event":      "sweep_result",
    "target":     "https://target.example",
    "request":    {"method": "GET", "url": "...", "headers": {}, "body": null},
    "response":   {"status": 200, "length": 312, "entropy_score": 0.61, "fingerprint": "a3f1c9"},
    "signals":    ["possible_idor", "interesting_response"],
    "confidence": "medium",
    "strategy":   "auth",
    "mutation":   "path_id_adjacent",
    "parameter":  "2",
    "timestamp":  1748000000.0
}
```

---

## Dependencies

| Package          | Role                                          |
| ---------------- | --------------------------------------------- |
| `commonhuman-core` | Crawling and HTTP client used by strategies |
| `httpx[http2]`   | Async HTTP execution in `ExecutionLayer`      |

---

## Development

```bash
# Install in editable mode
uv pip install -e . --python /path/to/.venv/bin/python

# Run tests (no live targets — all HTTP is mocked)
pytest tests/
```

### Test layout

```text
tests/
├── conftest.py              # network guard + shared fixtures
├── test_models.py           # SweepEvent, SweepResponse, AuthContext, SweepOptions
├── test_mutation_engine.py  # analyse(), generate(), classification helpers
├── test_request_builder.py  # apply() for all 5 mutation locations
├── test_intelligence.py     # classifier, similarity engine, anomaly detector
├── test_event_router.py     # pub/sub fan-out, filters, handler isolation
└── test_strategies.py       # registry, WordlistStrategy loading
```

The `_block_real_http` autouse fixture patches `httpx.AsyncClient.send` for every test. Any test that reaches live HTTP raises `RuntimeError` immediately.

---

## License

Licensed under the [AGPLv3](LICENSE).
You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.