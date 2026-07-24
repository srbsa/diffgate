# Cross-file blast radius (code graph)

Most reviewers face a false tradeoff: index the whole repo for cross-file context and you catch breaking changes *but get noisier*; stay diff-scoped and you're quiet *but miss the call sites*. DiffGate resolves it because tiers **route attention instead of emitting comments**, so cross-file context makes the review *quieter and more complete at once*.

Zero setup by default. DiffGate ships a **built-in** call graph (`graph.provider: "builtin"`, tree-sitter + Babel, in-process) that requires no external binary and no index step — it parses the repo and builds the call graph on the fly, briefly cached in a long-lived host like the MCP server. An external, more powerful graph ([codegraph-ai/CodeGraph](https://github.com/codegraph-ai/CodeGraph), Apache-2.0) remains available as an opt-in upgrade (`graph.provider: "codegraph"`) for cross-repo impact, richer resolution, and the ~40-tool agent/IDE ecosystem.

---

## What it does

The impact pass enriches public-surface findings (`public-api-change`, `signature-drift`, `deprecated-api` — currently JS/TS only, since those are the only rules that emit a symbol) and adjusts their tier:

| Situation | What DiffGate does |
|-----------|--------------------|
| Public change **with callers** | Stays 🟠, message names the caller count, **suggested reviewers**, **untested** call sites, plus complexity and stale-doc flags (`tierAdjusted: escalated`) |
| Public change **nobody calls** | De-escalates 🟠 → 🟡 and **stops blocking the gate** (`tierAdjusted: deescalated`) |
| Bare name matched to >1 definition in the repo | Enrich-only — the count is shown but never drives the tier (`impact.ambiguous: true`); the builtin graph matches callers by bare identifier name, so two unrelated classes with the same method name can't be told apart without type information |
| No graph available (`graph.enabled: false`) | Complete no-op; same behavior as before, no cost |

---

## Builtin vs CodeGraph

| | `builtin` (default) | `codegraph` (opt-in) |
|---|---|---|
| Setup | None — in-process | Install the binary, run `diffgate graph index` |
| Coverage | JS/TS (Babel) + Python/Go/Java/Kotlin/Ruby/PHP/C# (tree-sitter), bare-name matching, single repo | Same languages plus proper symbol resolution, cross-repo consumers, Pro taint analysis |
| Freshness | Rebuilt from source each run (briefly cached for a resident host) | Kept fresh by CodeGraph's own daemon/filesystem watch |
| `diffgate graph index` | No-op (forces an immediate in-process rebuild) | Builds/refreshes the external index |

Switch providers in `.diffgate.json`:

```jsonc
"graph": { "provider": "codegraph", "command": "codegraph-server" }
```

## How it sources impact

One `pr_context` call per review covers the whole diff (callers, test gaps, reviewers, stale docs, complexity). Symbols it doesn't cover, or any time it's unavailable, fall back to a per-finding `analyze_impact` lookup, with `find_related_tests` supplying authoritative test-gap data. In the MCP loop, `diffgate_analyze` additionally attaches `get_edit_context` (callers/tests/recent history) to the highest-blast finding so an agent can fix the call sites before writing code.

Impact surfaces everywhere a finding does: the CLI report, GitHub PR annotations, SARIF `properties`, the MCP `diffgate_analyze` output (so coding agents see blast radius **before code is written to disk**), and the VS Code hover card.

---

## Setup

```bash
diffgate graph status   # which provider, and is it ready?
diffgate graph index    # builtin: force an immediate rebuild. codegraph: build the index (or print install instructions)
```

Under `provider: "codegraph"`, DiffGate auto-detects the index — the legacy `~/.codegraph/graph.db` or the newer per-project `~/.codegraph/projects/<slug>/` (CodeGraph ≥ 0.18). The graph indexes committed/disk state, so *who calls a changed symbol* is reliable. DiffGate **reads** the index via one-shot queries; the index itself is built and kept fresh by CodeGraph (its VS Code extension / daemon, or `diffgate graph index`). If reachability quietly returns no escalation, check `diffgate graph status` — a cold or partially-built index can't resolve a sink's callers (it degrades to advisory `unconfirmed`, never a false block). To never auto-de-escalate a rule, pin its tier:

```jsonc
"rules": { "signature-drift": { "tier": "orange" } }
```

---

## Does an external graph still earn its place as DiffGate adds per-language AST?

Yes — its value is **orthogonal** to AST precision, and concentrated. AST rules (`@babel` for JS/TS, tree-sitter for the rest) are *intra-procedural*: "is this sink dangerous as written, past local sanitizers/guards/static constants?" The graph is *inter-procedural*: "can untrusted input reach it across files, what's the blast radius, who reviews it, is it tested?" Neither subsumes the other — they compose. DiffGate uses a focused ~7 of community CodeGraph's ~40 tools on purpose (the rest are agent/IDE features: doc indexing, memory, architecture-doc generation, semantic search, cross-repo). The builtin provider covers the single-repo, in-process case the community tier needs; CodeGraph adds proper symbol resolution (no bare-name ambiguity) and cross-repo consumers.

## Reachability (community edition)

The blocking SQL-injection rule is AST-deep on JS/TS (`@babel`) and Python + PHP (tree-sitter); on the remaining languages DiffGate emits broad **advisory** findings (`sql-injection-candidate`, `raw-query`, `dangerous-exec`). Broad regex is recall, not precision, so those never block on their own. Reachability is the **community-tier precision source** that lets them earn a block — no Pro binary required. (For the AST-deep languages the finding already blocks on local evidence; reachability then only attaches the entry-point trace or, if the team opted in, de-escalates a proven-unreachable sink.)

For each such finding, DiffGate walks the call graph from the sink back toward **untrusted entry points**:

1. Detect the set of HTTP/event handlers the framework exposes (e.g. a Flask `@app.route`, a Sinatra `get '/x' do…end`, a Ktor/Laravel/minimal-API route closure — tagged `http_handler`). Fetched **once per review** and cached. (`find_entry_points` under `provider: "codegraph"`.)
2. Walk the sink's transitive callers, bounded by `reachabilityMaxDepth`. (`get_callers` / `traverse_graph` under `provider: "codegraph"`.) DSL-style routes with no separate named function (Sinatra/Ktor/Laravel/minimal-API closures, an inline Go handler) are matched by the handler body's own line span, not by name — a sink inside that span, or reached through a helper called from inside it, counts as reachable even though nothing calls a function literally named after the route.
3. If an untrusted entry point is in that ancestor set, the sink is **reachable**.

| Verdict | What DiffGate does | Trust label |
|---------|--------------------|-------------|
| **Reachable** from a handler | Escalates 🟡/advisory → blocking 🟠, names the entry point (`GET /user → …`) | `reachable` |
| **Unreachable** (handlers known, no path) | Left as-is by default; down-tiers **only** with `graph.reachabilityDeescalate: true` | `unreachable` |
| **Unknown** (no index / no handlers / query failed) | Untouched — never a false "unreachable" | `unconfirmed` |

**Fail-safe posture.** Any uncertainty returns "unknown", never "unreachable" — an incomplete index must never hide a real vulnerability. Default is escalate-can-block, **never auto-clear**. Untrusted roots are `http_handler` + `event_handler` by default (configurable via `graph.untrustedEntryKinds`); `cli_command` / `test` / `main` are not untrusted.

**Framework note.** Decorator routes (Flask `@app.route`) are inline and easy. Frameworks that register routes in separate files (Laravel/Symfony `routes/*.php`, Express router files) need those files in the index for `http_handler` tagging — otherwise the sink degrades to advisory `unconfirmed` (not a false `unreachable`). Keep route-registration files in your index scope. Index freshness matters: a stale index can make a reachable sink look unreachable, so `diffgate graph status` surfaces the index age.

Config keys: `graph.reachability` (`auto` | `true` | `false`), `reachabilityDeescalate`, `untrustedEntryKinds`, `reachabilityMaxDepth`, `reachabilityTimeoutMs` — see [CONFIG.md](CONFIG.md).

---

## Graph-aware security (optional, Pro — an enhancement on top of reachability)

Reachability above is the community floor. A CodeGraph **Pro** taint analysis is an optional precision *upgrade*, not a prerequisite: for injection-class findings it answers *does user input actually reach this sink?* with full data-flow, not just call-graph reachability. A confirmed taint path is attached (source → … → sink) and keeps the gate. A proven-clean sink de-escalates **only if you set `graph.securityDeescalate: true`**; enrich-only by default, because a false "no taint" must never silently hide a vulnerability. When a Pro verdict is present it **wins** over community reachability for that finding. (Validated against CodeGraph's documented contract, not a live Pro binary.)

The graph is a **precision layer, not a recall layer**: it escalates, confirms, or clears injection findings the base rules already produced — it does **not** add detections a rule missed. Raising recall is a rule-layer change. See [SCOPE.md](SCOPE.md).

---

## Deep Review

For orange findings, an agentic loop (grep, read_file, find_references, git_blame) investigates blast radius and returns a `confirmed-risk / likely-safe / needs-human` verdict. Available from the CLI (`--deep`) and the VS Code hover card.
