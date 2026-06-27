# Cross-file blast radius (optional code graph)

Most reviewers face a false tradeoff: index the whole repo for cross-file context and you catch breaking changes *but get noisier*; stay diff-scoped and you're quiet *but miss the call sites*. DiffGate resolves it because tiers **route attention instead of emitting comments**, so cross-file context makes the review *quieter and more complete at once*.

Fully optional and graceful: a complete no-op when no graph is present.

---

## What it does

When an optional code graph ([codegraph-ai/CodeGraph](https://github.com/codegraph-ai/CodeGraph), Apache-2.0) is present, the impact pass enriches public-surface findings (`public-api-change`, `signature-drift`, `deprecated-api`) and adjusts their tier:

| Situation | What DiffGate does |
|-----------|--------------------|
| Public change **with callers** | Stays 🟠, message names the caller count, **suggested reviewers**, **untested** call sites, plus complexity and stale-doc flags (`tierAdjusted: escalated`) |
| Public change **nobody calls** | De-escalates 🟠 → 🟡 and **stops blocking the gate** (`tierAdjusted: deescalated`) |
| No graph available | Complete no-op; same behavior as before, no subprocess cost |

---

## How it sources impact

One `pr_context` call per review covers the whole diff (callers, test gaps, reviewers, stale docs, complexity). Symbols it doesn't cover, or any time it's unavailable, fall back to a per-finding `analyze_impact` lookup, with `find_related_tests` supplying authoritative test-gap data. In the MCP loop, `diffgate_analyze` additionally attaches `get_edit_context` (callers/tests/recent history) to the highest-blast finding so an agent can fix the call sites before writing code.

Impact surfaces everywhere a finding does: the CLI report, GitHub PR annotations, SARIF `properties`, the MCP `diffgate_analyze` output (so coding agents see blast radius **before code is written to disk**), and the VS Code hover card.

---

## Setup

```bash
diffgate graph status   # is the code graph enabled / installed / indexed?
diffgate graph index    # build the cross-file index (or prints install instructions)
```

DiffGate auto-detects the index — the legacy `~/.codegraph/graph.db` or the newer per-project `~/.codegraph/projects/<slug>/` (CodeGraph ≥ 0.18). The graph indexes committed/disk state, so *who calls a changed symbol* is reliable. DiffGate **reads** the index via one-shot queries; the index itself is built and kept fresh by CodeGraph (its VS Code extension / daemon, or `diffgate graph index`). If reachability quietly returns no escalation, check `diffgate graph status` — a cold or partially-built index can't resolve a sink's callers (it degrades to advisory `unconfirmed`, never a false block). To never auto-de-escalate a rule, pin its tier:

```jsonc
"rules": { "signature-drift": { "tier": "orange" } }
```

---

## Does the graph still earn its place as DiffGate adds per-language AST?

Yes — its value is **orthogonal** to AST precision, and concentrated. AST rules (`@babel` for JS/TS, tree-sitter for Python) are *intra-procedural*: "is this sink dangerous as written, past local sanitizers/guards/static constants?" The graph is *inter-procedural*: "can untrusted input reach it across files, what's the blast radius, who reviews it, is it tested?" Neither subsumes the other — they compose. DiffGate uses a focused ~7 of community CodeGraph's ~40 tools on purpose (the rest are agent/IDE features: doc indexing, memory, architecture-doc generation, semantic search). As AST precision lands language-by-language, the graph's role shifts from *the* justification to block a noisy regex → *reachability refinement + the language-agnostic blast-radius/cross-repo/reviewers/test-gap layer* ([src/core/impact.ts](src/core/impact.ts)) — strongest on web-server code, lighter on CLI/data/ML repos that have no HTTP entry points.

## Reachability (community edition)

The blocking SQL-injection rule is AST-deep on JS/TS (`@babel`) and Python (tree-sitter); on the remaining languages DiffGate emits broad **advisory** findings (`sql-injection-candidate`, `raw-query`, `dangerous-exec`). Broad regex is recall, not precision, so those never block on their own. Reachability is the **community-tier precision source** that lets them earn a block — no Pro binary required. (For the AST-deep languages the finding already blocks on local evidence; reachability then only attaches the entry-point trace or, if the team opted in, de-escalates a proven-unreachable sink.)

For each such finding, DiffGate walks the call graph from the sink back toward **untrusted entry points**:

1. `find_entry_points` → the set of HTTP/event handlers the framework exposes (e.g. a Flask `@app.route` is tagged `http_handler`). Fetched **once per review** and cached.
2. `get_callers` / `traverse_graph` (incoming `calls`, bounded by `reachabilityMaxDepth`) → the sink's transitive callers.
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
