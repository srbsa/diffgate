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

DiffGate auto-detects the index (`~/.codegraph/graph.db`). The graph indexes committed/disk state, so *who calls a changed symbol* is reliable. To never auto-de-escalate a rule, pin its tier:

```jsonc
"rules": { "signature-drift": { "tier": "orange" } }
```

---

## Graph-aware security (optional, Pro)

For injection-class findings (`sql-injection`, `xss-sink`, `nosql-injection`, `path-traversal`, …) a CodeGraph Pro taint analysis answers *does user input actually reach this sink?* A confirmed taint path is attached (source → … → sink) and keeps the gate. A proven-clean sink de-escalates **only if you set `graph.securityDeescalate: true`**; enrich-only by default, because a false "no taint" must never silently hide a vulnerability. (Validated against CodeGraph's documented contract, not a live Pro binary.)

---

## Deep Review

For orange findings, an agentic loop (grep, read_file, find_references, git_blame) investigates blast radius and returns a `confirmed-risk / likely-safe / needs-human` verdict. Available from the CLI (`--deep`) and the VS Code hover card.
