# Scope & Coverage

DiffGate is diff-aware and deterministic. **How deeply it analyzes a change depends on the file's language.** JavaScript/TypeScript and Python get a real AST; other common languages are covered by comment-aware pattern rules; everything else is analyzed at the text level. This page states exactly where each tier applies so you can calibrate how much to trust a clean result.

---

## Language coverage

| Tier | Languages | What runs |
|------|-----------|-----------|
| **Deep (AST)** | JavaScript, TypeScript, JSX/TSX (`@babel`); Python (tree-sitter) | Real AST — [`@babel/parser`](https://www.npmjs.com/package/@babel/parser) for JS/TS, tree-sitter (WASM, no native build) for Python. Rules are structural: deprecated calls aren't matched inside comments or strings, exported-signature changes are detected by shape (JS/TS), and injection sinks are AST-precise. The Python `sql-injection` rule is **sink-targeted** (only flags a dynamic SQL string reaching `.execute`/`.executemany`/`.raw`/`text(...)`, not a `SELECT` in a log line), **parameter-aware** (`cur.execute("… %s", (uid,))` is safe), **static-clearing** (`f"… {TABLE}"` where `TABLE` is a constant is safe), and **sanitizer-aware** (`quote_ident`/`sql.Identifier` down-tier to review). On JS/TS, injection sinks also cover XSS, path traversal, and prototype pollution and are eligible for code-graph **taint confirmation**. |
| **Pattern (regex, comment-aware)** | Go, Java, Ruby, PHP, C/C++, C#, Rust, Kotlin, Swift, Scala, SQL, shell | Hardcoded secrets, schema/migration changes, auth/crypto-sensitive code, dynamic execution / shell-out, raw queries, outbound network calls, debug logging, TODO/FIXME. Commented-out code (`# os.system(x)`) isn't flagged; a secret committed *inside* a comment still is. Injection sinks run here too: a broad **advisory** `sql-injection-candidate` rule catches the idiomatic non-AST vectors (PHP `.`-concat & `"…$var…"`, Ruby `#{}`) and `dangerous-exec` covers Go `exec.Command`, Ruby `system`/`%x{}`, etc. Those advisories **escalate to blocking when CodeGraph confirms reachability from an HTTP/event handler** (see below). |
| **Text-only** | YAML, Terraform, JSON, and any other text | Hardcoded secrets and TODO/FIXME markers. |

The deterministic core is the **trustworthy floor**, not an exhaustive guarantee. On AST languages, an injection finding is AST-precise. On pattern/text languages, treat injection findings as a strong signal and clean results as "nothing matched the patterns," not "proven safe."

### Reachability (community CodeGraph)

The non-JS injection advisories are deliberately broad — broad regex is recall, not precision, so on its own a candidate **never blocks**. Precision comes from the graph: when an optional [CodeGraph](CODE-GRAPH.md) index is present, DiffGate walks the (deterministic, AST-derived) call graph from the sink back toward **untrusted entry points** — HTTP/event handlers that the framework exposes. If a path exists, the finding **escalates to a blocking orange** with the entry point named (`GET /user → …`) and is labelled `trust: "reachable"`. If no path exists it stays advisory and is labelled `trust: "unreachable"` ("verify before dismissing — coverage depends on the index"); it is **never auto-cleared** unless you opt in with `graph.reachabilityDeescalate: true`. No graph, or a graph that can't answer, leaves the advisory exactly as it was — the gate behavior with no code graph is unchanged. This needs only the **community** CodeGraph edition (no Pro taint engine).

**Raising coverage for your stack:** add project-specific rules via `customPatterns` / `orangePatterns` in `.diffgate.json` — these apply to any language. See [CONFIG.md](CONFIG.md).

---

## What the code graph does — and doesn't

The optional code graph ([CODE-GRAPH.md](CODE-GRAPH.md)) is a **precision layer, not a recall layer.** When configured, it operates on the findings the base rules already produced and makes them more trustworthy and better-prioritized:

- attaches cross-file **blast radius** — caller counts, suggested reviewers, untested call sites — and adjusts tier accordingly;
- **reachability** (community edition): escalates a broad cross-language injection advisory to a blocking finding when the call graph proves the sink is reachable from an untrusted entry point — the community-tier precision source;
- **taint analysis** (Pro): *confirms* a real source → sink path on injection findings (kept, with the data-flow trace) or *proves* none exists (down-tiered only if you opt in with `graph.securityDeescalate: true`).

**It does not add new detections.** If a base rule doesn't flag a sink, enabling the graph won't flag it either — there is nothing for the graph to escalate. Raising recall (e.g. catching more non-JS injection forms) is a **rule-layer** change — which is exactly what `sql-injection-candidate` is. The split is deliberate: rules buy recall, the graph buys the right to block. The graph is off by default and degrades to a complete no-op when absent.

---

## Design intent

DiffGate is intentionally a **low-noise, diff-scoped second pair of eyes** — not a whole-repo SAST. It is tuned to the residue modern coding agents actually ship (see [MEASUREMENT.md](MEASUREMENT.md)) rather than to maximize raw rule count. If you need exhaustive multi-language taint analysis across an entire codebase, pair DiffGate with a dedicated SAST tool; DiffGate's job is the fast, deterministic gate on the lines that just changed.
