# Scope & Coverage

DiffGate is diff-aware and deterministic. **How deeply it analyzes a change depends on the file's language.** JavaScript/TypeScript get a real AST; other common languages are covered by comment-aware pattern rules; everything else is analyzed at the text level. This page states exactly where each tier applies so you can calibrate how much to trust a clean result.

---

## Language coverage

| Tier | Languages | What runs |
|------|-----------|-----------|
| **Deep (AST)** | JavaScript, TypeScript, JSX/TSX | Real [`@babel/parser`](https://www.npmjs.com/package/@babel/parser) AST. Rules are structural: deprecated calls aren't matched inside comments or strings, exported-signature changes are detected by shape, and injection sinks (SQL injection, XSS, path traversal, prototype pollution) are AST-precise and eligible for code-graph **taint confirmation**. |
| **Pattern (regex, comment-aware)** | Python, Go, Java, Ruby, PHP, C/C++, C#, Rust, Kotlin, Swift, Scala, SQL, shell | Hardcoded secrets, schema/migration changes, auth/crypto-sensitive code, dynamic execution / shell-out, raw queries, outbound network calls, debug logging, TODO/FIXME. Commented-out code (`# os.system(x)`) isn't flagged; a secret committed *inside* a comment still is. Injection-sink rules also run here, but the patterns are **tuned for JavaScript/TypeScript idioms** — they catch common string-concatenation forms and may not flag every language-specific variant. |
| **Text-only** | YAML, Terraform, JSON, and any other text | Hardcoded secrets and TODO/FIXME markers. |

The deterministic core is the **trustworthy floor**, not an exhaustive guarantee. On AST languages, an injection finding is AST-precise. On pattern/text languages, treat injection findings as a strong signal and clean results as "nothing matched the patterns," not "proven safe."

**Raising coverage for your stack:** add project-specific rules via `customPatterns` / `orangePatterns` in `.diffgate.json` — these apply to any language. See [CONFIG.md](CONFIG.md).

---

## What the code graph does — and doesn't

The optional code graph ([CODE-GRAPH.md](CODE-GRAPH.md)) is a **precision layer, not a recall layer.** When configured, it operates on the findings the base rules already produced and makes them more trustworthy and better-prioritized:

- attaches cross-file **blast radius** — caller counts, suggested reviewers, untested call sites — and adjusts tier accordingly;
- runs **taint analysis** on injection findings to *confirm* a real source → sink path (kept, with the data-flow trace) or *prove* none exists (down-tiered only if you opt in with `graph.securityDeescalate: true`).

**It does not add new detections.** If a base rule doesn't flag a sink, enabling the graph won't flag it either — there is nothing for the graph to confirm. Raising recall (e.g. catching more non-JS injection forms) is a **rule-layer** change, not a graph toggle. The graph is off by default and degrades to a complete no-op when absent.

---

## Design intent

DiffGate is intentionally a **low-noise, diff-scoped second pair of eyes** — not a whole-repo SAST. It is tuned to the residue modern coding agents actually ship (see [MEASUREMENT.md](MEASUREMENT.md)) rather than to maximize raw rule count. If you need exhaustive multi-language taint analysis across an entire codebase, pair DiffGate with a dedicated SAST tool; DiffGate's job is the fast, deterministic gate on the lines that just changed.
