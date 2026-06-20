# Changelog

All notable changes to this project will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [0.3.0] — 2026-06-20

### Added

- **Deeper code-graph use** — DiffGate now drives more of CodeGraph than a single `analyze_impact` call:
  - **`pr_context` is the primary source.** One whole-diff call returns callers, test gaps, suggested reviewers, **stale-doc warnings**, and **cyclomatic complexity** per changed symbol. Findings are enriched from that single payload; symbols it doesn't cover — or any time it's unavailable — fall back to the per-finding `analyze_impact` lookup, so behavior degrades cleanly. Complexity (when high) and stale-doc flags now show in the CLI report, SARIF `properties`, and the VS Code hover.
  - **`find_related_tests` for authoritative test gaps.** In the fallback path, a changed public symbol with zero covering tests is marked untested directly from the graph instead of inferred.
  - **`get_edit_context` in the MCP loop.** `diffgate_analyze` attaches callers/tests/recent-history for the highest-blast finding, so a coding agent can fix the call sites **before the generated code is written to disk**.
- **`diffgate graph` command** — `graph status` shows whether the graph is enabled, the binary is on PATH, and an index exists; `graph index` bootstraps the index (or prints install help when CodeGraph isn't installed). `check` also shows a one-line, non-nagging tip when a public-surface change would benefit from a graph that isn't indexed yet.
- **Graph-aware security (optional, Pro)** — for injection-class findings (`sql-injection`, `xss-sink`, `nosql-injection`, `path-traversal`, `dangerous-exec`, `prototype-pollution`), a CodeGraph Pro taint analysis answers "does user input actually reach this sink?". A **confirmed taint path** is attached to the finding (source → … → sink) and keeps the gate; a **proven-clean** sink can de-escalate **only when `graph.securityDeescalate` is explicitly enabled** (enrich-only by default — a false "no taint" must never silently hide a vulnerability). Fully optional and a no-op when no security graph is present.
- **New `graph` config keys** — `prContext`, `relatedTests`, `editContext` (all default `true`), `security` (`"auto"`), and `securityDeescalate` (`false`).

### Notes

- The CodeGraph driver tries each tool by its bare name and retries with the `codegraph_` namespace, tolerating version/profile differences in tool naming.
- The security pass is validated against CodeGraph's documented tool contract and injected fakes, **not a live Pro binary** — treat the security integration as untested-against-a-real-server until exercised in your environment.

---

## [0.2.0] — 2026-06-20

### Added

- **Cross-file blast radius (code graph)** — public-surface findings (`public-api-change`, `signature-drift`, `deprecated-api`) are enriched with deterministic impact from an optional code graph ([codegraph-ai/CodeGraph](https://github.com/codegraph-ai/CodeGraph)): caller count, suggested reviewers, and test gaps. The pass uses that impact to **route human attention rather than emit more comments**:
  - a changed public surface with **callers stays orange**, names the reviewers, and flags untested call sites (`tierAdjusted: "escalated"`);
  - a changed public surface the graph says **nobody calls de-escalates to yellow** and stops blocking the gate (`tierAdjusted: "deescalated"`) — cutting the largest false-positive class for compatibility rules.
  - Pin a rule's tier in config (e.g. `"signature-drift": { "tier": "orange" }`) to opt out of de-escalation.
- **Optional, graceful dependency** — configured via the new `graph` block. `enabled: "auto"` (default) uses the graph when an index exists and is otherwise a complete no-op (zero subprocess cost, no errors). Talks to CodeGraph via one-shot `codegraph-server --run-tool analyze_impact` queries; a host can also inject its own provider.
- **Impact on every surface** — CLI report blast-radius line, GitHub PR annotations, SARIF `properties` (caller count, reviewers, test gaps, `tierAdjusted`), the MCP `diffgate_analyze` output (so a coding agent sees blast radius before code hits disk), and the VS Code hover card (on saved files).
- **`diffgate stats`** — a signal-vs-noise report. *Realized* signal from reviewer verdicts in `.diffgate/learnings.json` (confirm vs dismiss), including a list of chronically-noisy rules to consider disabling; *predicted* signal from the current diff's tier mix.

### Fixed

- **SARIF** now emits a per-result `level` (orange → error, yellow → warning, green → note) and the real package version (was hard-coded `0.1.2`).

---

## [0.1.5] — 2026-06-16

### Added

- **Feedback → learnings** — `diffgate feedback <ruleId> <file> <line>` (and the `diffgate_feedback` MCP tool) records a verdict on a finding. `dismiss` suppresses that exact flagged code (ruleId + code hash) in all future reviews (noise reduction); `confirm` marks it a real catch. Stored in `.diffgate/learnings.json` (commit it to share across the team). Applied automatically by `check`, `scan`, and the MCP `analyze`.
- **GitHub PR annotations** — `diffgate check --github` emits Actions workflow-command annotations that render inline on the PR "Files changed" tab (orange → error, yellow → warning, green → notice). Ships with a ready-to-use `.github/workflows/diffgate.yml`.

### Fixed

- **Version drift** — the CLI and MCP server version strings are now injected from `package.json` at build time (single source of truth) instead of being hand-maintained.

---

## [0.1.4] — 2026-06-16

### Added

- **Coding-guideline review** — DiffGate now reviews the diff against your repo's own guideline files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`) — the same files your coding agents already read. New `diffgate guidelines` CLI command and `diffgate_guidelines` MCP tool. Configurable via the `guidelines` block.
- **Per-directory scoping** — a guideline file applies to its own directory and all subdirectories; the nearest file wins. Deep nesting is capped (`maxDepth`, default 3): the nearest files plus the repo-root file are kept and the middle is dropped, with a logged note (no silent truncation).
- **Agent-credit (host) evaluation** — `guidelines.evaluator: "auto"` delegates the natural-language judgment to the calling agent's own model when no provider is configured (zero API-key setup), and uses the configured provider otherwise. Guideline findings are advisory (`yellow`, non-blocking) by default since they are non-deterministic.

---

## [0.1.3] — 2026-06-16

### Changed

- **Explain with AI is now thinking-free** — the single-shot explain path suppresses model "thinking" so reasoning models (e.g. Qwen on LM Studio) answer directly instead of burning the budget deliberating. Deep Review still reasons + sweeps.

### Fixed

- **Model-agnostic thinking suppression** — non-standard params (`chat_template_kwargs`, `/no_think`) are only sent to local templated runtimes (LM Studio/Ollama) by default, so hosted APIs (OpenAI, Groq, etc.) no longer 400. Opt in on a custom gateway via `ai.noThink: true`. Residual empty `<think>` blocks are stripped from output.

---

## [0.1.2] — 2026-06-15

### Added

- **Inspector webview** — risk-aware VS Code webview panel for explaining and performing agentic Deep Review. Includes live agent stepper showing tool calls and final verdict.
- **SARIF export** — `--sarif` flag on CLI emits valid SARIF 2.1.0 output for CI/CD integration.
- **Rule packs toggling** — config options to enable/disable whole groups of rules (e.g. `web-security`).
- **Structured verdict** — Deep Review agent now returns structured `verdictClass` (`confirmed-risk`, `likely-safe`, or `needs-human`) parsed from the model output.

### Changed

- **AST rewrites** — `sql-injection`, `xss-sink`, and `path-traversal` rules rewritten with Babel AST matching to identify true security risks while eliminating false positives on parameterized/safe patterns.
- **Smart annotations** — inline diagnostics, gutter icons, and CodeLenses are now displayed on high-impact lines, with CodeLens gated to orange-tier findings.
- **VS Code Engine** — bumped requirement to `^1.90.0` for webview and chat support.

---

## [0.1.1] — 2026-06-14

### Changed

- **Full TypeScript migration** — all source files (`src/**`, `extension/src/extension`) converted from `.js` to `.ts` with `strict: true`. Types are enforced at build time via `tsc --noEmit`.
- **esbuild bundler** — CLI ships as a single bundled file (`dist/cli.js`) with shebang. Core library and MCP server are compiled individually to `dist/` for tree-shaking by consumers.
- **6 new security rules** — `sql-injection` (blocking orange), `permissive-cors`, `xss-sink`, `path-traversal`, `nosql-injection`, `prototype-pollution`. Rule count: 21 → 27.
- **Inline verdict badge** — after Deep Review runs, the hover card shows `$(error) Confirmed risk`, `$(pass) Likely safe`, or `$(question) Needs human review` directly in the tooltip. No need to open the output channel.
- **MCP `diffgate_analyze` agent-review workflow** — documented with diagram in README. Enables coding agents (Claude Code, Cursor, etc.) to check generated code before writing it to disk.
- Package entry points updated: `bin.diffgate → dist/cli.js`, `main / exports → dist/core/index.js`.

---

## [0.1.0] — 2024-06-14

Initial public release.

### Engine (`src/core`)

- **Diff-aware analysis** — reports findings only on lines changed vs the git baseline; falls back to whole-file when outside a git repo.
- **Real AST for JS/TS** — `@babel/parser` powers precise rules that are not fooled by comments or strings.
- **21 built-in rules** across three tiers (green / yellow / orange):
  - Secrets: `hardcoded-secret`
  - SQL / NoSQL injection: `sql-injection`, `nosql-injection`, `raw-query`, `db-schema-change`, `db-schema-destructive`
  - Web security: `permissive-cors`, `xss-sink`, `path-traversal`, `prototype-pollution`
  - Execution: `dangerous-exec`
  - Auth / crypto: `auth-crypto`
  - Public surface: `public-api-change`, `signature-drift`, `deprecated-api` (with auto-fix)
  - Network / deps: `network-call`, `dependency-manifest`, `migration-file`
  - Dev hygiene: `leftover-debugger`, `debug-logging`, `todo-marker`
- **Signature-drift detection** — warns when an exported function's parameter list changes.
- **Real gate** — runs the project's `testCommand` when an orange finding is gated.
- **Provider-agnostic LLM** — optional AI layer with 8 providers (Anthropic, OpenAI, OpenRouter, Groq, Together, LM Studio, Ollama, custom). Per-tier model routing.
- **Deep Review** — ReAct agent loop that uses grep, read_file, find_references, and git_blame to investigate blast radius of orange findings, returning a `confirmed-risk / likely-safe / needs-human` verdict.

### CLI (`diffgate`)

- `check` — diff gate, exits 1 on orange/blocking findings.
- `check --staged` — staged-only diff.
- `check --json` — machine-readable output.
- `scan <path>` — analyze a directory without git.
- `watch [path]` — live re-analysis on file change.
- `explain <path> <line>` — AI explanation for a specific finding.
- `init` — write a starter `.diffgate.json`.
- `install-hook` — add a git pre-commit gate.
- `mcp` — start the MCP stdio server.

### VS Code extension

- Inline diagnostics on changed lines (or whole-file mode).
- Hover cards: tier, message, git-blame attribution, AI explain link, Deep Review link.
- Deep Review verdict badge in hover (confirmed-risk / likely-safe / needs-human) after the agent runs.
- Quick-fixes for `deprecated-api` findings.
- Risk Review tree (activity bar): all pending changes by file and tier.
- Status-bar risk summary.
- Verification gate command.
- Settings: `diffgate.scanMode`, `diffgate.diffMode`, `diffgate.ai.*`.

### MCP server

- `diffgate_analyze` — deterministic analysis of a file; accepts unsaved `content` parameter (zero LLM tokens).
- `diffgate_check_staged` — scan all working-tree / staged changes.
- `diffgate_deep_review` — agentic blast-radius analysis for an orange finding.
- `diffgate_explain` — single-shot AI explanation.
- JSON-RPC 2.0 over stdin/stdout with Content-Length framing (LSP-style). No SDK dependency.
- Compatible with Claude Code (`~/.claude/mcp.json`), Cursor, and any MCP-capable agent.

### Tests

- 47 unit and integration tests (`node:test`).
- Extension smoke test (module-stub harness, no VS Code process needed).
