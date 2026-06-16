# Changelog

All notable changes to this project will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

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
