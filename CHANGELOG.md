# Changelog

All notable changes to this project will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

Adoption-friction pass: make DiffGate trivial to install for individuals and teams, raise non-JS/TS precision, and stop the gate from blocking on test scaffolding. (Additive — suggested release: minor bump to 0.4.3.)

### Added

- **Comment-aware pattern rules** ([src/core/mask.ts](src/core/mask.ts)). Non-JS/TS languages match via regex, so commented-out code (`# os.system(x)`, `// eval(x)`, `-- DROP TABLE`) used to trip security rules. Comment regions are now blanked before matching (columns preserved) across Python, Go, Ruby, Java, C/C++, C#, Rust, SQL, shell, HTML, and more. Strings are left intact (secrets and SQL live in strings), and `hardcoded-secret` / `todo-marker` scan raw text via a new `scanRaw` rule flag (a secret in a comment is still a leak; markers live in comments).
- **Test-context de-escalation** ([src/core/testscope.ts](src/core/testscope.ts), `testScope` config, default `true`). Non-exempt orange findings in test / fixture / mock files down-tier to yellow and stop blocking the gate — test scaffolding (mock SQL, `eval` in a harness, sample payloads) is almost always intentional. Never suppressed (still shown as a review note). Exempt and still blocking: `hardcoded-secret`, `db-schema-destructive`, and the graph-owned public-surface rules (`public-api-change`, `signature-drift`, `deprecated-api`). Opt out per-rule by pinning its tier, or globally with `testScope: false`.
- **Language-aware CodeGraph nudge** ([src/cli.ts](src/cli.ts) `maybeGraphTip`). A non-JS/TS repo now gets a quiet, fade-out tip that CodeGraph adds cross-file caller/taint precision for its language — previously the tip only fired on JS/TS public-surface findings, so the users who benefit most never saw it.
- **`diffgate merge-driver`** ([src/core/learnings.ts](src/core/learnings.ts) `mergeLearningStores`). A git merge driver that auto-resolves parallel `learnings.json` verdicts (set-union by id; newer timestamp wins). `diffgate install-hook` registers it automatically (calls `diffgate` on PATH with a node fallback — no fragile `node_modules` path).
- **Release automation**: `publish-npm.yml`, `publish-ext.yml`, `publish-mcpb.yml` GitHub Actions publish the CLI (npm, with provenance), the VS Code extension (Marketplace + Open VSX), and a `.mcpb` Desktop Extension on a `v*` tag. Extension version is stamped from the tag.
- **One-click MCP**: `claude mcp add diffgate -- diffgate mcp`; `extension.manifest.json` ships a Desktop Extension manifest. `diffgate init --demo` previews findings on the bundled `mock_project` so first-run is never empty.
- **`diffgate marginal`** ([src/marginal.ts](src/marginal.ts)). Marginal-catch experiment: hands a model 12 realistic coding tasks with no security hint, runs the gate over whatever it writes, and reports how often the agent's *unguided* output trips a security finding DiffGate would catch. Answers the actual adoption question — does before-the-diff catch code the agent wouldn't have avoided on its own — rather than the absolute detection `diffgate bench` measures. Provider-agnostic (hosted or local LM Studio/Ollama); `--out` saves the generated code so every verdict is auditable. Scoring is deliberately honest: empty/think-only replies are errors (never "clean"); blast-radius advisories like `public-api-change` are excluded; and *coarse* construct-presence rules (`dangerous-exec`, `auth-crypto`, `db-schema-destructive`) — which fire on correct code (e.g. the safe `execFile(['…'])`, a secure PBKDF2) — are reported as a separate "advisory" bucket so they never inflate the defect-catch headline. `--max-tokens` / `--token-param` / `--base-url` / `--provider` / `--model` flags; reasoning-model token-param is auto-selected (gpt-5.x/o-series → `max_completion_tokens`). Live runs vs `qwen3.5-9b` and `gpt-5.4-mini` both landed at a low single-digit/teens defect-catch rate — the models already avoid the textbook vulns, and the residual catches (unguarded recursive merge, permissive default CORS) are the second-order footguns.

### Fixed

- **MCP stdio transport is now spec-compliant** ([src/mcp.ts](src/mcp.ts)). The server framed messages LSP-style (`Content-Length:` headers); the [MCP spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) mandates newline-delimited JSON. Spec-compliant clients (Cursor, mcp-inspector, the official SDKs) got no response and hung. The reader now auto-detects both framings (older Claude Code builds keep working) and the writer emits newline-delimited JSON. `initialize` also negotiates the protocol version (echoes the client's if supported, else `2025-06-18`) instead of hardcoding `2024-11-05`.
- **`permissive-cors` now catches bare `cors()`** ([src/core/rules/builtin.ts](src/core/rules/builtin.ts)). The `cors` npm package with no `origin` option defaults to `Access-Control-Allow-Origin: *`; the rule previously only matched the explicit `*` / `origin:true` forms, so the most common permissive form slipped through. Surfaced by `diffgate marginal` — both a local 9B and `gpt-5.4-mini` wrote `cors()`. Bench cases added (`cors/default-permissive`, `clean/cors-allowlist`); gate noise stays 0 false-blocks.
- **`prototype-pollution` now flags unguarded recursive deep-merge** ([src/core/rules/builtin.ts](src/core/rules/builtin.ts)). An AST check for a recursive merge that lacks a string-literal `__proto__`/`constructor` guard (a `hasOwnProperty` member-access does *not* count — it still pollutes through `target["__proto__"]`). Non-blocking review note; `Object.create(null)` targets and Maps are an accepted recall gap.
- Extension version synced to the CLI (was stuck at 0.1.5) and given the marketplace metadata it was missing (`icon`, `repository`, `homepage`, `bugs`, `keywords`, `galleryBanner`); added a generated PNG icon. Extension `package` script no longer hardcodes a `0.1.2` filename. Removed stale committed `.vsix` artifacts.

---

## [0.4.2] — 2026-06-21

Hardening of the agent autonomy ladder (0.4.1): make the budget enforceable where a session actually exists, surface trust in the IDE, and close config/CLI footguns.

### Added

- **Opt-in budget enforcement** ([src/core/session.ts](src/core/session.ts)). DiffGate stays stateless and deterministic by default (a CI/pre-commit gate is a pure function of the diff). But in the two contexts that have a real agent loop, it now counts how many gate checks a finding has survived and escalates when it outlasts `escalateAfterTurns`:
  - **MCP** (one server process == one session): `diffgate_check_staged` adds an `agentBudget` block listing findings that have recurred past the budget — the external "stop re-fixing, escalate to a human" signal an agent can't self-enforce.
  - **CLI**: `diffgate check --agent --session=<id>` (or `$DIFFGATE_AGENT_SESSION`) promotes over-budget findings to the `escalate` rung, surfacing them as `review`. Without a session id, behavior is unchanged and deterministic. `agentVerdict` gains an `escalations` count and a per-finding `overBudget` flag.
  - Session ledger is idle-window scoped (30 min) and per-`sessionId`, so unrelated runs never bleed into each other.
- **Trust in the VS Code hover.** Findings now carry their deterministic trust label (`confirmed` / `cleared` / `unconfirmed`) in the editor, so the same orange finding reads "pattern/AST match" vs "no taint analysis available — verify before acting". Kept quiet for green/yellow deterministic matches to avoid noise.

### Changed

- **`gate.agent.mode` (and `failOn`, `agent.autoFixFloor`, `agent.trustSource`) are now validated at config load** — a typo like `"gated2"` throws a clear error instead of silently falling back to advisory behavior.
- **Host-mode guideline payload is structurally non-blocking.** `diffgate_guidelines` host mode now returns `blocking: false` plus a `reason`, so a harness can honor the advisory constraint without parsing prose (in addition to the existing `independent:false`/`advisory:true`).
- **`diffgate_capabilities` protocol text** now states plainly that the loop budget is *self-enforced* (DiffGate cannot reject the Nth fix per call) and that MCP/`--session` runs emit a hard-stop budget signal.

### Fixed

- **`--agent-mode` space form no longer silently ignored.** `diffgate check --agent-mode gated` (no `=`) warns to stderr instead of quietly staying advisory; an unknown value also warns. Documented in `--help`.

## [0.4.0] — 2026-06-20

### Added — native security signal (no code graph required)

The whole product thesis is "flag what needs attention, in a gradient, without noise." These land for **every** user; CodeGraph remains strictly optional and only adds cross-file reach on top.

- **Sanitizer-aware XSS down-tiering.** A dynamic `innerHTML`/`document.write`/`insertAdjacentHTML` value that is produced by a recognized sanitizer (`DOMPurify.sanitize`, `escapeHtml`, `encodeURIComponent`, `he.encode`, …) is **down-tiered from a blocking orange to a yellow review note** ("sink, but sanitized in place — verify") instead of blocking the gate. Resolves one level of local-variable aliasing (`const clean = DOMPurify.sanitize(x); el.innerHTML = clean`). We **never suppress** a security finding — a missed sanitizer keeps it blocking — so this can only reduce noise, never hide a vulnerability.
- **Secret-finding precision.** The broad `hardcoded-secret` catch-all now runs an entropy + placeholder filter: env/interpolation references (`process.env.X`, `${…}`) and obvious placeholders (`changeme`, `your-key-here`, low-entropy fixtures) are dropped, while **known provider key formats (AWS/GitHub/Stripe/Google/Slack) are always kept and labeled "high confidence."**
- **Wider taint sources.** Request-derived input detection now covers `req.cookies` / `req.signedCookies` in addition to `query`/`body`/`params`/`headers`, improving recall for the path-traversal and SQL sinks.
- **New engine hooks** (internal): pattern rules gain an optional `validate(match)` for per-match precision; AST findings can carry a `blocking` override and `tierAdjusted` natively (previously only the graph passes set tiers).

### Changed

- **The CodeGraph adoption tip now fades.** The one-line "install CodeGraph for blast radius" nudge on `check` shows at most **3 times per repo** (tracked in `.diffgate/state.json`), then goes quiet — CodeGraph is good-to-have, not mandatory, and the engine is fully useful without it.

### Added — team-adoption suite

- **PR-native review** — `diffgate check --pr[=<n>]` posts an inline PR review + a `diffgate` commit status via the GitHub API (uses `GITHUB_TOKEN` and the Actions env); orange findings fail the check so they gate merge. `--pr-dry-run` previews the payload offline. `--base=<ref>` reviews the whole PR/branch against a base branch (needed in CI, where the working tree is clean). Updated [`.github/workflows/diffgate.yml`](.github/workflows/diffgate.yml) + GitHub App scaffold ([docs/github-app.md](docs/github-app.md), [docs/app-manifest.json](docs/app-manifest.json)).
- **Noise benchmark** — `diffgate bench` scores precision/recall/F1 per rule on a versioned, offline corpus and reports the headline trust metric: **false blocks per clean change** (0 on the shipped corpus). Methodology in [BENCHMARK.md](BENCHMARK.md).
- **Org-wide policy packs** — config `extends` (path or npm package; base-first, local wins; arrays concat, objects merge, with circular/depth guards) and `learnings.shared` (merge dismiss/confirm verdicts across repos; local overrides shared).
- **Review metrics** — `diffgate report` summarizes tiers, hotspot files, top rules, and the learnings loop. `diffgate report --compliance` emits SOC 2 control evidence (rule→control mapping in [src/compliance.ts](src/compliance.ts); narrative in [COMPLIANCE.md](COMPLIANCE.md)).
- **Agent gate** — `diffgate check --agent` emits a compact pass/blocked JSON verdict for coding-agent harnesses (exit 1 when blocked). Positioning in [docs/ai-agents.md](docs/ai-agents.md).
- **Smarter onboarding** — `diffgate init` now auto-detects the test command (npm/pytest/go/cargo/make), languages, and guideline files, and writes a tailored config (`--minimal` for the old static template).

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
