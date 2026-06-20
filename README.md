# DiffGate Review Engine

**Diff-aware, three-tiered code review — in your editor and on the command line.**

Most review tooling fires on the whole file and treats every line the same, so you drown in noise and the real risks hide in it. DiffGate reviews only the lines you **changed** (vs the committed baseline) and sorts each change into one of three risk tiers, so trivial edits fly through and high-impact ones get gated:

| Tier | Meaning | What you do | Examples |
|------|---------|-------------|----------|
| 🟢 **Green** | Safe / self-contained | merge freely | comments, local logging |
| 🟡 **Yellow** | Review — soft dependency | take a look | deprecated APIs, raw SQL, network calls, dependency-manifest edits |
| 🟠 **Orange** | High-impact — gate it | verify before merge | schema/migrations, hardcoded secrets, auth/crypto, public-API & signature changes, SQL/XSS/path-traversal injection sinks |

It runs two ways from one shared engine:

- **VS Code extension** — inline squiggles on changed lines, hover cards (why · who owns it · quick-fix), a Risk Review tree, a status-bar summary, a verification gate, and **Deep Review** (agentic blast-radius analysis for orange findings).
- **CLI** — `diffgate check` reviews your diff and exits non-zero on high-impact findings: perfect as a **pre-commit hook** or **CI gate**.
- **MCP server** — `diffgate mcp` exposes the engine as an MCP tool so coding agents (Claude Code, Cursor, etc.) can check generated code before surfacing it to you.

---

## Quick start

```bash
npm install            # installs the engine + @babel/parser
npm link               # optional: makes `diffgate` available globally

diffgate scan mock_project          # analyze files directly (no git needed)
diffgate check                      # review your pending git changes (the gate)
diffgate check --github             # same + emit GitHub Actions inline annotations
diffgate watch                      # live review as you edit
diffgate guidelines                 # review diff against your repo's AGENTS.md/CLAUDE.md etc.
diffgate feedback <ruleId> <f> <l>  # record a dismiss/confirm verdict on a finding
diffgate stats                      # signal-vs-noise report (realized verdicts + predicted diff)
diffgate graph status               # is the code graph enabled / installed / indexed?
diffgate graph index                # build the cross-file index (or print install help)
diffgate init                       # write a starter .diffgate.json
diffgate install-hook               # add a git pre-commit gate
diffgate mcp                        # start the MCP stdio server
```

> No git repo? `check`/`watch` fall back gracefully; use `scan` to analyze files directly.

### VS Code extension

```bash
npm install --prefix extension
npm run build --prefix extension
```

Press **F5** in this repo ("Run DiffGate Extension") to launch a dev host, or build an installable package:

```bash
npm run package --prefix extension   # produces extension/diffgate-*.vsix
# then: code --install-extension extension/diffgate-0.1.2.vsix
```

---

## How it works

- **Diff-aware** — uses `git diff` (CLI) or an in-memory LCS diff (editor, accurate on unsaved buffers) to find changed lines, and only reports findings on those lines.
- **Real AST for JS/TS** — `@babel/parser` powers precise rules: deprecated calls are not matched inside comments or strings, and exported-signature changes are detected structurally.
- **Language-agnostic pattern rules** — secrets, SQL/schema changes, auth/crypto, dynamic execution, and injection sinks are detected across Python, Go, Java, Ruby, and any text via pattern rules.
- **Real gate** — when a change is high-impact, DiffGate runs your `testCommand` and shows the actual exit code and output.
- **Hybrid AI (optional, provider-agnostic)** — the deterministic engine always runs offline; when `ai.enabled` is true it adds plain-English explanations and fix suggestions. Works with **Anthropic, OpenAI, OpenRouter, Groq, Together, LM Studio, Ollama, or any OpenAI-compatible endpoint**.
- **Cross-file blast radius (optional code graph)** — when a code graph ([codegraph-ai/CodeGraph](https://github.com/codegraph-ai/CodeGraph)) is available, public-surface findings carry deterministic impact (caller count, suggested reviewers, test gaps, complexity, stale docs) sourced from a single `pr_context` call per review. DiffGate uses it to **route attention, not add comments**: a public change with callers stays orange and names the reviewers; one nobody calls de-escalates to yellow and stops blocking. For injection-class findings, an optional Pro taint analysis confirms whether user input reaches the sink. Fully optional and graceful — a no-op when no graph is present.
- **Deep Review** — for orange findings, an agentic loop (grep, read_file, find_references, git_blame) investigates blast radius and returns a `confirmed-risk / likely-safe / needs-human` verdict.
- **Guideline review** — reviews the diff against your repo's own `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and similar files. Per-directory scoping; the nearest file wins. No extra API key needed in host mode — the calling agent does the judgment.
- **Learnings** — `diffgate feedback` records dismiss/confirm verdicts. Dismissed findings (same rule + same code) are suppressed in all future reviews. Stored in `.diffgate/learnings.json` — commit it to share across the team.

Engine layout: [`src/core`](src/core) (shared) · [`src/cli.ts`](src/cli.ts) (CLI) · [`src/mcp.ts`](src/mcp.ts) (MCP server) · [`extension/`](extension) (VS Code). Tests: [`test/`](test) and [`extension/test/smoke.cjs`](extension/test/smoke.cjs).

---

## Configuration — `.diffgate.json`

Place it at your repo root (`diffgate init` generates one). See [example.diffgate.json](example.diffgate.json) for the full schema.

```jsonc
{
  "testCommand": "npm test",                 // run for orange changes (the gate)
  "gate": { "mode": "working", "failOn": "orange" },
  "ai": { "enabled": false, "model": "claude-sonnet-4-6", "apiKeyEnv": "ANTHROPIC_API_KEY" },

  "guidelines": {                            // review diff against AGENTS.md/CLAUDE.md etc.
    "enabled": true,
    "autoDetect": true,                      // walk up to find AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, etc.
    "maxDepth": 3,                           // keep nearest 2 + repo-root; drop middle (logged)
    "tier": "yellow",                        // cap guideline findings here (non-blocking by default)
    "blocking": false,
    "evaluator": "auto"                      // "host" = calling agent judges (no API key); "model" = configured provider
  },

  "deprecated": [                            // drives the deprecated-api rule + quick-fix
    { "pattern": "StripeClient.charge", "replacedBy": "StripeClient.createPaymentIntent",
      "author": "Finance Team", "pr": "PR #204" }
  ],

  "customPatterns": [                        // your own pattern rules
    { "id": "no-process-env", "tier": "yellow", "pattern": "process\\.env\\.",
      "message": "Use the typed config module, not process.env." }
  ],

  "rules": {                                 // tune built-ins
    "todo-marker": false,                    //  - disable a rule
    "network-call": { "tier": "green" }      //  - or change its tier
  },

  "graph": {                                 // optional cross-file blast radius
    "enabled": "auto",                       //  - "auto": use a code graph when indexed, else no-op
    "provider": "codegraph",                 //  - github.com/codegraph-ai/CodeGraph
    "escalateThreshold": 1,                  //  - callers ≥ this keeps a public change orange; 0 callers → yellow
    "security": "auto",                      //  - use the Pro taint graph for injection findings when present
    "securityDeescalate": false              //  - allow a proven-clean sink to de-escalate (off = enrich-only)
  },

  "ignore": ["**/node_modules/**", "**/dist/**"]
}
```

### LLM providers

The engine is **provider-agnostic**. Under the hood there are two wire adapters — Anthropic's Messages API and the OpenAI Chat Completions API — and OpenAI's format is spoken by almost everything else.

| `provider` | Key env | Notes |
|------------|---------|-------|
| `anthropic` *(default)* | `ANTHROPIC_API_KEY` | Claude models |
| `openai` | `OPENAI_API_KEY` | any model you have access to |
| `openrouter` | `OPENROUTER_API_KEY` | model as `vendor/model` |
| `groq` / `together` | `GROQ_API_KEY` / `TOGETHER_API_KEY` | fast hosted OSS models |
| `lmstudio` / `ollama` | *(none)* | **local models, no key needed** |
| `custom` | your `apiKeyEnv` | any OpenAI-compatible server + `baseURL` |

**Multi-model routing by complexity.** `model` can be a per-tier map so cheap edits use a small model and high-impact ones use a strong one:

```jsonc
"ai": { "enabled": true, "provider": "openai",
        "model": { "orange": "gpt-5.5", "default": "gpt-5.4-mini" } }
```

### Built-in rules

| Rule | Tier | Notes |
|------|------|-------|
| `hardcoded-secret` | 🟠 blocking | AWS keys, GitHub PATs, Stripe secrets, generic credential patterns |
| `db-schema-destructive` | 🟠 blocking | `DROP`, `TRUNCATE`, `DELETE` without `WHERE` |
| `sql-injection` | 🟠 blocking | template literals / concatenation inside SQL calls |
| `db-schema-change` | 🟠 | `ALTER TABLE`, `ADD COLUMN`, `RENAME` |
| `auth-crypto` | 🟠 | passport, JWT, bcrypt, session handlers |
| `dangerous-exec` | 🟠 | `eval()`, `exec()`, `os.system()`, `pickle.loads` |
| `public-api-change` | 🟠 | exported symbols (JS/TS AST) |
| `signature-drift` | 🟠 | exported function parameter changes (JS/TS) |
| `permissive-cors` | 🟠 | `origin: '*'` |
| `xss-sink` | 🟠 | `innerHTML`, `document.write`, `insertAdjacentHTML` (JS/TS) |
| `path-traversal` | 🟠 | `path.join/readFile` called with `req.params/query/body` |
| `nosql-injection` | 🟠 | `$where`, `db.eval`, `Model.find(req.body)` passthrough |
| `prototype-pollution` | 🟠 | `Object.assign(existing, req.body)`, `_.merge` with request data (JS/TS) |
| `deprecated-api` | 🟡 | configured via `deprecated[]`, offers a quick-fix |
| `raw-query` | 🟡 | `db.query()`, bare SQL keywords |
| `network-call` | 🟡 | `fetch`, `axios`, `requests.*` |
| `migration-file` | 🟡 | migration file names |
| `dependency-manifest` | 🟡 | `package.json`, `requirements.txt`, etc. |
| `leftover-debugger` | 🟡 | `debugger` statement (JS/TS) |
| `debug-logging` | 🟢 | `console.log`, `fmt.Print`, `System.out.println` |
| `todo-marker` | 🟢 | `TODO`, `FIXME`, `HACK` |

Disable or re-tier any rule via the `rules` key in `.diffgate.json`.

**Native precision (no code graph needed).** Injection and secret findings are refined deterministically from the file's own AST: an XSS sink whose value comes from a recognized sanitizer (`DOMPurify.sanitize`, `escapeHtml`, `encodeURIComponent`, …) is **down-tiered to a yellow "verify" note** rather than blocking, and `hardcoded-secret` drops env/placeholder/low-entropy matches while always keeping — and labeling — known provider key formats. Down-tiering never *suppresses* a security finding, so a missed sanitizer stays blocking (the safe default).

---

## Guideline review (AGENTS.md / CLAUDE.md)

Checks the diff against your repo's coding-agent instruction files.

**Detected automatically:** `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`

**Per-directory scoping** — nearest file wins; deep nesting is capped at `maxDepth` (default 3), keeping the closest files + repo-root. Drops logged.

**`evaluator`** — `"auto"` (default): uses configured provider when available, otherwise returns the guideline text + diff hunks for the calling agent to evaluate with its own model (no API key needed). `"model"`: always uses the configured provider.

```bash
diffgate guidelines            # run manually
```

Findings are `yellow` / non-blocking by default (configurable).

---

## Cross-file blast radius (code graph)

Most reviewers face a false tradeoff: index the whole repo for cross-file context and you catch breaking changes *but get noisier*; stay diff-scoped and you're quiet *but miss the call sites*. DiffGate resolves it because tiers **route attention instead of emitting comments** — so cross-file context makes the review *quieter and more complete at once*.

When an optional code graph ([codegraph-ai/CodeGraph](https://github.com/codegraph-ai/CodeGraph), Apache-2.0) is present, the impact pass enriches public-surface findings (`public-api-change`, `signature-drift`, `deprecated-api`) and adjusts their tier:

| Situation | What DiffGate does |
|-----------|--------------------|
| Public change **with callers** | Stays 🟠, message names the caller count, **suggested reviewers**, **untested** call sites, plus complexity and stale-doc flags (`tierAdjusted: escalated`) |
| Public change **nobody calls** | De-escalates 🟠 → 🟡 and **stops blocking the gate** (`tierAdjusted: deescalated`) |
| No graph available | Complete no-op — same behavior as before, no subprocess cost |

**How it sources impact.** One `pr_context` call per review covers the whole diff (callers, test gaps, reviewers, stale docs, complexity). Symbols it doesn't cover — or any time it's unavailable — fall back to a per-finding `analyze_impact` lookup, with `find_related_tests` supplying authoritative test-gap data. In the MCP loop, `diffgate_analyze` additionally attaches `get_edit_context` (callers/tests/recent history) to the highest-blast finding so an agent can fix the call sites before writing code.

**Setup** — `diffgate graph status` tells you what's configured; `diffgate graph index` builds the index (or prints install instructions if CodeGraph isn't installed). DiffGate auto-detects the index (`~/.codegraph/graph.db`). The graph indexes committed/disk state, so *who calls a changed symbol* is reliable. To never auto-de-escalate a rule, pin its tier: `"rules": { "signature-drift": { "tier": "orange" } }`.

**Graph-aware security (optional, Pro).** For injection-class findings (`sql-injection`, `xss-sink`, `nosql-injection`, `path-traversal`, …) a CodeGraph Pro taint analysis answers *does user input actually reach this sink?* A confirmed taint path is attached (source → … → sink) and keeps the gate. A proven-clean sink de-escalates **only if you set `graph.securityDeescalate: true`** — enrich-only by default, because a false "no taint" must never silently hide a vulnerability. (Validated against CodeGraph's documented contract, not a live Pro binary.)

Impact surfaces everywhere a finding does: the CLI report, GitHub PR annotations, SARIF `properties`, the MCP `diffgate_analyze` output (so coding agents see blast radius **before code is written to disk**), and the VS Code hover card.

---

## Signal report

```bash
diffgate stats          # realized signal (from your verdicts) + predicted signal (current diff)
```

*Realized* signal turns the `confirm`/`dismiss` verdicts in `.diffgate/learnings.json` into a ratio of real catches to noise, and lists **chronically-noisy rules** worth disabling. *Predicted* signal scores the current diff (🟠/🟡 = signal, 🟢 = low-signal). Use it to prove — and keep — a low-noise review.

---

## Feedback and learnings

```bash
diffgate feedback <ruleId> <file> <line> --confirm     # real catch — mark it
diffgate feedback <ruleId> <file> <line> --dismiss     # noise — suppress it in future reviews
```

Matched by `ruleId` + code hash. Latest verdict wins. Stored in `.diffgate/learnings.json` — commit it to share across the team.

---

## CI / pre-commit

```bash
# Pre-commit hook (installed by `diffgate install-hook`)
diffgate check --staged

# CI
diffgate check --fail-on=orange      # exit 1 blocks the build
diffgate check --json                # machine-readable output
diffgate check --github              # emit GitHub Actions inline PR annotations
```

### GitHub Actions

Drop this file into `.github/workflows/diffgate.yml` (also ships ready-made with the package):

```yaml
on: [pull_request]
jobs:
  diffgate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: git reset --mixed "origin/${{ github.base_ref }}"
      - run: npx diffgate-review@latest check --working --github
```

## DiffGate for Coding Agents

DiffGate's MCP server enables a workflow that PR-review tools cannot address: catching security issues in **generated code before it is written to disk**.

When a coding agent (Claude Code, Cursor, Continue, etc.) is about to suggest code, it calls `diffgate_analyze` with the generated content directly — no commit, no staged file:

```
Agent generates code
        │
        ▼
diffgate_analyze(filePath, content)   ← content = the unsaved suggestion
        │
  orange finding?
   ┌────┴────┐
  yes        no
   │          │
   ▼          ▼
Agent       User sees
self-corrects  the code
```

Example: the agent writes a function with `` db.query(`SELECT * FROM users WHERE id = ${req.query.id}`) ``. DiffGate returns an orange `sql-injection` finding. The agent revises to `db.query("SELECT * FROM users WHERE id = ?", [req.query.id])` and re-checks — clean result. The user sees only the corrected version.

The deterministic rules cost **zero LLM tokens** — the agent gets back structured JSON findings, not prose. Token spend only occurs if the agent also calls `diffgate_deep_review` to investigate blast radius.

**Setup (2 lines):** Add to `~/.claude/mcp.json` (Claude Code) or your Cursor MCP settings:

```json
{
  "mcpServers": {
    "diffgate": { "command": "diffgate", "args": ["mcp"] }
  }
}
```

Without a global install: `{ "command": "node", "args": ["/path/to/diffgate/dist/cli.js", "mcp"] }`

See [MCP.md](MCP.md) for tool descriptions and AI configuration.

---

## Try it

```bash
diffgate scan mock_project
```

You'll see green findings (logging), yellow findings (deprecated `StripeClient.charge`), and orange findings (the `DROP COLUMN` migration, a public export).

## Tests

```bash
npm test    # builds the extension, runs 145 unit/integration tests + the extension smoke test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
