# Guardrail Review Engine

**Diff-aware, three-tiered code review — in your editor and on the command line.**

Most review tooling fires on the whole file and treats every line the same, so you drown in noise and the real risks hide in it. Guardrail reviews only the lines you **changed** (vs the committed baseline) and sorts each change into one of three risk tiers, so trivial edits fly through and high-impact ones get gated:

| Tier | Meaning | What you do | Examples |
|------|---------|-------------|----------|
| 🟢 **Green** | Safe / self-contained | merge freely | comments, local logging |
| 🟡 **Yellow** | Review — soft dependency | take a look | deprecated APIs, raw SQL, network calls, dependency-manifest edits |
| 🟠 **Orange** | High-impact — gate it | verify before merge | schema/migrations, hardcoded secrets, auth/crypto, public-API & signature changes, SQL/XSS/path-traversal injection sinks |

It runs two ways from one shared engine:

- **VS Code extension** — inline squiggles on changed lines, hover cards (why · who owns it · quick-fix), a Risk Review tree, a status-bar summary, a verification gate, and **Deep Review** (agentic blast-radius analysis for orange findings).
- **CLI** — `guardrail check` reviews your diff and exits non-zero on high-impact findings: perfect as a **pre-commit hook** or **CI gate**.
- **MCP server** — `guardrail mcp` exposes the engine as an MCP tool so coding agents (Claude Code, Cursor, etc.) can check generated code before surfacing it to you.

---

## Quick start

```bash
npm install            # installs the engine + @babel/parser
npm link               # optional: makes `guardrail` available globally

guardrail scan mock_project          # analyze files directly (no git needed)
guardrail check                      # review your pending git changes (the gate)
guardrail watch                      # live review as you edit
guardrail init                       # write a starter .guardrails.json
guardrail install-hook               # add a git pre-commit gate
guardrail mcp                        # start the MCP stdio server
```

> No git repo? `check`/`watch` fall back gracefully; use `scan` to analyze files directly.

### VS Code extension

```bash
npm install --prefix extension
npm run build --prefix extension
```

Press **F5** in this repo ("Run Guardrail Extension") to launch a dev host, or build an installable package:

```bash
npm run package --prefix extension   # produces extension/guardrail-review-*.vsix
# then: code --install-extension extension/guardrail-review-0.1.1.vsix
```

---

## How it works

- **Diff-aware** — uses `git diff` (CLI) or an in-memory LCS diff (editor, accurate on unsaved buffers) to find changed lines, and only reports findings on those lines.
- **Real AST for JS/TS** — `@babel/parser` powers precise rules: deprecated calls are not matched inside comments or strings, and exported-signature changes are detected structurally.
- **Language-agnostic pattern rules** — secrets, SQL/schema changes, auth/crypto, dynamic execution, and injection sinks are detected across Python, Go, Java, Ruby, and any text via pattern rules.
- **Real gate** — when a change is high-impact, Guardrail runs your `testCommand` and shows the actual exit code and output.
- **Hybrid AI (optional, provider-agnostic)** — the deterministic engine always runs offline; when `ai.enabled` is true it adds plain-English explanations and fix suggestions. Works with **Anthropic, OpenAI, OpenRouter, Groq, Together, LM Studio, Ollama, or any OpenAI-compatible endpoint**.
- **Deep Review** — for orange findings, an agentic loop (grep, read_file, find_references, git_blame) investigates blast radius and returns a `confirmed-risk / likely-safe / needs-human` verdict.

Engine layout: [`src/core`](src/core) (shared) · [`src/cli.ts`](src/cli.ts) (CLI) · [`src/mcp.ts`](src/mcp.ts) (MCP server) · [`extension/`](extension) (VS Code). Tests: [`test/`](test) and [`extension/test/smoke.cjs`](extension/test/smoke.cjs).

---

## Configuration — `.guardrails.json`

Place it at your repo root (`guardrail init` generates one). See [example.guardrails.json](example.guardrails.json) for the full schema.

```jsonc
{
  "testCommand": "npm test",                 // run for orange changes (the gate)
  "gate": { "mode": "working", "failOn": "orange" },
  "ai": { "enabled": false, "model": "claude-sonnet-4-6", "apiKeyEnv": "ANTHROPIC_API_KEY" },

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

Disable or re-tier any rule via the `rules` key in `.guardrails.json`.

---

## CI / pre-commit

```bash
# Pre-commit hook (installed by `guardrail install-hook`)
guardrail check --staged

# CI
guardrail check --fail-on=orange      # exit 1 blocks the build
guardrail check --json                # machine-readable output
```

## Guardrail for Coding Agents

Guardrail's MCP server enables a workflow that PR-review tools cannot address: catching security issues in **generated code before it is written to disk**.

When a coding agent (Claude Code, Cursor, Continue, etc.) is about to suggest code, it calls `guardrail_analyze` with the generated content directly — no commit, no staged file:

```
Agent generates code
        │
        ▼
guardrail_analyze(filePath, content)   ← content = the unsaved suggestion
        │
  orange finding?
   ┌────┴────┐
  yes        no
   │          │
   ▼          ▼
Agent       User sees
self-corrects  the code
```

Example: the agent writes a function with `` db.query(`SELECT * FROM users WHERE id = ${req.query.id}`) ``. Guardrail returns an orange `sql-injection` finding. The agent revises to `db.query("SELECT * FROM users WHERE id = ?", [req.query.id])` and re-checks — clean result. The user sees only the corrected version.

The deterministic rules cost **zero LLM tokens** — the agent gets back structured JSON findings, not prose. Token spend only occurs if the agent also calls `guardrail_deep_review` to investigate blast radius.

**Setup (2 lines):** Add to `~/.claude/mcp.json` (Claude Code) or your Cursor MCP settings:

```json
{
  "mcpServers": {
    "guardrail": { "command": "guardrail", "args": ["mcp"] }
  }
}
```

Without a global install: `{ "command": "node", "args": ["/path/to/guardrail_review_engine/dist/cli.js", "mcp"] }`

See [MCP.md](MCP.md) for tool descriptions and AI configuration.

---

## Try it

```bash
guardrail scan mock_project
```

You'll see green findings (logging), yellow findings (deprecated `StripeClient.charge`), and orange findings (the `DROP COLUMN` migration, a public export).

## Tests

```bash
npm test    # builds the extension, runs 47 unit/integration tests + the extension smoke test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
