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
diffgate check --pr                 # CI: post a PR review + commit status (gates merge)
diffgate check --agent              # compact JSON verdict for coding agents (pass/blocked)
diffgate watch                      # live review as you edit
diffgate report                     # review metrics: tiers, hotspots, learnings
diffgate report --compliance        # SOC 2 control evidence for the diff
diffgate bench                      # noise benchmark (precision/recall/false-blocks)
diffgate guidelines                 # review diff against your repo's AGENTS.md/CLAUDE.md etc.
diffgate feedback <ruleId> <f> <l>  # record a dismiss/confirm verdict on a finding
diffgate init                       # write a tailored .diffgate.json (auto-detects test cmd/langs)
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
- **Deep Review** — for orange findings, an agentic loop (grep, read_file, find_references, git_blame) investigates blast radius and returns a `confirmed-risk / likely-safe / needs-human` verdict.
- **Guideline review** — reviews the diff against your repo's own `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and similar files. Per-directory scoping; the nearest file wins. No extra API key needed in host mode — the calling agent does the judgment.
- **Learnings** — `diffgate feedback` records dismiss/confirm verdicts. Dismissed findings (same rule + same code) are suppressed in all future reviews. Stored in `.diffgate/learnings.json` — commit it to share across the team.

Engine layout: [`src/core`](src/core) (shared) · [`src/cli.ts`](src/cli.ts) (CLI) · [`src/mcp.ts`](src/mcp.ts) (MCP server) · [`extension/`](extension) (VS Code). Tests: [`test/`](test) and [`extension/test/smoke.cjs`](extension/test/smoke.cjs).

---

## Team adoption

DiffGate is built around one thesis: a reviewer earns trust by being **quiet and
deterministic**, then spreads by living where review actually happens — the pull request.

- **PR-native review** — `diffgate check --pr` posts inline review comments + a `diffgate`
  commit status on the PR; orange findings fail the check. Make it a required check and
  it's a merge gate, not another comment to scroll past. Drop-in
  [GitHub Action](.github/workflows/diffgate.yml) + [App scaffold](docs/github-app.md).
- **Provable low noise** — `diffgate bench` scores precision/recall and, the metric that
  predicts adoption, **false blocks per clean change** (target: 0). Corpus is versioned and
  offline so anyone can reproduce it. See [BENCHMARK.md](BENCHMARK.md).
- **Org-wide policy packs** — `extends` lets repos inherit a shared `.diffgate.json` (a
  path or an npm package); `learnings.shared` merges dismiss/confirm verdicts across repos
  so noise suppression is org-wide. Local config/verdicts always win.
- **Metrics for leaders** — `diffgate report` summarizes tiers, hotspot files, and the
  noise-reduction loop; `--compliance` emits SOC 2 control evidence ([COMPLIANCE.md](COMPLIANCE.md)).
- **Guardrail for AI agents** — the deterministic core is the trustable checkpoint between
  agent-written code and a human. Use the MCP server or `check --agent`. See
  [docs/ai-agents.md](docs/ai-agents.md).

---

## Configuration — `.diffgate.json`

Place it at your repo root (`diffgate init` generates one). See [example.diffgate.json](example.diffgate.json) for the full schema.

```jsonc
{
  "extends": ["@acme/diffgate-policy"],       // inherit org-wide policy packs (base-first; local wins)
  "testCommand": "npm test",                 // run for orange changes (the gate)
  "gate": { "mode": "working", "failOn": "orange" },
  "learnings": { "shared": ["../shared-policy"] }, // merge dismiss/confirm verdicts across repos
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
npm test    # builds the extension, runs 71 unit/integration tests + the extension smoke test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
