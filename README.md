# DiffGate

**A deterministic second pair of eyes for AI-generated code: in your agent, your editor, your terminal.**

The model that wrote the code has the same blind spots reviewing it. DiffGate is a separate, deterministic check that runs on **only the lines that changed** (vs the committed baseline) and sorts each change into one of three risk tiers, so trivial edits fly through and high-impact ones get gated. No model grading its own homework, no whole-file noise.

| Tier | Meaning | What you do | Examples |
|------|---------|-------------|----------|
| 🟢 **Green** | Safe / self-contained | merge freely | comments, local logging |
| 🟡 **Yellow** | Review (soft dependency) | take a look | deprecated APIs, raw SQL, network calls, dependency edits |
| 🟠 **Orange** | High-impact, gate it | verify before merge | schema/migrations, hardcoded secrets, auth/crypto, public-API changes, injection sinks |

### What it catches that the model misses

Modern coding agents already avoid the textbook bugs (SQL injection, XSS, hardcoded secrets) unprompted. What they still ship are **second-order footguns**: an unguarded recursive merge (prototype pollution), a bare `cors()` (any-origin by default), a file read with no path-containment check. They drop these guards **most when editing existing code**, which is most of what an agent does.

We measured this: across local-to-frontier models, textbook OWASP issues were introduced **0% of the time**, but the proto-pollution and CORS footguns showed up, and a frontier model that wrote **zero** issues from scratch reintroduced them **when editing a file** (0% → 13%). DiffGate is tuned to exactly that residue. See [the measurement](docs/MEASUREMENT.md).

---

## Quick start

```bash
npm install -g diffgate-review
cd your-repo
diffgate init          # auto-detects language + test command, writes .diffgate.json
diffgate check         # review your pending changes right now
```

No uncommitted changes yet? See the output on bundled examples first:

```bash
diffgate init --demo   # live scan, no config or git changes needed
```

---

## The three surfaces (one shared engine)

### 1. In your coding agent (via MCP)

The highest-leverage spot: the agent **self-checks generated code before it's written to disk**, gets back structured findings (zero LLM tokens), and surfaces what it corrected (original + fix + why) instead of silently rewriting. A trustworthy, deterministic self-check is what makes it safe to grant the agent more autonomy.

```bash
# Claude Code — one command:
claude mcp add diffgate -- diffgate mcp

# One-click via Smithery (zero config):
npx @smithery/cli install diffgate-review --client claude

# Cursor — add to MCP settings:
# { "diffgate": { "command": "diffgate", "args": ["mcp"] } }
```

Or one-click in Claude Desktop: download [`diffgate.mcpb`](https://github.com/srbsa/diffgate/releases/latest) and open it. The server also exposes **prompts** and **resources**; see [MCP.md](MCP.md).

### 2. In your editor (VS Code / Cursor)

Inline squiggles on changed lines, hover cards (why · who owns it · quick-fix), a Risk Review tree, a status-bar summary, and **Deep Review** (agentic blast-radius analysis for orange findings). The same verdict you'd get from the CLI, on the diff you're reviewing.

Install from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=srbsa.diffgate-review) or [Open VSX](https://open-vsx.org/extension/srbsa/diffgate-review) (Cursor / Windsurf / Gitpod).

### 3. On the command line

`diffgate check` reviews your diff and exits non-zero on high-impact findings.

```bash
diffgate install-hook  # adds .git/hooks/pre-commit; only runs tests on 🟠 orange changes
```

The hook is fast because it's selective: green and yellow changes pass instantly; tests only run when a change is genuinely high-impact.

**Common commands:**

```bash
diffgate check                 # review pending changes (the gate)
diffgate check --staged        # staged-only (pre-commit)
diffgate check --agent         # machine verdict for coding agents
diffgate scan <path>           # analyze files directly (no git needed)
diffgate watch                 # live review as you edit
diffgate guidelines            # review diff against AGENTS.md / CLAUDE.md etc.
diffgate feedback <rule> <f> <l> --dismiss   # suppress a false positive (shared via git)
diffgate mcp                   # start the MCP stdio server
```

Run `diffgate --help` for the full list (`report`, `bench`, `stats`, `graph`, `marginal`, …).

---

## How it works

- **Diff-aware:** `git diff` (CLI) or an in-memory LCS diff (editor, accurate on unsaved buffers) finds changed lines; findings only report on those lines.
- **Real AST for JS/TS:** `@babel/parser` powers precise rules: deprecated calls aren't matched inside comments or strings; exported-signature changes are detected structurally.
- **Comment-aware pattern rules:** secrets, SQL/schema changes, auth/crypto, dynamic execution, and injection sinks detected across Python, Go, Java, Ruby, and any text. Commented-out code (`# os.system(x)`) isn't flagged; a secret committed *inside* a comment still is.
- **Real gate:** on a high-impact change, DiffGate runs your `testCommand` and shows the actual exit code and output.
- **Low noise, provably:** `diffgate bench` runs a versioned corpus offline: **100% precision / 0 false blocks** on clean changes. Reproduce it yourself; that's the point of shipping the corpus. See [BENCHMARK.md](BENCHMARK.md).
- **Learnings:** `diffgate feedback` records dismiss/confirm verdicts; dismissed findings (same rule + same code) are suppressed everywhere. Stored in `.diffgate/learnings.json`; commit it to share across the team.
- **Optional add-ons:** a provider-agnostic AI layer (plain-English explanations + fixes) and a cross-file blast-radius pass via an optional code graph. Both are off by default and degrade gracefully.

Engine layout: [`src/core`](src/core) (shared) · [`src/cli.ts`](src/cli.ts) (CLI) · [`src/mcp.ts`](src/mcp.ts) (MCP) · [`extension/`](extension) (VS Code).

---

## Configuration

`diffgate init` writes a tailored `.diffgate.json` at your repo root. Minimal example:

```jsonc
{
  "testCommand": "npm test",          // run for orange changes (the gate)
  "gate": { "mode": "working", "failOn": "orange" },
  "deprecated": [
    { "pattern": "StripeClient.charge", "replacedBy": "StripeClient.createPaymentIntent" }
  ]
}
```

Full schema, the built-in rule table, LLM providers, and per-rule tuning: **[docs/CONFIG.md](docs/CONFIG.md)**.

---

## More

- **[docs/CONFIG.md](docs/CONFIG.md):** full `.diffgate.json` schema, all built-in rules, LLM providers, native precision & test-scope behavior.
- **[docs/TEAM.md](docs/TEAM.md):** rolling DiffGate out to a team (GitHub Action / PR gate, shared learnings, org-wide policy packs, SOC 2 evidence, metrics for leaders).
- **[docs/CODE-GRAPH.md](docs/CODE-GRAPH.md):** optional cross-file blast radius (caller counts, suggested reviewers, test gaps, taint analysis).
- **[docs/MEASUREMENT.md](docs/MEASUREMENT.md):** what agents actually ship unprompted and how to reproduce it (`diffgate marginal`).
- **[MCP.md](MCP.md):** MCP tools, prompts, resources, and AI configuration.

---

## Try it

```bash
diffgate scan mock_project
```

You'll see green findings (logging), yellow findings (a deprecated call), and orange findings (a `DROP COLUMN` migration, a public export).

## Tests

```bash
npm test    # builds the extension, runs the full unit/integration suite + extension smoke test
```

## Contributing & License

See [CONTRIBUTING.md](CONTRIBUTING.md). Apache 2.0; see [LICENSE](LICENSE).
