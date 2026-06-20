# DiffGate MCP Server

Expose the diffgate engine to any coding agent that supports MCP (Claude Code, Cursor, Continue, etc.).

## Quick start

```bash
npm install -g .          # or: npm link
diffgate mcp             # starts the stdio server; clients launch it for you
```

## Register with Claude Code

Add to `~/.claude/mcp.json` (global) or `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "diffgate": {
      "command": "diffgate",
      "args": ["mcp"]
    }
  }
}
```

Or if not globally installed, use `node` directly:

```json
{
  "mcpServers": {
    "diffgate": {
      "command": "node",
      "args": ["/absolute/path/to/diffgate/dist/cli.js", "mcp"]
    }
  }
}
```

Restart Claude Code. You'll see "diffgate" in the MCP tools list.

## Register with Cursor

In Cursor Settings → MCP, add:

```json
{
  "diffgate": {
    "command": "diffgate",
    "args": ["mcp"]
  }
}
```

## Tools exposed

| Tool | When to use |
|---|---|
| `diffgate_analyze` | After writing/modifying a file — check it for risk before suggesting it to the user |
| `diffgate_check_staged` | Before committing — scan all pending changes across the repo |
| `diffgate_deep_review` | When `diffgate_analyze` returns an orange finding — investigate blast radius |
| `diffgate_explain` | Get a concise explanation of any yellow/orange finding |
| `diffgate_guidelines` | Check the diff against the repo's AGENTS.md/CLAUDE.md coding guidelines |
| `diffgate_feedback` | Record a dismiss or confirm verdict on a finding (updates learnings) |

### diffgate_analyze

```json
{
  "filePath": "src/payments.js",
  "content": "...file content...",  // optional: omit to read from disk
  "cwd": "/path/to/repo"            // optional: defaults to cwd
}
```

Returns a structured analysis result. Key fields:
- `findings[]` — list of findings, each with `{ ruleId, tier, title, message, line, fix? }`
- `tier` — overall tier: `"green"` | `"yellow"` | `"orange"`
- `blocking` — true if any finding should block a commit

When a code graph is available, public-surface findings also carry:
- `impact` — `{ callerCount, reviewers[], testGaps[], reachable, complexity?, staleDoc? }` — cross-file blast radius
- `tierAdjusted` — `"escalated"` (has callers) or `"deescalated"` (nobody calls it)
- `editContext` — on the highest-blast finding only: `{ callers[], tests[], history[] }` from `get_edit_context`, so you can update the call sites in the same turn **before writing the code to disk**
- `security` — on injection-class findings when a Pro taint graph is present: `{ tainted, dataFlow[] }`. `tainted: true` means user input reaches the sink (source → … → sink in `dataFlow`) — **do not ship it**.

If a finding is `escalated` with a high `callerCount`, **fix it before surfacing the code** — the change breaks existing call sites. Use `editContext.callers` to find them and `editContext.tests` to update coverage.

### diffgate_check_staged

```json
{ "cwd": "/path/to/repo", "mode": "working" }
```

Returns `{ files[], tier, counts, blocking }` across all changed files.

### diffgate_deep_review

Requires `ai.enabled: true` in `.diffgate.json` and an API key.

```json
{
  "finding": { "tier": "orange", "ruleId": "signature-drift", "title": "...", "message": "...", "code": "..." },
  "filePath": "src/payments.js",
  "snippet": "export function processPayment(amount, currency) { ... }",
  "language": "javascript",
  "cwd": "/path/to/repo"
}
```

Returns `{ verdict, why, fix, steps, transcript, model, hitMax }`.

### diffgate_explain

```json
{
  "finding": { ... },
  "snippet": "...",
  "language": "javascript",
  "cwd": "/path/to/repo"
}
```

Returns `{ text, model }`.

### diffgate_guidelines

Reviews the diff against the repo's own coding-guideline files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, etc.).

```json
{ "cwd": "/path/to/repo", "mode": "working" }
```

**Host mode (default when no provider is configured):** returns `{ mode: "host", groups: [...] }` where each group contains the guideline text and the relevant diff hunks. **When you receive this, evaluate the hunks against the guidelines yourself and surface any violations as findings.** This costs zero tokens on DiffGate's side — you use your own model and credits.

**Model mode:** DiffGate calls the configured provider and returns `{ mode: "model", findings: [...] }` directly.

Findings are `{ ruleId, tier, title, message, file, line }` at most `yellow` tier by default (configurable via `guidelines.tier` and `guidelines.blocking` in `.diffgate.json`).

### diffgate_feedback

Records a dismiss or confirm verdict on a finding. Dismissed findings (same `ruleId` + same code, matched by hash) are suppressed in all future `analyze`, `check_staged`, and `guidelines` calls.

```json
{
  "ruleId": "no-process-env",
  "file": "src/config.ts",
  "line": 42,
  "code": "const key = process.env.STRIPE_KEY",
  "verdict": "dismiss",    // "dismiss" | "confirm"
  "note": "This module is the approved escape hatch."
}
```

Returns `{ ok: true }`. Stored in `.diffgate/learnings.json` in the repo — commit it to share across the team. Latest verdict wins; calling feedback again with `"confirm"` un-dismisses a previously dismissed finding.

## AI configuration

For `diffgate_deep_review` and `diffgate_explain`, the agent uses the AI provider
configured in `.diffgate.json`. Add to your project config:

```json
{
  "ai": {
    "enabled": true,
    "provider": "anthropic",
    "model": "claude-sonnet-4-6",
    "deepReview": {
      "model": "claude-opus-4-8"
    }
  }
}
```

Local providers (LM Studio, Ollama) need no API key.

## Is this circular when used inside Claude Code?

No. The two model invocations have different roles:

- **Outer agent (Claude Code)**: writes code, answers your questions, orchestrates tasks.
- **DiffGate MCP tool**: runs deterministic rules (no LLM) for `diffgate_analyze` and `diffgate_check_staged`; uses a focused security-review system prompt and specialized git/grep tools for `diffgate_deep_review`; returns structured guideline payloads for `diffgate_guidelines` in host mode (you judge, zero DiffGate LLM spend).

The outer agent delegates "is this safe to ship?" to a specialist. The deterministic tools cost zero LLM tokens — the outer agent just gets structured risk findings back.
