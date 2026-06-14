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
- **DiffGate MCP tool**: runs deterministic rules (no LLM) for `diffgate_analyze` and `diffgate_check_staged`; uses a *focused* security-review system prompt and specialized git/grep tools for `diffgate_deep_review`.

The outer agent delegates "is this safe to ship?" to a specialist. The deterministic tools cost zero LLM tokens — the outer agent just gets structured risk findings back.
