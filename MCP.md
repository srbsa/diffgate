# Guardrail MCP Server

Expose the guardrail engine to any coding agent that supports MCP (Claude Code, Cursor, Continue, etc.).

## Quick start

```bash
npm install -g .          # or: npm link
guardrail mcp             # starts the stdio server; clients launch it for you
```

## Register with Claude Code

Add to `~/.claude/mcp.json` (global) or `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "guardrail",
      "args": ["mcp"]
    }
  }
}
```

Or if not globally installed, use `node` directly:

```json
{
  "mcpServers": {
    "guardrail": {
      "command": "node",
      "args": ["/absolute/path/to/guardrail_review_engine/src/cli.js", "mcp"]
    }
  }
}
```

Restart Claude Code. You'll see "guardrail" in the MCP tools list.

## Register with Cursor

In Cursor Settings → MCP, add:

```json
{
  "guardrail": {
    "command": "guardrail",
    "args": ["mcp"]
  }
}
```

## Tools exposed

| Tool | When to use |
|---|---|
| `guardrail_analyze` | After writing/modifying a file — check it for risk before suggesting it to the user |
| `guardrail_check_staged` | Before committing — scan all pending changes across the repo |
| `guardrail_deep_review` | When `guardrail_analyze` returns an orange finding — investigate blast radius |
| `guardrail_explain` | Get a concise explanation of any yellow/orange finding |

### guardrail_analyze

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

### guardrail_check_staged

```json
{ "cwd": "/path/to/repo", "mode": "working" }
```

Returns `{ files[], tier, counts, blocking }` across all changed files.

### guardrail_deep_review

Requires `ai.enabled: true` in `.guardrails.json` and an API key.

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

### guardrail_explain

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

For `guardrail_deep_review` and `guardrail_explain`, the agent uses the AI provider
configured in `.guardrails.json`. Add to your project config:

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
- **Guardrail MCP tool**: runs deterministic rules (no LLM) for `guardrail_analyze` and `guardrail_check_staged`; uses a *focused* security-review system prompt and specialized git/grep tools for `guardrail_deep_review`.

The outer agent delegates "is this safe to ship?" to a specialist. The deterministic tools cost zero LLM tokens — the outer agent just gets structured risk findings back.
