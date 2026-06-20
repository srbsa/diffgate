# DiffGate as the guardrail for AI-generated code

Coding agents (Claude Code, Cursor, Copilot, …) now write a large and growing share of
diffs. They are fast and confident — and they hallucinate. The missing piece is a
**deterministic checkpoint** between "the agent wrote code" and "a human sees it": a gate
that runs offline, gives the same verdict every time, and doesn't itself need a model to be
trusted. That's DiffGate.

## Two integration points

### 1. MCP server (the agent checks its own work)

`diffgate mcp` exposes the engine as MCP tools so an agent can review code *before*
surfacing it:

```jsonc
// ~/.claude/mcp.json  (or your agent's MCP config)
{ "mcpServers": { "diffgate": { "command": "diffgate", "args": ["mcp"] } } }
```

Tools: `diffgate_analyze`, `diffgate_check_staged`, `diffgate_deep_review`,
`diffgate_explain`. See [`MCP.md`](../MCP.md). The agent calls these, sees the tiered
findings, and fixes orange issues before showing you the diff.

### 2. `--agent` verdict (scriptable gate)

For agent harnesses and pre-PR automation, `check --agent` emits a compact machine verdict:

```bash
diffgate check --agent
```

```json
{
  "verdict": "blocked",
  "counts": { "green": 1, "yellow": 2, "orange": 1 },
  "findings": [
    { "rule": "sql-injection", "tier": "orange", "file": "src/db.ts", "line": 42, "message": "…" }
  ]
}
```

Exit code is `1` when `verdict` is `blocked`, so it drops into any agent loop:

```bash
diffgate check --agent || echo "agent: fix the orange findings before opening a PR"
```

## Why deterministic matters here

An AI reviewer checking AI-generated code stacks one probabilistic judgment on another —
and inherits the noise the [benchmark](../BENCHMARK.md) is built to expose. DiffGate's core
is rule-based: same input, same verdict, no API key, nothing leaves the machine. It's the
trustable floor under the agent, not another opinion on top of it.
