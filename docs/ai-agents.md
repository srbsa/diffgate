# DiffGate as the guardrail for AI-generated code

Coding agents (Claude Code, Cursor, Copilot, …) now write a large and growing share of
diffs. They are fast and confident — and they hallucinate. The missing piece is a
**deterministic checkpoint** the agent can run on its own work: one that runs offline, gives
the same verdict every time, and doesn't itself need a model to be trusted. That's DiffGate.

The point isn't to *gate* your agent — it's to let your agent **self-check before a human
sees the diff**, so you can hand it more autonomy with less worry. Same deterministic verdict
every time means the agent catches its own footguns before you do, and surfaces what it
changed instead of silently rewriting (the capability protocol tells it to show both the
original and corrected version). A trustworthy self-check is what makes more autonomy safe to grant.

## Two integration points

### 1. MCP server (the agent checks its own work)

`diffgate mcp` exposes the engine as MCP tools so an agent can review code *before*
surfacing it:

```jsonc
// ~/.claude/mcp.json  (or your agent's MCP config)
{ "mcpServers": { "diffgate": { "command": "diffgate", "args": ["mcp"] } } }
```

Tools: `diffgate_capabilities`, `diffgate_analyze`, `diffgate_check_staged`,
`diffgate_deep_review`, `diffgate_explain`, `diffgate_guidelines`, `diffgate_feedback`. See
[`MCP.md`](../MCP.md). The agent calls these, sees the tiered findings, and fixes orange
issues before showing you the diff.

**Call `diffgate_capabilities` first.** DiffGate has three optional layers — core (always),
code graph, and LLM — and not every install has all three. The manifest tells the agent up
front which tools work without erroring, whether blast-radius/taint data is available, and
the autonomy budget it should respect — instead of discovering missing layers via thrown
errors mid-loop:

```jsonc
{
  "graph": { "available": false, "reason": "codegraph-server not found on PATH" },
  "llm":   { "available": true,  "provider": "anthropic" },
  "availableTools": ["diffgate_analyze", "diffgate_check_staged", "…", "diffgate_explain"],
  "unavailableTools": [],
  "agent": { "mode": "advisory", "autoFixFloor": "orange", "maxFixesPerTurn": 3, "escalateAfterTurns": 2, "trustSource": "deterministic" },
  "protocol": ["Loop budget: apply at most 3 DiffGate fixes per turn…", "…"]
}
```

`diffgate_analyze` / `diffgate_check_staged` also embed a compact `_diffgate: { graph, llm,
agentMode }` hint on every response, so the agent always knows the lay of the land.

### 2. `--agent` verdict (scriptable gate)

For agent harnesses and pre-PR automation, `check --agent` emits a compact machine verdict
shaped by the **autonomy ladder** (`gate.agent`):

```bash
diffgate check --agent                 # default: advisory
diffgate check --agent --agent-mode=gated   # legacy: orange blocks
diffgate check --agent --agent-mode=off     # never blocks (pure data)
```

```json
{
  "verdict": "review",
  "mode": "advisory",
  "budget": { "maxFixesPerTurn": 3, "escalateAfterTurns": 2 },
  "counts": { "green": 1, "yellow": 2, "orange": 1 },
  "findings": [
    { "rule": "public-api-change", "tier": "orange", "trust": "confirmed", "rung": "autofix", "file": "src/api.ts", "line": 12, "message": "…" },
    { "rule": "sql-injection", "tier": "orange", "trust": "confirmed", "rung": "block", "file": "src/db.ts", "line": 42, "message": "…" }
  ]
}
```

Each finding carries a **`rung`** that tells the agent how to act, and a deterministic
**`trust`** label so it acts on evidence, not on its own (often miscalibrated) confidence:

| rung | meaning | agent action |
|---|---|---|
| `block` | a hard rule (secret / destructive SQL / injection) or graph-confirmed taint | stop — must be fixed |
| `escalate` | high blast radius confirmed by the code graph | hand to a human with context; don't silently edit callers |
| `autofix` | at/above `autoFixFloor`, in code the agent just wrote | fix, within `maxFixesPerTurn` |
| `advisory` | below the floor (yellow/green) | note it; don't auto-fix |

| trust | meaning |
|---|---|
| `confirmed` | a deterministic signal backs it (taint path, or a non-security pattern/AST rule) |
| `cleared` | the graph proved no taint path — safe |
| `unconfirmed` | no deterministic signal could confirm/deny (an injection pattern with no code graph, or an LLM-derived guideline finding) — flag for a human, don't silently "fix" |

**Why advisory is the default.** Blocking on every `orange` makes agents loop: fix → new
finding → fix → human interrupt. So the default `verdict` is `review` (exit `0`) for
everything except `block`-rung findings — the agent surfaces the diff with notes instead of
grinding. The two genuine hard-stops (the four `blocking` rules and graph-confirmed taint)
still set `verdict: "blocked"` and exit `1`:

```bash
diffgate check --agent || echo "agent: a hard finding must be fixed before opening a PR"
```

Teams that want the old strict gate set `gate.agent.mode: "gated"` (or pass
`--agent-mode=gated`); fully autonomous pipelines can set `"off"`.

### Guideline self-review without an LLM

When no model is configured, `diffgate_guidelines` returns `mode: "host"` — material for the
**calling agent** to judge. That's a self-review, not an independent gate, so the payload is
marked `independent: false, advisory: true`: surface what you find, never block on it. With a
model configured (`evaluator: "model"`), an independent provider evaluates the diff instead.

## Why deterministic matters here

An AI reviewer checking AI-generated code stacks one probabilistic judgment on another —
and inherits the noise the [benchmark](../BENCHMARK.md) is built to expose. DiffGate's core
is rule-based: same input, same verdict, no API key, nothing leaves the machine. It's the
trustable floor under the agent, not another opinion on top of it.
