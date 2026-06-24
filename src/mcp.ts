import fs from "fs";
import path from "path";
import type { Readable, Writable } from "stream";
import {
  analyze,
  loadConfig,
  isGitRepo,
  getPreviousContent,
  computeChangedLines,
  getChangedLinesForFile,
  reviewChanges,
  explainFinding,
  isAiAvailable,
  deepReview,
  reviewGuidelines,
  repoRoot,
  loadLearnings,
  applyLearnings,
  recordLearning,
  getGraph,
  attachImpact,
  attachSecurity,
  labelTrust,
  resolveGraphConfig,
  buildCapabilities,
  capabilityHint,
  recordTurn,
  findingFingerprint,
  ruleCatalog,
} from "./core/index.js";
import type { Capabilities } from "./core/index.js";
import type { Finding, Config, FetchFn } from "./core/types.js";
import { agentVerdict } from "./metrics.js";

declare const __DIFFGATE_VERSION__: string;
const VERSION = typeof __DIFFGATE_VERSION__ !== "undefined" ? __DIFFGATE_VERSION__ : "0.0.0";

// One MCP server process == one agent session. This id keys the budget ledger so we can count how
// many gate checks a finding has survived this session — the one place DiffGate can honestly give
// the agent the external "stop re-fixing, escalate" signal it cannot enforce statelessly per call.
const MCP_SESSION = `mcp:${process.pid}:${Date.now()}`;

// Protocol versions we can speak. Per the spec, on `initialize` the server echoes the client's
// requested version if it supports it, otherwise replies with its own preferred (latest) version.
const SUPPORTED_PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const PREFERRED_PROTOCOL = "2025-06-18";

export function negotiateProtocol(requested: unknown): string {
  return typeof requested === "string" && SUPPORTED_PROTOCOLS.includes(requested)
    ? requested
    : PREFERRED_PROTOCOL;
}

// A JSON-RPC error carrying a protocol error `code` (e.g. -32602 invalid params, -32002 resource
// not found). Thrown by prompt/resource handlers and surfaced as a proper JSON-RPC `error` object.
export class RpcError extends Error {
  constructor(public code: number, message: string, public data?: unknown) {
    super(message);
    this.name = "RpcError";
  }
}

const SEP = Buffer.from("\r\n\r\n");

// The MCP stdio transport is newline-delimited JSON: "Messages are delimited by newlines, and MUST
// NOT contain embedded newlines" (modelcontextprotocol.io/specification → Transports → stdio). We
// emit that. We still *read* the legacy LSP-style `Content-Length:` framing too, so older Claude
// Code builds (and any lenient client) keep working — the reader auto-detects per message.
export function createReader(stream: Readable): { onMessage: (fn: (msg: unknown) => void) => void } {
  let buf = Buffer.alloc(0);
  const listeners: Array<(msg: unknown) => void> = [];
  const emit = (text: string) => {
    const t = text.trim();
    if (!t) return;
    let msg: unknown;
    try { msg = JSON.parse(t); } catch { return; }
    for (const fn of listeners) fn(msg);
  };
  stream.on("data", (chunk: Buffer | string) => {
    buf = Buffer.concat([buf, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    while (buf.length > 0) {
      // Skip blank-line separators between newline-delimited messages.
      let start = 0;
      while (start < buf.length && (buf[start] === 0x0a || buf[start] === 0x0d)) start++;
      if (start > 0) { buf = buf.slice(start); continue; }

      // Legacy Content-Length framing (LSP-style) — kept for backward compatibility.
      if (buf.slice(0, 15).toString("ascii").toLowerCase().startsWith("content-length:")) {
        const sepIdx = buf.indexOf(SEP);
        if (sepIdx === -1) break; // header not fully arrived yet
        const header = buf.slice(0, sepIdx).toString("ascii");
        const m = header.match(/Content-Length:\s*(\d+)/i);
        if (!m) { buf = buf.slice(sepIdx + 4); continue; }
        const len = parseInt(m[1], 10);
        const bodyStart = sepIdx + 4;
        if (buf.length < bodyStart + len) break; // body not fully arrived yet
        emit(buf.slice(bodyStart, bodyStart + len).toString("utf-8"));
        buf = buf.slice(bodyStart + len);
        continue;
      }

      // Spec path: one JSON message per line.
      const nl = buf.indexOf(0x0a);
      if (nl === -1) break; // message not yet terminated
      emit(buf.slice(0, nl).toString("utf-8"));
      buf = buf.slice(nl + 1);
    }
  });
  return { onMessage: (fn) => listeners.push(fn) };
}

export function createWriter(stream: Writable): (obj: unknown) => void {
  return function send(obj: unknown) {
    // Newline-delimited per the MCP stdio spec. JSON.stringify (no indent) never embeds a newline.
    stream.write(JSON.stringify(obj) + "\n");
  };
}

export const TOOL_DEFS = [
  {
    name: "diffgate_analyze",
    description:
      "Analyze a file for code review findings. Only flags risk on lines changed vs the git baseline (diff-aware). " +
      "Pass `content` to analyze unsaved or generated code before it is written to disk. " +
      "When a code graph is available, public-surface findings carry an `impact` field (caller count, suggested " +
      "reviewers, test gaps) and may be tier-adjusted — fix high-blast-radius findings before surfacing the code.",
    inputSchema: {
      type: "object",
      properties: {
        filePath: { type: "string", description: "Absolute or repo-relative path to the file." },
        content: { type: "string", description: "File content to analyze. Omit to read from disk." },
        cwd: { type: "string", description: "Repo root directory. Defaults to process.cwd()." },
      },
      required: ["filePath"],
    },
  },
  {
    name: "diffgate_check_staged",
    description:
      "Check all staged (or working-tree) changes in a git repo for DiffGate findings. " +
      "Returns overall tier, counts, and per-file findings across the whole diff, plus a `verdict` block " +
      "(the agent autonomy ladder: pass/review/blocked overall, with a rung — block/escalate/autofix/advisory — " +
      "per finding) so you can decide whether to surface the diff without reimplementing the rules.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string", description: "Repo root. Defaults to process.cwd()." },
        mode: { type: "string", enum: ["staged", "working"], description: "Check staged-only or all working-tree changes. Default: working." },
      },
    },
  },
  {
    name: "diffgate_deep_review",
    description:
      "Run an agentic deep review on a single high-impact (orange) finding. " +
      "The model uses real repo tools (grep, read_file, find_references, git_blame) to investigate blast radius before rendering a verdict.",
    inputSchema: {
      type: "object",
      properties: {
        finding: { type: "object", description: "A finding object from diffgate_analyze." },
        filePath: { type: "string", description: "Repo-relative path of the file containing the finding." },
        snippet: { type: "string", description: "Code snippet around the finding." },
        language: { type: "string", description: "Language id (javascript, python, go, etc.)." },
        cwd: { type: "string", description: "Repo root. Defaults to process.cwd()." },
      },
      required: ["finding", "filePath", "cwd"],
    },
  },
  {
    name: "diffgate_explain",
    description:
      "Get a concise AI explanation for a DiffGate finding. " +
      "Faster than diffgate_deep_review — a single LLM call with no tool loops.",
    inputSchema: {
      type: "object",
      properties: {
        finding: { type: "object", description: "A finding object from diffgate_analyze." },
        snippet: { type: "string", description: "Code snippet around the finding." },
        language: { type: "string", description: "Language id." },
        cwd: { type: "string", description: "Repo root. Defaults to process.cwd()." },
      },
      required: ["finding", "cwd"],
    },
  },
  {
    name: "diffgate_capabilities",
    description:
      "Report which DiffGate layers are active (core / code graph / LLM), which tools you can call right now " +
      "without an error, and the agent autonomy budget (fix limit, escalation, trust source). Call this once up " +
      "front so you know what's available instead of discovering it via thrown errors.",
    inputSchema: {
      type: "object",
      properties: { cwd: { type: "string", description: "Repo root. Defaults to process.cwd()." } },
    },
  },
  {
    name: "diffgate_guidelines",
    description:
      "Review the diff against the repo's own coding guideline files (AGENTS.md, CLAUDE.md, .cursorrules, etc.), " +
      "scoped per directory (nearest file wins). " +
      "IMPORTANT: if the result has mode='host', NO external model was used — this is a SELF-REVIEW, not an " +
      "independent gate: YOU (the calling agent) evaluate each group's `hunks` against its `guidelines` text using " +
      "your own model. Treat host-mode results as ADVISORY only — never block the change on them. " +
      "If mode='model', findings were produced by the configured provider and are returned directly.",
    inputSchema: {
      type: "object",
      properties: {
        cwd: { type: "string", description: "Repo root. Defaults to process.cwd()." },
        mode: { type: "string", enum: ["staged", "working"], description: "Diff scope. Default: working." },
      },
    },
  },
  {
    name: "diffgate_feedback",
    description:
      "Record a reviewer's verdict on a finding so DiffGate learns. verdict 'dismiss' suppresses that same flagged " +
      "code (ruleId + code) in future reviews (noise reduction); 'confirm' marks it as a real, valued catch. " +
      "Stored in .diffgate/learnings.json at the repo root.",
    inputSchema: {
      type: "object",
      properties: {
        ruleId: { type: "string", description: "The finding's ruleId." },
        code: { type: "string", description: "The flagged code (finding.code)." },
        verdict: { type: "string", enum: ["dismiss", "confirm"], description: "dismiss = noise/false-positive; confirm = real issue." },
        note: { type: "string", description: "Optional reviewer note (why)." },
        file: { type: "string", description: "Optional repo-relative file path for context." },
        cwd: { type: "string", description: "Repo root. Defaults to process.cwd()." },
      },
      required: ["ruleId", "code", "verdict"],
    },
  },
];

// ---------------------------------------------------------------------------------------------
// Prompts — user-invocable playbooks (MCP `prompts/*`). These encode the autonomy ladder so an
// agent triages findings the same way every time instead of over-escalating to a human or looping.
// ---------------------------------------------------------------------------------------------

export const PROMPT_DEFS = [
  {
    name: "review-workflow",
    title: "DiffGate self-review workflow",
    description:
      "The end-to-end self-check to run before surfacing a diff: capabilities → analyze → triage each " +
      "finding by its rung → escalate or dismiss. Use at the start of a coding task so the human only " +
      "sees what needs their judgment.",
    arguments: [
      { name: "mode", description: "Diff scope for check_staged: 'staged' or 'working'. Default working.", required: false },
    ],
  },
  {
    name: "triage-finding",
    title: "Triage one DiffGate finding",
    description:
      "Decide what to do with a single finding from its tier/trust/rung — without over-escalating to a " +
      "human or silently rewriting correct code. Pass the finding's fields.",
    arguments: [
      { name: "ruleId", description: "The finding's ruleId.", required: false },
      { name: "tier", description: "green | yellow | orange.", required: false },
      { name: "trust", description: "confirmed | unconfirmed | cleared.", required: false },
      { name: "rung", description: "block | escalate | autofix | advisory (from the verdict block).", required: false },
    ],
  },
  {
    name: "setup-diffgate",
    title: "Configure DiffGate for this repo",
    description:
      "Write a .diffgate.json and wire the gate (pre-commit hook, MCP, optional AI) with low-noise " +
      "defaults so the team is not flooded with advisory findings.",
    arguments: [
      { name: "aiProvider", description: "Optional: anthropic | openai | local — include AI config for explain/deep-review.", required: false },
    ],
  },
];

function capsFor(cwd: string): Capabilities {
  const { config } = loadConfig(cwd);
  return buildCapabilities(config, VERSION);
}

function promptReviewWorkflow(caps: Capabilities, mode: string): string {
  const a = caps.agent;
  const lines = [
    "Before surfacing code changes for human review, run DiffGate's self-check so the human only sees what needs their judgment.",
    "",
    `Repo: graph=${caps.graph.available}, llm=${caps.llm.available}, agentMode=${a.mode}. ` +
      `Budget: maxFixesPerTurn=${a.maxFixesPerTurn}, escalateAfterTurns=${a.escalateAfterTurns}, autoFixFloor=${a.autoFixFloor}.`,
    "",
    "Steps:",
    "1. Call diffgate_capabilities once to confirm which tools work and your autonomy budget.",
    "2. After writing/editing a file, call diffgate_analyze (pass `content` for unsaved/generated code) — it only flags lines you changed vs the git baseline.",
    `3. Before committing, call diffgate_check_staged{mode:"${mode}"} for the repo-wide verdict and the per-finding rung.`,
    "4. Act on each finding by its rung (see the triage-finding prompt):",
    "   - block    → a hard rule or graph-confirmed taint. Fix it or stop; never surface as-is.",
    "   - escalate → high blast radius, or it outlived your budget. Hand to the human with context; do NOT keep re-fixing.",
    "   - autofix  → tier at/above the floor in code you just wrote. Fix it, then SHOW the human before/after.",
    "   - advisory → a note. Surface it; don't block.",
    `5. False positive? Call diffgate_feedback{verdict:"dismiss", note:"why"} instead of editing correct code — it suppresses that exact flag for the whole team. A real catch worth keeping? feedback{verdict:"confirm"}.`,
    `6. Do NOT loop: cap at ${a.maxFixesPerTurn} DiffGate-driven fixes this turn. If a fix creates a new finding, STOP and report.`,
  ];
  lines.push("", "Protocol for this repo:");
  for (const p of caps.protocol) lines.push(`- ${p}`);
  return lines.join("\n");
}

function promptTriageFinding(args: { ruleId?: string; tier?: string; trust?: string; rung?: string }): string {
  const { ruleId = "(unknown)", tier = "(unknown)", trust = "(unknown)", rung = "(unknown)" } = args;
  const rungGuide: Record<string, string> = {
    block: "BLOCK — a hard rule (secret, destructive SQL, injection) or graph-confirmed taint. Fix it before surfacing the diff, or stop and report. Never present this code as ready.",
    escalate: "ESCALATE — high blast radius, or it survived your fix budget. Hand it to the human with context (callers, why). Do NOT keep re-fixing it.",
    autofix: "AUTOFIX — at/above the auto-fix floor in code you just wrote. Fix it, then show the human BOTH the original and corrected version and why.",
    advisory: "ADVISORY — informational. Surface it as a note; do not block the change on it.",
  };
  const trustGuide: Record<string, string> = {
    confirmed: "trust=confirmed: a deterministic signal backs this. Treat it as real.",
    cleared: "trust=cleared: a signal disproved it (e.g. the graph found no taint path). Safe to leave.",
    unconfirmed: "trust=unconfirmed: nothing could confirm or deny it. Flag it for a human — do NOT silently 'fix' correct code.",
  };
  return [
    `Finding: ruleId=${ruleId}, tier=${tier}, trust=${trust}, rung=${rung}.`,
    "",
    rungGuide[rung] || "No rung supplied — fetch it from diffgate_check_staged's `verdict.findings[]`.",
    trustGuide[trust] || "No trust supplied — read it from the finding's `trust` field.",
    "",
    "If this is a false positive, do NOT edit the code. Record it so it never re-fires for anyone:",
    `  diffgate_feedback{ ruleId:"${ruleId}", code:"<the flagged line>", verdict:"dismiss", note:"<reason>" }`,
    'If it is a real issue you fixed, mark it valued: diffgate_feedback{ verdict:"confirm" }.',
  ].join("\n");
}

function promptSetupDiffgate(aiProvider?: string): string {
  const ai = aiProvider
    ? `,\n  "ai": { "enabled": true, "provider": "${aiProvider}", "model": "${aiProvider === "anthropic" ? "claude-sonnet-4-6" : aiProvider === "openai" ? "gpt-5.5" : "local-model"}" }`
    : "";
  return [
    "Create `.diffgate.json` at the repo root with low-noise defaults:",
    "",
    "```json",
    "{",
    '  "gate": {',
    '    "failOn": "orange",',
    '    "agent": { "mode": "advisory", "escalateAfterTurns": 2, "maxFixesPerTurn": 3 }',
    `  }${ai}`,
    "}",
    "```",
    "",
    "Then wire the gate:",
    "- `diffgate install-hook` — pre-commit gate; only runs your test suite on 🟠 orange changes.",
    "- `claude mcp add diffgate -- diffgate mcp` — expose the engine to this agent.",
    "",
    "Noise control:",
    "- `mode:\"advisory\"` never hard-blocks on yellow/green — only hard rules and graph-confirmed taint block.",
    "- Commit `.diffgate/learnings.json` so the team shares dismissals (the git merge driver auto-resolves conflicts).",
    aiProvider ? "- AI is optional: diffgate_explain / diffgate_deep_review use it; the deterministic gate does not." : "- No AI configured: diffgate_guidelines runs in host mode (you judge — advisory only).",
  ].join("\n");
}

export function listPrompts(): { prompts: typeof PROMPT_DEFS } {
  return { prompts: PROMPT_DEFS };
}

export function getPrompt(
  name: string,
  args: Record<string, unknown> = {},
  opts: { cwd?: string } = {}
): { description: string; messages: Array<{ role: string; content: { type: string; text: string } }> } {
  const cwd = opts.cwd || process.cwd();
  const def = PROMPT_DEFS.find((p) => p.name === name);
  if (!def) throw new RpcError(-32602, `Unknown prompt: ${name}`);
  let text: string;
  if (name === "review-workflow") {
    const mode = args.mode === "staged" ? "staged" : "working";
    text = promptReviewWorkflow(capsFor(cwd), mode);
  } else if (name === "triage-finding") {
    text = promptTriageFinding(args as Parameters<typeof promptTriageFinding>[0]);
  } else {
    text = promptSetupDiffgate(typeof args.aiProvider === "string" ? args.aiProvider : undefined);
  }
  return { description: def.description, messages: [{ role: "user", content: { type: "text", text } }] };
}

// ---------------------------------------------------------------------------------------------
// Resources — attachable context (MCP `resources/*`). Read-only views of repo-scoped engine state
// so an agent can pre-load the rule catalog / suppressions / budget without a tool round-trip.
// All resources resolve against process.cwd() (the repo the MCP server was launched in), matching
// how the tools default `cwd`.
// ---------------------------------------------------------------------------------------------

export const RESOURCE_DEFS = [
  { uri: "diffgate://capabilities", name: "capabilities", title: "DiffGate capabilities", description: "Active layers (core/graph/llm), callable tools, and the agent autonomy budget for this repo.", mimeType: "application/json" },
  { uri: "diffgate://rules", name: "rules", title: "Active rule catalog", description: "Every rule DiffGate applies in this repo (id, tier, blocking, pack) after config overrides.", mimeType: "application/json" },
  { uri: "diffgate://learnings", name: "learnings", title: "Dismissed / confirmed findings", description: "The team's recorded verdicts — noise suppressions and confirmed catches — from .diffgate/learnings.json.", mimeType: "application/json" },
  { uri: "diffgate://protocol", name: "protocol", title: "Agent autonomy protocol", description: "The trust × rung ladder for acting on findings without over-escalating to a human.", mimeType: "text/markdown" },
];

export const RESOURCE_TEMPLATE_DEFS = [
  { uriTemplate: "diffgate://rules/{ruleId}", name: "rule", title: "Single rule detail", description: "Metadata for one rule by id (e.g. diffgate://rules/hardcoded-secret).", mimeType: "application/json" },
];

function protocolMarkdown(caps: Capabilities): string {
  const a = caps.agent;
  const lines = [
    "# DiffGate agent protocol",
    "",
    `Mode **${a.mode}** · auto-fix floor **${a.autoFixFloor}** · max fixes/turn **${a.maxFixesPerTurn}** · escalate after **${a.escalateAfterTurns}** turns.`,
    "",
    "## Rungs (what to do with a finding)",
    "- **block** — hard rule or graph-confirmed taint. Fix or stop; never surface as-is.",
    "- **escalate** — high blast radius, or it outlived your budget. Hand to a human with context; don't re-fix.",
    "- **autofix** — tier at/above the floor in code you just wrote. Fix, then show before/after.",
    "- **advisory** — a note. Surface, don't block.",
    "",
    "## Trust (how much to believe it)",
    "- **confirmed** — a deterministic signal backs it. Real.",
    "- **cleared** — a signal disproved it (graph found no taint path). Safe.",
    "- **unconfirmed** — nothing could confirm/deny. Flag for a human; don't silently fix.",
    "",
    "## This repo",
  ];
  for (const p of caps.protocol) lines.push(`- ${p}`);
  return lines.join("\n");
}

export function listResources(): { resources: typeof RESOURCE_DEFS } {
  return { resources: RESOURCE_DEFS };
}

export function listResourceTemplates(): { resourceTemplates: typeof RESOURCE_TEMPLATE_DEFS } {
  return { resourceTemplates: RESOURCE_TEMPLATE_DEFS };
}

export function readResource(
  uri: string,
  opts: { cwd?: string } = {}
): { contents: Array<{ uri: string; mimeType: string; text: string }> } {
  const cwd = opts.cwd || process.cwd();
  const json = (val: unknown) => JSON.stringify(val, null, 2);
  const text = (mimeType: string, body: string) => ({ contents: [{ uri, mimeType, text: body }] });

  if (uri === "diffgate://capabilities") return text("application/json", json(capsFor(cwd)));
  if (uri === "diffgate://rules") {
    const { config } = loadConfig(cwd);
    return text("application/json", json(ruleCatalog(config)));
  }
  if (uri === "diffgate://learnings") {
    return text("application/json", json(loadLearnings(repoRoot(cwd) || cwd)));
  }
  if (uri === "diffgate://protocol") return text("text/markdown", protocolMarkdown(capsFor(cwd)));

  const ruleMatch = /^diffgate:\/\/rules\/([^/]+)$/.exec(uri);
  if (ruleMatch) {
    const id = decodeURIComponent(ruleMatch[1]);
    const { config } = loadConfig(cwd);
    const entry = ruleCatalog(config).find((r) => r.id === id);
    if (!entry) throw new RpcError(-32002, `Rule not found: ${id}`, { uri });
    return text("application/json", json(entry));
  }
  throw new RpcError(-32002, `Resource not found: ${uri}`, { uri });
}

export async function handleAnalyze(
  { filePath, content, cwd: cwdArg }: { filePath: string; content?: string; cwd?: string },
  opts: { graph?: Parameters<typeof attachImpact>[1]["graph"] } = {}
) {
  const cwd = cwdArg || process.cwd();
  const absPath = path.isAbsolute(filePath) ? filePath : path.join(cwd, filePath);
  const { config } = loadConfig(cwd);

  let actualContent = content;
  if (actualContent == null) {
    actualContent = fs.readFileSync(absPath, "utf-8");
  }

  let changedLines = null;
  let previousContent = null;
  if (isGitRepo(cwd)) {
    previousContent = getPreviousContent(cwd, absPath, { mode: "working" });
    if (content != null) {
      if (previousContent != null) changedLines = computeChangedLines(previousContent, actualContent);
    } else {
      changedLines = getChangedLinesForFile(cwd, absPath, { mode: "working" });
    }
  }

  const result = applyLearnings(
    analyze({ filePath: absPath, content: actualContent, previousContent, changedLines, config }),
    loadLearnings(repoRoot(cwd) || cwd)
  );
  // Cross-file blast radius + graph-aware security (no-ops when no code graph is available).
  const graph = opts.graph !== undefined ? opts.graph : getGraph(cwd, config);
  let [withImpact] = attachImpact([result], { cwd, config, graph, mode: "working" });
  [withImpact] = attachSecurity([withImpact], { cwd, config, graph });
  [withImpact] = labelTrust([withImpact]);
  // Pre-edit context for the agent: callers/tests/history of the highest-blast finding, so it
  // can fix the call sites before the generated code is ever written to disk.
  if (graph && typeof graph.editContext === "function" && resolveGraphConfig(config).editContext) {
    const target = withImpact.findings.find((f) => f.tierAdjusted === "escalated" && f.symbol);
    if (target) {
      try {
        const ec = graph.editContext({ symbol: target.symbol as string, file: absPath, line: target.line, cwd });
        if (ec) target.editContext = ec;
      } catch {
        /* best-effort */
      }
    }
  }
  return { ...withImpact, _diffgate: capabilityHint(config) };
}

export async function handleCheckStaged({ cwd: cwdArg, mode = "working" }: { cwd?: string; mode?: string } = {}) {
  const cwd = cwdArg || process.cwd();
  const review = reviewChanges(cwd, { mode });
  // Omit `config` from the MCP payload: it bloats the agent context window every call and
  // exposes resolved config (ai.apiKeyEnv, customPatterns, extends paths, …) to the agent.
  const { config, ...rest } = review;
  const out: Record<string, unknown> = { ...rest, _diffgate: capabilityHint(config) };
  // Budget signal: each check_staged is one "turn". When a finding outlasts escalateAfterTurns this
  // session, surface it so the agent escalates to a human instead of looping. Best-effort.
  try {
    const root = repoRoot(cwd) || cwd;
    const agentCfg = config.gate?.agent ?? {};
    const escalateAfterTurns = agentCfg.escalateAfterTurns ?? 2;
    const entries = review.files.flatMap((fr) => fr.findings.map((f) => ({ file: fr.filePath, finding: f })));
    const { overBudget, turns } = recordTurn(root, MCP_SESSION, entries, { escalateAfterTurns });
    // Autonomy verdict: the same compact pass/review/blocked + rung-per-finding shape the CLI emits via
    // `check --agent`, so an agent driving DiffGate over MCP doesn't have to reimplement rungFor(). Thread
    // the same overBudget set (gated on mode like the CLI) so MCP and CLI agree turn-for-turn.
    out.verdict = agentVerdict(review.files, agentCfg, agentCfg.mode !== "off" ? { overBudget } : {});
    if (overBudget.size > 0) {
      out.agentBudget = {
        escalateAfterTurns,
        message: `${overBudget.size} finding(s) have survived ${escalateAfterTurns}+ gate checks this session. Escalate to a human with context instead of re-fixing.`,
        overBudget: review.files.flatMap((fr) =>
          fr.findings
            .filter((f) => overBudget.has(findingFingerprint(fr.filePath, f)))
            .map((f) => ({ rule: f.ruleId, file: fr.filePath, line: f.line, turns: turns.get(findingFingerprint(fr.filePath, f)) }))
        ),
      };
    }
  } catch {
    /* budget is best-effort — never break a check */
  }
  return out;
}

export async function handleCapabilities({ cwd: cwdArg }: { cwd?: string } = {}) {
  const cwd = cwdArg || process.cwd();
  const { config } = loadConfig(cwd);
  return buildCapabilities(config, VERSION);
}

export async function handleDeepReview(
  { finding, filePath, snippet, language, cwd: cwdArg }: {
    finding: Finding;
    filePath: string;
    snippet?: string;
    language?: string;
    cwd: string;
  },
  opts: { config?: Partial<Config>; fetchImpl?: FetchFn } = {}
) {
  const cwd = cwdArg || process.cwd();
  const config = opts.config || loadConfig(cwd).config;
  if (!isAiAvailable(config)) {
    throw new Error("AI is not configured. Set ai.enabled: true and provide an API key in .diffgate.json or the environment.");
  }
  const toolSteps: unknown[] = [];
  const res = await deepReview({
    finding,
    filePath,
    snippet: snippet || finding.code || "",
    language: language || "unknown",
    cwd,
    config,
    onStep: (s) => toolSteps.push(s),
    fetchImpl: opts.fetchImpl,
  });
  return { ...res, toolSteps };
}

export async function handleExplain(
  { finding, snippet, language, cwd: cwdArg }: {
    finding: Finding;
    snippet?: string;
    language?: string;
    cwd: string;
  },
  opts: { config?: Partial<Config>; fetchImpl?: FetchFn } = {}
) {
  const cwd = cwdArg || process.cwd();
  const config = opts.config || loadConfig(cwd).config;
  if (!isAiAvailable(config)) {
    throw new Error("AI is not configured. Set ai.enabled: true and provide an API key in .diffgate.json or the environment.");
  }
  return explainFinding({
    finding,
    snippet: snippet || finding.code || "",
    language: language || "unknown",
    config,
    fetchImpl: opts.fetchImpl,
  });
}

export async function handleGuidelines({ cwd: cwdArg, mode = "working" }: { cwd?: string; mode?: string } = {}) {
  const cwd = cwdArg || process.cwd();
  return reviewGuidelines(cwd, { mode });
}

export async function handleFeedback(
  { ruleId, code, verdict, note, file, cwd: cwdArg }: {
    ruleId: string; code: string; verdict: "dismiss" | "confirm"; note?: string; file?: string; cwd?: string;
  }
) {
  const cwd = cwdArg || process.cwd();
  const entry = recordLearning(repoRoot(cwd) || cwd, { ruleId, code, verdict, note, file });
  return { recorded: entry };
}

const DISPATCH: Record<string, (args: Record<string, unknown>, opts?: unknown) => Promise<unknown>> = {
  diffgate_analyze: (args) => handleAnalyze(args as Parameters<typeof handleAnalyze>[0]),
  diffgate_check_staged: (args) => handleCheckStaged(args as Parameters<typeof handleCheckStaged>[0]),
  diffgate_capabilities: (args) => handleCapabilities(args as Parameters<typeof handleCapabilities>[0]),
  diffgate_deep_review: (args) => handleDeepReview(args as Parameters<typeof handleDeepReview>[0]),
  diffgate_explain: (args) => handleExplain(args as Parameters<typeof handleExplain>[0]),
  diffgate_guidelines: (args) => handleGuidelines(args as Parameters<typeof handleGuidelines>[0]),
  diffgate_feedback: (args) => handleFeedback(args as Parameters<typeof handleFeedback>[0]),
};

export function runMcpServer(): void {
  process.stderr.write("[diffgate mcp] server started\n");
  const send = createWriter(process.stdout as unknown as Writable);
  const reader = createReader(process.stdin as unknown as Readable);

  reader.onMessage(async (msg: unknown) => {
    const { id, method, params } = msg as { id?: unknown; method?: string; params?: { name?: string; arguments?: Record<string, unknown>; protocolVersion?: unknown } };

    if (method === "initialize") {
      const protocolVersion = negotiateProtocol(params?.protocolVersion);
      send({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion,
          capabilities: { tools: {}, prompts: {}, resources: {} },
          serverInfo: { name: "diffgate", version: VERSION },
        },
      });
      return;
    }
    if (method === "initialized" || method === "notifications/initialized") return;
    if (method === "ping") { send({ jsonrpc: "2.0", id, result: {} }); return; }
    if (method === "tools/list") { send({ jsonrpc: "2.0", id, result: { tools: TOOL_DEFS } }); return; }
    if (method === "prompts/list") { send({ jsonrpc: "2.0", id, result: listPrompts() }); return; }
    if (method === "resources/list") { send({ jsonrpc: "2.0", id, result: listResources() }); return; }
    if (method === "resources/templates/list") { send({ jsonrpc: "2.0", id, result: listResourceTemplates() }); return; }

    if (method === "prompts/get") {
      try {
        send({ jsonrpc: "2.0", id, result: getPrompt(params?.name as string, (params?.arguments as Record<string, unknown>) || {}) });
      } catch (e) {
        const code = e instanceof RpcError ? e.code : -32603;
        send({ jsonrpc: "2.0", id, error: { code, message: (e as Error).message, ...(e instanceof RpcError && e.data ? { data: e.data } : {}) } });
      }
      return;
    }

    if (method === "resources/read") {
      try {
        send({ jsonrpc: "2.0", id, result: readResource((params as { uri?: string })?.uri as string) });
      } catch (e) {
        const code = e instanceof RpcError ? e.code : -32603;
        send({ jsonrpc: "2.0", id, error: { code, message: (e as Error).message, ...(e instanceof RpcError && e.data ? { data: e.data } : {}) } });
      }
      return;
    }

    if (method === "tools/call") {
      const { name, arguments: args = {} } = params || {};
      const handler = name ? DISPATCH[name] : undefined;
      if (!handler) {
        send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Unknown tool: ${name}` } });
        return;
      }
      try {
        const result = await handler(args || {});
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], isError: false } });
      } catch (e) {
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `Error: ${(e as Error).message}` }], isError: true } });
      }
      return;
    }

    if (id != null) {
      send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
  });

  process.stdin.resume();
}
