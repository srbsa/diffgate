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
} from "./core/index.js";
import type { Finding, Config, FetchFn } from "./core/types.js";

declare const __DIFFGATE_VERSION__: string;
const VERSION = typeof __DIFFGATE_VERSION__ !== "undefined" ? __DIFFGATE_VERSION__ : "0.0.0";

const SEP = Buffer.from("\r\n\r\n");

export function createReader(stream: Readable): { onMessage: (fn: (msg: unknown) => void) => void } {
  let buf = Buffer.alloc(0);
  const listeners: Array<(msg: unknown) => void> = [];
  stream.on("data", (chunk: Buffer | string) => {
    buf = Buffer.concat([buf, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    while (true) {
      const sepIdx = buf.indexOf(SEP);
      if (sepIdx === -1) break;
      const header = buf.slice(0, sepIdx).toString("ascii");
      const m = header.match(/Content-Length:\s*(\d+)/i);
      if (!m) { buf = buf.slice(sepIdx + 4); continue; }
      const len = parseInt(m[1], 10);
      const bodyStart = sepIdx + 4;
      if (buf.length < bodyStart + len) break;
      const body = buf.slice(bodyStart, bodyStart + len).toString("utf-8");
      buf = buf.slice(bodyStart + len);
      let msg: unknown;
      try { msg = JSON.parse(body); } catch { continue; }
      for (const fn of listeners) fn(msg);
    }
  });
  return { onMessage: (fn) => listeners.push(fn) };
}

export function createWriter(stream: Writable): (obj: unknown) => void {
  return function send(obj: unknown) {
    const body = JSON.stringify(obj);
    const len = Buffer.byteLength(body, "utf-8");
    stream.write(`Content-Length: ${len}\r\n\r\n${body}`);
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
      "Returns overall tier, counts, and per-file findings across the whole diff.",
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
  return { ...rest, _diffgate: capabilityHint(config) };
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
    const { id, method, params } = msg as { id?: unknown; method?: string; params?: { name?: string; arguments?: Record<string, unknown> } };

    if (method === "initialize") {
      send({ jsonrpc: "2.0", id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "diffgate", version: VERSION } } });
      return;
    }
    if (method === "initialized" || method === "notifications/initialized") return;
    if (method === "ping") { send({ jsonrpc: "2.0", id, result: {} }); return; }
    if (method === "tools/list") { send({ jsonrpc: "2.0", id, result: { tools: TOOL_DEFS } }); return; }

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
