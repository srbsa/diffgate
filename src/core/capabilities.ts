// Capability manifest for agent consumers. Lets a coding agent learn — in one call, up front —
// which layers are active (core / code graph / LLM), which tools it can call without hitting an
// error, and the autonomy budget it should respect. The goal is graded, budgeted self-correction
// instead of an endless fix-loop against findings the agent can neither confirm nor safely ignore.

import { graphStatus } from "./graph/index.js";
import { resolveGraphConfig } from "./graph/index.js";
import { isAiAvailable, describeProvider } from "./llm/index.js";
import type { Config, AgentConfig } from "./types.js";

const ALWAYS_TOOLS = [
  "diffgate_analyze",
  "diffgate_check_staged",
  "diffgate_guidelines",
  "diffgate_feedback",
  "diffgate_capabilities",
];
const LLM_TOOLS = ["diffgate_explain", "diffgate_deep_review"];

export interface Capabilities {
  version: string;
  core: true;
  graph: { available: boolean; reason: string };
  llm: { available: boolean; provider: string | null };
  /** Tools the agent can call right now without an "AI not configured" error. */
  availableTools: string[];
  /** Tools that will throw until their layer is configured. */
  unavailableTools: string[];
  /** Resolved autonomy policy, so the agent need not re-read config to learn its budget. */
  agent: Required<AgentConfig> & { failOn: string };
  /** Compact interaction protocol (the autonomy ladder), tailored to what's available. */
  protocol: string[];
}

function resolveAgentConfig(config: Partial<Config>): Required<AgentConfig> {
  const a = config.gate?.agent || {};
  return {
    mode: a.mode ?? "advisory",
    autoFixFloor: a.autoFixFloor ?? "orange",
    maxFixesPerTurn: a.maxFixesPerTurn ?? 3,
    escalateAfterTurns: a.escalateAfterTurns ?? 2,
    trustSource: a.trustSource ?? "deterministic",
  };
}

function buildProtocol(opts: { graph: boolean; llm: boolean; agent: Required<AgentConfig> }): string[] {
  const { graph, llm, agent } = opts;
  const lines = [
    `Severity rungs: fix findings at/above '${agent.autoFixFloor}' only in code you just wrote; ` +
      `surface 'yellow'/'green' as notes, do not auto-fix.`,
    `Loop budget: apply at most ${agent.maxFixesPerTurn} DiffGate fixes per turn. If a fix creates a ` +
      `new finding, STOP and report — do not re-fix.`,
    `Escalate (don't block): when the same finding survives ${agent.escalateAfterTurns} turns, hand it ` +
      `to the human with context instead of trying again.`,
    `Trust the label, not your confidence: act on a finding's 'trust' field. 'confirmed' = real; ` +
      `'cleared' = safe; 'unconfirmed' = flag for a human, don't silently "fix".`,
    `False positives: use diffgate_feedback {verdict:"dismiss"} with a reason rather than changing correct code.`,
  ];
  if (graph) {
    lines.push(
      `Blast radius present: for findings marked tierAdjusted:"escalated" (high caller count), pause and ` +
        `ask before editing downstream callers.`
    );
  } else {
    lines.push(
      `No code graph: security findings carry trust:"unconfirmed" (no taint analysis). Flag them to the ` +
        `human rather than auto-fixing. A graph would confirm/deny them.`
    );
  }
  if (llm) {
    lines.push(
      `LLM present: use diffgate_explain sparingly on 'orange' findings you're unsure of — explanation only, ` +
        `it never changes the gate decision. If it contradicts the code, trust the code.`
    );
  } else {
    lines.push(`No LLM: do not call diffgate_explain / diffgate_deep_review (they will error).`);
    lines.push(
      `diffgate_guidelines runs in host mode — it returns material for YOU to judge (self-review, not an ` +
        `independent gate). Treat results as advisory; never block on them.`
    );
  }
  return lines;
}

/** Build the capability manifest for the given repo config. `version` is injected at the call site. */
export function buildCapabilities(config: Config, version: string): Capabilities {
  const g = graphStatus(config);
  // Available = enabled in config AND an index exists, so queries return data now.
  const graphAvailable = g.enabled && g.indexed && resolveGraphConfig(config).mode !== "off";
  const llm = isAiAvailable(config);
  const agent = resolveAgentConfig(config);
  return {
    version,
    core: true,
    graph: { available: graphAvailable, reason: g.reason },
    llm: { available: llm, provider: llm ? describeProvider(config) : null },
    availableTools: [...ALWAYS_TOOLS, ...(llm ? LLM_TOOLS : [])],
    unavailableTools: llm ? [] : LLM_TOOLS,
    agent: { ...agent, failOn: config.gate?.failOn ?? "orange" },
    protocol: buildProtocol({ graph: graphAvailable, llm, agent }),
  };
}

/** A tiny capability hint embedded in analyze/check responses so the agent never has to discover
 *  a layer's absence via a thrown error. Full detail lives in diffgate_capabilities. */
export function capabilityHint(config: Config): { graph: boolean; llm: boolean; agentMode: string } {
  const g = graphStatus(config);
  return {
    graph: g.enabled && g.indexed && resolveGraphConfig(config).mode !== "off",
    llm: isAiAvailable(config),
    agentMode: config.gate?.agent?.mode ?? "advisory",
  };
}
