// Aggregated metrics for the `report` command — the surface engineering leaders buy on.
// Pure functions over a review + the learnings store; the CLI renders them.
import type { AnalyzeResult, AgentConfig, Finding } from "./core/types.js";
import type { LearningStore } from "./core/learnings.js";
import { SECURITY_RULES } from "./core/security.js";
import { TIER_ORDER } from "./core/tiers.js";
import { findingFingerprint } from "./core/session.js";

export interface RuleCount {
  rule: string;
  count: number;
}

export interface ReviewMetrics {
  counts: { green: number; yellow: number; orange: number };
  total: number;
  blocked: boolean;
  filesWithFindings: number;
  topRules: RuleCount[];
  topFiles: { file: string; orange: number; total: number }[];
  learnings: {
    total: number;
    dismissed: number;
    confirmed: number;
    /** Rules teams most often dismiss as noise — the noise-reduction loop, made visible. */
    noisiestRules: RuleCount[];
  };
}

export function buildMetrics(files: AnalyzeResult[], learnings: LearningStore, cwd: string): ReviewMetrics {
  const counts = { green: 0, yellow: 0, orange: 0 };
  const ruleFreq = new Map<string, number>();
  const fileStats: { file: string; orange: number; total: number }[] = [];
  let blocked = false;

  for (const file of files) {
    let orange = 0;
    for (const f of file.findings) {
      if (f.tier in counts) counts[f.tier as keyof typeof counts] += 1;
      if (f.tier === "orange") orange += 1;
      if (f.blocking) blocked = true;
      ruleFreq.set(f.ruleId, (ruleFreq.get(f.ruleId) || 0) + 1);
    }
    const rel = relPath(file.filePath, cwd);
    fileStats.push({ file: rel, orange, total: file.findings.length });
  }

  const dismissFreq = new Map<string, number>();
  let dismissed = 0;
  let confirmed = 0;
  for (const e of learnings.entries) {
    if (e.verdict === "dismiss") {
      dismissed += 1;
      dismissFreq.set(e.ruleId, (dismissFreq.get(e.ruleId) || 0) + 1);
    } else if (e.verdict === "confirm") {
      confirmed += 1;
    }
  }

  return {
    counts,
    total: counts.green + counts.yellow + counts.orange,
    blocked,
    filesWithFindings: files.length,
    topRules: toSorted(ruleFreq).slice(0, 10),
    topFiles: fileStats.sort((a, b) => b.orange - a.orange || b.total - a.total).slice(0, 10),
    learnings: {
      total: learnings.entries.length,
      dismissed,
      confirmed,
      noisiestRules: toSorted(dismissFreq).slice(0, 10),
    },
  };
}

/** Autonomy rung for a single finding (see AgentConfig). Deterministic — never uses LLM output. */
export type AgentRung = "block" | "escalate" | "autofix" | "advisory";

export function rungFor(f: Finding, autoFixFloor: string): AgentRung {
  // Hard rules (secret, destructive SQL, injection) and graph-confirmed taint are the only true blocks.
  if (f.blocking) return "block";
  if (SECURITY_RULES.has(f.ruleId) && f.trust === "confirmed") return "block";
  // Graph-confirmed high blast radius → hand to a human rather than silently editing call sites.
  if (f.tierAdjusted === "escalated") return "escalate";
  if ((TIER_ORDER[f.tier] ?? 0) >= (TIER_ORDER[autoFixFloor] ?? 2)) return "autofix";
  return "advisory";
}

interface AgentVerdictFinding {
  rule: string; tier: string; trust: string; rung: AgentRung;
  file: string; line: number; message: string;
  /** True when this finding has outlasted the agent's escalation budget this session (see opts). */
  overBudget?: boolean;
}

/**
 * Compact machine verdict for coding agents — "can I surface this diff to the human?" The autonomy
 * ladder (config.gate.agent) decides how findings translate to a verdict:
 *  - "advisory" (default): only `block`-rung findings fail; everything else is "review" (exit 0).
 *  - "gated": legacy — any orange/blocking finding blocks.
 *  - "off": never blocks; pure advisory data.
 */
export function agentVerdict(
  files: AnalyzeResult[],
  agent: AgentConfig = {},
  opts: { overBudget?: Set<string> } = {}
): {
  verdict: "pass" | "review" | "blocked";
  mode: string;
  budget: { maxFixesPerTurn: number; escalateAfterTurns: number };
  /** Count of findings that outlasted the escalation budget (0 unless a session was tracked). */
  escalations: number;
  counts: { green: number; yellow: number; orange: number };
  findings: AgentVerdictFinding[];
} {
  const mode = agent.mode ?? "advisory";
  const autoFixFloor = agent.autoFixFloor ?? "orange";
  const overBudget = opts.overBudget;
  const counts = { green: 0, yellow: 0, orange: 0 };
  const findings: AgentVerdictFinding[] = [];
  let hasBlock = false;
  let hasReview = false; // escalate or autofix rung — worth a human's eyes but not a hard fail
  let escalations = 0;

  for (const file of files) {
    for (const f of file.findings) {
      if (f.tier in counts) counts[f.tier as keyof typeof counts] += 1;
      let rung = rungFor(f, autoFixFloor);
      // Budget overrun (only when a session was tracked): a finding the agent keeps re-touching is
      // promoted to 'escalate' so it surfaces for human review instead of feeding another fix-loop.
      const over = !!overBudget && overBudget.has(findingFingerprint(file.filePath, f));
      if (over) {
        escalations += 1;
        if (rung === "autofix" || rung === "advisory") rung = "escalate";
      }
      if (rung === "block") hasBlock = true;
      else if (rung === "escalate" || rung === "autofix") hasReview = true;
      findings.push({
        rule: f.ruleId, tier: f.tier, trust: f.trust ?? "confirmed", rung,
        file: file.filePath, line: f.line, message: f.message,
        ...(over ? { overBudget: true } : {}),
      });
    }
  }

  let verdict: "pass" | "review" | "blocked";
  if (mode === "off") verdict = "pass";
  else if (mode === "gated") verdict = hasBlock || counts.orange > 0 ? "blocked" : "pass";
  else verdict = hasBlock ? "blocked" : hasReview ? "review" : "pass"; // advisory

  return {
    verdict,
    mode,
    budget: { maxFixesPerTurn: agent.maxFixesPerTurn ?? 3, escalateAfterTurns: agent.escalateAfterTurns ?? 2 },
    escalations,
    counts,
    findings,
  };
}

function toSorted(m: Map<string, number>): RuleCount[] {
  return [...m.entries()].map(([rule, count]) => ({ rule, count })).sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule));
}

function relPath(filePath: string, cwd: string): string {
  if (filePath.startsWith(cwd)) return filePath.slice(cwd.length).replace(/^[/\\]/, "");
  return filePath;
}
