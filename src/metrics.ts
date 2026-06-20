// Aggregated metrics for the `report` command — the surface engineering leaders buy on.
// Pure functions over a review + the learnings store; the CLI renders them.
import type { AnalyzeResult } from "./core/types.js";
import type { LearningStore } from "./core/learnings.js";

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

/** Compact machine verdict for coding agents — "can I surface this diff to the human?" */
export function agentVerdict(files: AnalyzeResult[]): {
  verdict: "pass" | "blocked";
  counts: { green: number; yellow: number; orange: number };
  findings: { rule: string; tier: string; file: string; line: number; message: string }[];
} {
  const counts = { green: 0, yellow: 0, orange: 0 };
  let blocked = false;
  const findings: { rule: string; tier: string; file: string; line: number; message: string }[] = [];
  for (const file of files) {
    for (const f of file.findings) {
      if (f.tier in counts) counts[f.tier as keyof typeof counts] += 1;
      if (f.blocking || f.tier === "orange") blocked = true;
      findings.push({ rule: f.ruleId, tier: f.tier, file: file.filePath, line: f.line, message: f.message });
    }
  }
  return { verdict: blocked ? "blocked" : "pass", counts, findings };
}

function toSorted(m: Map<string, number>): RuleCount[] {
  return [...m.entries()].map(([rule, count]) => ({ rule, count })).sort((a, b) => b.count - a.count || a.rule.localeCompare(b.rule));
}

function relPath(filePath: string, cwd: string): string {
  if (filePath.startsWith(cwd)) return filePath.slice(cwd.length).replace(/^[/\\]/, "");
  return filePath;
}
