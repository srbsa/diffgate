// Blast-radius pass: enrich public-surface findings with cross-file impact from a code graph,
// and route human attention by escalating/de-escalating their tier.
//
// This is what lets DiffGate use cross-file context to make reviews *quieter* (an exported
// symbol nobody calls is de-escalated) AND *more complete* (a change with many callers keeps
// the gate and names the reviewers) — instead of emitting more comments.

import { overallTier, tierCounts } from "./tiers.js";
import { resolveGraphConfig } from "./graph/index.js";
import type { GraphProvider } from "./graph/index.js";
import type { AnalyzeResult, Config, Finding, ImpactInfo } from "./types.js";

/** Findings that concern a named, cross-file symbol — eligible for a graph lookup. */
export const IMPACT_RULES = new Set(["public-api-change", "signature-drift", "deprecated-api"]);

/** Findings whose tier we may raise/lower based on caller count. */
const TIERABLE = new Set(["public-api-change", "signature-drift"]);

function distinctFiles(refs: ImpactInfo["callers"]): number {
  return new Set(refs.map((r) => r.file).filter(Boolean)).size;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** Append a concise blast-radius line to a finding's message. */
function blastSummary(impact: ImpactInfo): string {
  const fileCount = distinctFiles(impact.callers);
  const callsites = impact.truncated ? `${impact.callerCount}+` : String(impact.callerCount);
  const parts = [`⚡ Blast radius: ${callsites} call site${impact.callerCount === 1 ? "" : "s"}` +
    (fileCount ? ` across ${plural(fileCount, "file")}` : "")];
  if (impact.reachable === true) parts.push("reachable from an entry point");
  if (impact.reviewers.length) parts.push(`route: ${impact.reviewers.slice(0, 3).map((r) => "@" + r).join(", ")}`);
  if (impact.testGaps.length) {
    const names = impact.testGaps.slice(0, 3).map((t) => t.symbol || t.file).join(", ");
    parts.push(`⚠ untested: ${names}`);
  }
  return parts.join(" · ") + ".";
}

/** True when the user pinned this rule's tier in config — auto-tiering must not override that. */
function tierPinned(config: Partial<Config>, ruleId: string): boolean {
  const ov = config.rules?.[ruleId];
  return !!(ov && typeof ov === "object" && (ov.tier !== undefined || ov.blocking !== undefined));
}

function withImpact(
  finding: Finding,
  impact: ImpactInfo,
  opts: { escalateThreshold: number; pinned: boolean }
): Finding {
  const next: Finding = { ...finding, impact };

  if (!TIERABLE.has(finding.ruleId) || opts.pinned) {
    // Non-tierable (e.g. deprecated-api) or user-pinned: enrich text only.
    if (impact.callerCount > 0 || impact.testGaps.length) {
      next.message = `${finding.message}\n\n${blastSummary(impact)}`;
    }
    return next;
  }

  // De-escalate: an exported surface the graph says nobody calls is low blast radius.
  if (impact.source === "codegraph" && impact.callerCount === 0) {
    next.tier = "yellow";
    next.tierAdjusted = "deescalated";
    next.message = `${finding.message}\n\n⚡ Blast radius: no callers found in the code graph — exported but currently unused. Down-tiered to review.`;
    return next;
  }

  // Escalate / keep: real cross-file fan-out. Keep the gate and route attention.
  if (impact.callerCount >= opts.escalateThreshold) {
    next.tier = "orange";
    next.tierAdjusted = "escalated";
    next.message = `${finding.message}\n\n${blastSummary(impact)}`;
  }
  return next;
}

function recompute(result: AnalyzeResult, findings: Finding[]): AnalyzeResult {
  return {
    ...result,
    findings,
    tier: overallTier(findings),
    counts: tierCounts(findings),
    blocking: findings.some((f) => f.blocking),
  };
}

/**
 * Attach cross-file impact to findings and adjust tiers. No-op (returns input unchanged)
 * when `graph` is null. Pure with respect to inputs — returns new result objects.
 */
export function attachImpact(
  files: AnalyzeResult[],
  opts: { cwd: string; config: Partial<Config>; graph: GraphProvider | null }
): AnalyzeResult[] {
  const { graph } = opts;
  if (!graph) return files;
  const g = resolveGraphConfig(opts.config);
  const cache = new Map<string, ImpactInfo | null>();

  return files.map((result) => {
    let changed = false;
    const findings = result.findings.map((finding) => {
      if (!finding.symbol || !IMPACT_RULES.has(finding.ruleId)) return finding;
      const key = `${result.filePath}::${finding.symbol}::${finding.line}`;
      let impact = cache.get(key);
      if (impact === undefined) {
        try {
          impact = graph.impact({ symbol: finding.symbol, file: result.filePath, line: finding.line, cwd: opts.cwd });
        } catch {
          impact = null;
        }
        cache.set(key, impact ?? null);
      }
      if (!impact) return finding;
      changed = true;
      return withImpact(finding, impact, {
        escalateThreshold: g.escalateThreshold,
        pinned: tierPinned(opts.config, finding.ruleId),
      });
    });
    return changed ? recompute(result, findings) : result;
  });
}
