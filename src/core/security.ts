// Graph-aware security pass (optional, Pro). For injection-class findings, a code graph with
// taint tracing can answer the question pattern rules cannot: does user input actually reach
// this sink? That turns a noisy "looks like SQL concatenation" into either a confirmed taint
// path (kept, with the data-flow trace attached) or — only when the team opts in — a proven
// non-issue that gets down-tiered.
//
// Safety posture: the security graph ENRICHES by default. It only DOWN-tiers a security finding
// when `graph.securityDeescalate` is explicitly enabled, because a false "no taint" would hide a
// real vulnerability. Everything degrades to a no-op when no security graph is present.
//
// NOTE: validated against CodeGraph's documented tool contract and injected fakes, not a live
// Pro binary — see CHANGELOG.

import { overallTier, tierCounts } from "./tiers.js";
import { resolveGraphConfig } from "./graph/index.js";
import type { GraphProvider } from "./graph/index.js";
import type { AnalyzeResult, Config, Finding, SecurityVerdict } from "./types.js";

/** Injection-class rules whose risk depends on whether user input reaches the sink. */
export const SECURITY_RULES = new Set([
  "sql-injection", "nosql-injection", "xss-sink", "path-traversal", "dangerous-exec", "prototype-pollution",
]);

function tierPinned(config: Partial<Config>, ruleId: string): boolean {
  const ov = config.rules?.[ruleId];
  return !!(ov && typeof ov === "object" && (ov.tier !== undefined || ov.blocking !== undefined));
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

function taintTrace(verdict: SecurityVerdict): string {
  if (verdict.dataFlow.length === 0) return "🔓 Taint path confirmed by the code graph.";
  const hops = verdict.dataFlow.map((r) => r.symbol || r.file || "?").slice(0, 6).join(" → ");
  return `🔓 Taint path: ${hops}.`;
}

function withSecurity(
  finding: Finding,
  verdict: SecurityVerdict,
  opts: { deescalate: boolean; pinned: boolean }
): Finding {
  const next: Finding = { ...finding, security: verdict };

  // Confirmed reachable: keep the gate, attach the trace so the reviewer sees the path.
  if (verdict.tainted === true) {
    next.message = `${finding.message}\n\n${taintTrace(verdict)}`;
    return next;
  }

  // Proven clean by an authoritative graph — down-tier only when the team opted in and the
  // rule isn't pinned. Otherwise we just record the verdict without weakening the finding.
  if (verdict.tainted === false && verdict.source === "codegraph" && opts.deescalate && !opts.pinned) {
    next.tier = "yellow";
    next.blocking = false;
    next.tierAdjusted = "deescalated";
    next.message = `${finding.message}\n\n🛡 No taint path: the code graph found no user-input flow reaching this sink. Down-tiered to review.`;
  }
  return next;
}

/**
 * Attach graph-aware taint verdicts to injection-class findings. No-op when the provider has no
 * security capability, when `graph.security` is false, or when the graph returns nothing.
 */
export function attachSecurity(
  files: AnalyzeResult[],
  opts: { cwd: string; config: Partial<Config>; graph: GraphProvider | null }
): AnalyzeResult[] {
  const { graph } = opts;
  if (!graph || typeof graph.security !== "function") return files;
  const g = resolveGraphConfig(opts.config);
  if (g.security === false) return files;
  const deescalate = g.securityDeescalate === true;

  const cache = new Map<string, SecurityVerdict | null>();

  return files.map((result) => {
    let changed = false;
    const findings = result.findings.map((finding) => {
      if (!SECURITY_RULES.has(finding.ruleId)) return finding;
      const key = `${result.filePath}::${finding.ruleId}::${finding.line}`;
      let verdict = cache.get(key);
      if (verdict === undefined) {
        try {
          verdict = graph.security!({
            symbol: finding.symbol || "",
            file: result.filePath,
            line: finding.line,
            cwd: opts.cwd,
            ruleId: finding.ruleId,
            sink: finding.code,
          });
        } catch {
          verdict = null;
        }
        cache.set(key, verdict ?? null);
      }
      if (!verdict) return finding;
      changed = true;
      return withSecurity(finding, verdict, { deescalate, pinned: tierPinned(opts.config, finding.ruleId) });
    });
    return changed ? recompute(result, findings) : result;
  });
}
