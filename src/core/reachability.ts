// Community-edition reachability pass. For cross-language injection-class findings — where DiffGate's
// recall is broad regex rather than a deep AST — the question pattern rules can't answer is "can
// untrusted input actually get here?". The Pro taint engine answers it precisely but is absent from
// community CodeGraph; this pass answers a deterministic, recall-preserving approximation of it using
// only community tools: is the sink reachable, through the call graph, from an untrusted entry point
// (an HTTP/event handler)?
//
// Safety posture (mirror of attachSecurity, one notch stricter):
//   • reachable  → ESCALATE to a blocking orange (a request path to the sink is proven). This is how
//                  broad cross-language findings earn the right to block without looser unconditional
//                  regex — recall comes from the graph, not from firing on everything.
//   • unreachable→ DO NOT auto-clear by default. A false "unreachable" (incomplete index) must never
//                  hide a real vuln. We only down-tier when `graph.reachabilityDeescalate` is enabled.
//   • unknown    → untouched. The provider returns null whenever it cannot answer; we never guess.
// Pro wins: a finding the security graph already ruled on (tainted true/false) is left to that
// authoritative verdict. Everything degrades to a no-op when no graph / no reachability capability.

import { overallTier, tierCounts } from "./tiers.js";
import { resolveGraphConfig } from "./graph/index.js";
import { SECURITY_RULES } from "./security.js";
import type { GraphProvider } from "./graph/index.js";
import type { AnalyzeResult, Config, Finding, ReachabilityVerdict } from "./types.js";

/**
 * Findings routed through reachability: the injection-class security rules PLUS the broad,
 * cross-language advisory rules whose blocking decision we want gated on a proven request path.
 * `sql-injection-candidate` is the Phase-2 advisory rule that is inert at the gate until reachable.
 */
export const REACHABILITY_RULES = new Set<string>([
  ...SECURITY_RULES,
  "raw-query",
  "dangerous-exec",
  "sql-injection-candidate",
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

/** Name the proven entry point(s) for the finding message. */
function reachTrace(verdict: ReachabilityVerdict): string {
  const where = verdict.entryPoints
    .slice(0, 2)
    .map((ep) => (ep.method && ep.route ? `${ep.method} ${ep.route}` : ep.route || ep.name))
    .filter(Boolean)
    .join(", ");
  const src = where || "an HTTP/event handler";
  return `🔓 Reachable: untrusted input from \`${src}\` reaches this sink (CodeGraph call graph). ` +
    `Coverage depends on the index.`;
}

function unreachableNote(): string {
  return "🛡 No path from an HTTP/event handler reaches this sink in the code graph. Advisory only — " +
    "coverage depends on the index, so verify before dismissing.";
}

function withReachability(
  finding: Finding,
  verdict: ReachabilityVerdict,
  opts: { deescalate: boolean; pinned: boolean }
): Finding {
  const next: Finding = { ...finding, reachability: verdict };

  // Proven reachable from untrusted input: escalate to a blocking orange and attach the trace.
  // A pinned rule keeps its configured tier/blocking — the trace is still attached for the reviewer.
  if (verdict.reachable) {
    if (!opts.pinned) {
      next.tier = "orange";
      next.blocking = true;
      next.tierAdjusted = "escalated";
    }
    next.message = `${finding.message}\n\n${reachTrace(verdict)}`;
    return next;
  }

  // Proven unreachable: never auto-clear unless the team opted in (and the rule isn't pinned). Even
  // then we only step down to yellow/review — never below it — so this can't silence a real finding.
  if (verdict.source === "codegraph" && opts.deescalate && !opts.pinned) {
    next.tier = "yellow";
    next.blocking = false;
    next.tierAdjusted = "deescalated";
    next.message = `${finding.message}\n\n${unreachableNote()} Down-tiered to review.`;
  }
  return next;
}

/**
 * Attach community-graph reachability verdicts to injection-class findings and escalate the ones
 * proven reachable from untrusted input. No-op when the provider has no `reachability` capability,
 * when `graph.reachability` is false, or when the graph returns nothing. Pure w.r.t. inputs.
 */
export function attachReachability(
  files: AnalyzeResult[],
  opts: { cwd: string; config: Partial<Config>; graph: GraphProvider | null }
): AnalyzeResult[] {
  const { graph } = opts;
  if (!graph || typeof graph.reachability !== "function") return files;
  const g = resolveGraphConfig(opts.config);
  if (g.reachability === false) return files;
  const deescalate = g.reachabilityDeescalate === true;

  const cache = new Map<string, ReachabilityVerdict | null>();

  return files.map((result) => {
    let changed = false;
    const findings = result.findings.map((finding) => {
      if (!REACHABILITY_RULES.has(finding.ruleId)) return finding;
      // Pro taint verdict (if present) is authoritative — don't second-guess it with reachability.
      if (finding.security && finding.security.tainted !== null) return finding;

      const key = `${result.filePath}::${finding.ruleId}::${finding.line}`;
      let verdict = cache.get(key);
      if (verdict === undefined) {
        try {
          verdict = graph.reachability!({
            symbol: finding.symbol || "",
            file: result.filePath,
            line: finding.line,
            cwd: opts.cwd,
            untrustedKinds: g.untrustedEntryKinds,
            maxDepth: g.reachabilityMaxDepth,
          });
        } catch {
          verdict = null;
        }
        cache.set(key, verdict ?? null);
      }
      if (!verdict) return finding;
      changed = true;
      return withReachability(finding, verdict, { deescalate, pinned: tierPinned(opts.config, finding.ruleId) });
    });
    return changed ? recompute(result, findings) : result;
  });
}
