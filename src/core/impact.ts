// Blast-radius pass: enrich public-surface findings with cross-file impact from a code graph,
// and route human attention by escalating/de-escalating their tier.
//
// This is what lets DiffGate use cross-file context to make reviews *quieter* (an exported
// symbol nobody calls is de-escalated) AND *more complete* (a change with many callers keeps
// the gate and names the reviewers) — instead of emitting more comments.
//
// Sourcing strategy: one whole-diff `pr_context` call is the primary source (callers + test
// gaps + reviewers + stale docs + complexity in a single query). Symbols it does not cover —
// or when pr_context is unavailable — fall back to a per-finding `analyze_impact` lookup, with
// `find_related_tests` filling in test-gap data the impact call lacks.

import { overallTier, tierCounts } from "./tiers.js";
import { resolveGraphConfig } from "./graph/index.js";
import type { GraphProvider } from "./graph/index.js";
import type { AnalyzeResult, Config, Finding, ImpactInfo, PrContextInfo } from "./types.js";

/** Findings that concern a named, cross-file symbol — eligible for a graph lookup. */
export const IMPACT_RULES = new Set(["public-api-change", "signature-drift", "deprecated-api"]);

/** Findings whose tier we may raise/lower based on caller count. */
const TIERABLE = new Set(["public-api-change", "signature-drift"]);

/** Cyclomatic complexity at/above which we call it out in the blast-radius line. */
const HIGH_COMPLEXITY = 10;

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
  if (typeof impact.complexity === "number" && impact.complexity >= HIGH_COMPLEXITY) {
    parts.push(`complexity ${impact.complexity}`);
  }
  if (impact.staleDoc) parts.push("stale docs");
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

/** Last dotted/`#`/`::`-delimited segment of a symbol (StripeClient.charge → charge). */
function bareName(symbol: string): string {
  const m = symbol.split(/[.#]|::/);
  return m[m.length - 1] || symbol;
}

/** Find a symbol's impact in a pr_context result by exact name, then by bare last segment. */
function matchPrSymbol(pr: PrContextInfo, symbol: string): ImpactInfo | null {
  if (pr.bySymbol[symbol]) return pr.bySymbol[symbol];
  const bare = bareName(symbol);
  if (bare !== symbol && pr.bySymbol[bare]) return pr.bySymbol[bare];
  // Match a stored qualified key whose bare segment equals our bare name.
  for (const key of Object.keys(pr.bySymbol)) {
    if (bareName(key) === bare) return pr.bySymbol[key];
  }
  return null;
}

/** Build a set of symbol names (exact + bare) flagged stale by pr_context, for cheap lookup. */
function staleDocSymbols(pr: PrContextInfo): Set<string> {
  const set = new Set<string>();
  for (const d of pr.staleDocs) {
    if (d.symbol) { set.add(d.symbol); set.add(bareName(d.symbol)); }
  }
  return set;
}

/**
 * Attach cross-file impact to findings and adjust tiers. No-op (returns input unchanged)
 * when `graph` is null. Pure with respect to inputs — returns new result objects.
 */
export function attachImpact(
  files: AnalyzeResult[],
  opts: { cwd: string; config: Partial<Config>; graph: GraphProvider | null; mode?: string }
): AnalyzeResult[] {
  const { graph } = opts;
  if (!graph) return files;
  const g = resolveGraphConfig(opts.config);

  // Primary source: one whole-diff pr_context call (when the provider supports it).
  let pr: PrContextInfo | null = null;
  if (g.prContext && typeof graph.prContext === "function") {
    try {
      pr = graph.prContext({ cwd: opts.cwd, mode: opts.mode });
    } catch {
      pr = null;
    }
  }
  const staleSyms = pr ? staleDocSymbols(pr) : null;

  const cache = new Map<string, ImpactInfo | null>();

  const lookup = (finding: Finding, filePath: string): ImpactInfo | null => {
    const symbol = finding.symbol as string;
    const key = `${filePath}::${symbol}::${finding.line}`;
    if (cache.has(key)) return cache.get(key) ?? null;

    let impact: ImpactInfo | null = null;

    // 1. pr_context primary — covers most changed symbols in a single call.
    if (pr) impact = matchPrSymbol(pr, symbol);

    // 2. Per-finding fallback for symbols pr_context didn't cover (or when it's absent).
    if (!impact) {
      try {
        impact = graph.impact({ symbol, file: filePath, line: finding.line, cwd: opts.cwd });
      } catch {
        impact = null;
      }
      // #4 — authoritative test-gap fill: a changed public symbol with no covering test is untested.
      if (impact && impact.source === "codegraph" && impact.testGaps.length === 0 &&
          g.relatedTests && typeof graph.relatedTests === "function") {
        try {
          const tests = graph.relatedTests({ symbol, file: filePath, line: finding.line, cwd: opts.cwd });
          if (tests && tests.length === 0) {
            impact = { ...impact, testGaps: [{ symbol }] };
          }
        } catch {
          /* best-effort */
        }
      }
    }

    // Fold in repo-level stale-doc warnings from pr_context.
    if (impact && staleSyms && (staleSyms.has(symbol) || staleSyms.has(bareName(symbol)))) {
      impact = { ...impact, staleDoc: true };
    }

    cache.set(key, impact ?? null);
    return impact ?? null;
  };

  return files.map((result) => {
    let changed = false;
    const findings = result.findings.map((finding) => {
      if (!finding.symbol || !IMPACT_RULES.has(finding.ruleId)) return finding;
      const impact = lookup(finding, result.filePath);
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
