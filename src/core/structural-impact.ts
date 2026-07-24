/**
 * Graph-backed confirmation for structural findings.
 *
 * `single-caller-abstraction` is emitted optimistically by a rule that can only see one file — it
 * knows a class or interface was declared, not whether anything uses it. This pass asks the code
 * graph for the caller count and either confirms the finding or drops it.
 *
 * The invariant, inherited from `attachImpact` and the builtin provider's `partial` guard: an
 * unknown is never treated as a zero. No graph, no coverage for the language, or a truncated walk
 * all mean "we cannot prove this is speculative" — and an unproven finding is dropped, not shown.
 * Crying wolf on an incomplete graph is the one failure mode that would discredit the rule.
 */

import type { AnalyzeResult, Config, Finding, ImpactInfo } from "./types.js";
import type { GraphProvider } from "./graph/index.js";
import { overallTier, tierCounts } from "./tiers.js";

/** Rule ids whose findings only survive when the graph positively confirms them. */
export const STRUCTURAL_IMPACT_RULES = new Set(["single-caller-abstraction"]);

/** Callers at or below this count make an abstraction speculative. */
const SPECULATIVE_AT_OR_BELOW = 1;

function recompute(result: AnalyzeResult, findings: Finding[]): AnalyzeResult {
  return {
    ...result,
    findings,
    tier: overallTier(findings),
    counts: tierCounts(findings),
    blocking: findings.some((f) => f.blocking),
  };
}

function confirmedMessage(symbol: string, impact: ImpactInfo): string {
  const n = impact.callerCount;
  const callers = n === 0 ? "no call sites" : "1 call site";
  return (
    `⚡ Speculative abstraction: ${symbol} has ${callers} across the repository. ` +
    `Flatten it into a direct call unless a second implementation is imminent.`
  );
}

/**
 * Confirm or drop every `single-caller-abstraction` finding.
 *
 * Kept when the graph reports ≤1 caller. Dropped when it reports more (the abstraction earns its
 * keep) or when the graph cannot answer. Ambiguous name matches are kept but annotated rather than
 * treated as authoritative, mirroring `attachImpact`.
 */
export function attachStructuralImpact(
  files: AnalyzeResult[],
  opts: { cwd: string; config: Partial<Config>; graph: GraphProvider | null }
): AnalyzeResult[] {
  const { graph } = opts;

  const hasCandidate = files.some((f) =>
    f.findings.some((fn) => STRUCTURAL_IMPACT_RULES.has(fn.ruleId))
  );
  if (!hasCandidate) return files;

  // No graph → nothing can be confirmed, so every optimistic finding is dropped. This is the
  // common path when the graph is disabled, and it must stay silent rather than speculative.
  if (!graph) {
    return files.map((f) => {
      const kept = f.findings.filter((fn) => !STRUCTURAL_IMPACT_RULES.has(fn.ruleId));
      return kept.length === f.findings.length ? f : recompute(f, kept);
    });
  }

  const cache = new Map<string, ImpactInfo | null>();

  return files.map((file) => {
    if (!file.findings.some((fn) => STRUCTURAL_IMPACT_RULES.has(fn.ruleId))) return file;

    const next: Finding[] = [];
    for (const finding of file.findings) {
      if (!STRUCTURAL_IMPACT_RULES.has(finding.ruleId)) {
        next.push(finding);
        continue;
      }

      const symbol = finding.symbol;
      if (!symbol) continue; // nothing to look up → unprovable → drop

      const key = `${file.filePath}::${symbol}::${finding.line}`;
      let impact: ImpactInfo | null;
      if (cache.has(key)) {
        impact = cache.get(key) ?? null;
      } else {
        try {
          impact = graph.impact({ symbol, file: file.filePath, line: finding.line, cwd: opts.cwd });
        } catch {
          impact = null;
        }
        cache.set(key, impact);
      }

      // Unknown: no coverage for this language, a truncated walk, or a provider error.
      if (!impact) continue;
      // Justified: something already depends on it.
      if (impact.callerCount > SPECULATIVE_AT_OR_BELOW) continue;

      let message = confirmedMessage(symbol, impact);
      if (impact.ambiguous) {
        message +=
          "\n\n⚠ the name matched multiple definitions, so the count may include unrelated sites — confirm before removing the abstraction.";
      }
      next.push({ ...finding, message, tier: "yellow", blocking: false });
    }

    return next.length === file.findings.length && next.every((f, i) => f === file.findings[i])
      ? file
      : recompute(file, next);
  });
}
