// Defensive normalizer: turns a code-graph tool's JSON output into a stable ImpactInfo.
// CodeGraph's analyze_impact / pr_context payload shapes are not strictly versioned, so we
// read from several plausible key names rather than hard-coding one schema.

import type { ImpactInfo, ImpactRef } from "../types.js";

type Raw = Record<string, unknown>;

function pick(obj: unknown, keys: string[]): unknown {
  if (!obj || typeof obj !== "object") return undefined;
  const o = obj as Raw;
  for (const k of keys) {
    if (o[k] !== undefined && o[k] !== null) return o[k];
  }
  return undefined;
}

function asArray(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  // Some tools return a comma/newline-joined string (e.g. "refresh_token, revoke_session").
  if (typeof v === "string") {
    return v.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
  }
  return [];
}

function toRef(x: unknown): ImpactRef | null {
  if (typeof x === "string") {
    const s = x.trim();
    return s ? { symbol: s } : null;
  }
  if (!x || typeof x !== "object") return null;
  const file = pick(x, ["file", "uri", "path", "location", "filepath"]);
  const lineRaw = pick(x, ["line", "lineno", "row", "start_line", "startLine"]);
  const symbol = pick(x, ["symbol", "name", "function", "caller", "qualified_name", "qualifiedName"]);
  if (file == null && symbol == null) return null;
  const ref: ImpactRef = {};
  if (file != null) ref.file = String(file).replace(/^file:\/\//, "");
  if (typeof lineRaw === "number") ref.line = lineRaw;
  else if (typeof lineRaw === "string" && /^\d+$/.test(lineRaw)) ref.line = Number(lineRaw);
  if (symbol != null) ref.symbol = String(symbol);
  return ref;
}

function toReviewer(x: unknown): string | null {
  if (typeof x === "string") return x.trim() || null;
  if (!x || typeof x !== "object") return null;
  const name = pick(x, ["author", "name", "login", "reviewer", "owner", "handle"]);
  return name != null ? String(name) : null;
}

function reviewerWeight(x: unknown): number {
  const w = pick(x, ["lines_owned", "linesOwned", "weight", "ownership", "score"]);
  return typeof w === "number" ? w : 0;
}

function reachabilityOf(raw: unknown): boolean | null {
  const v = pick(raw, ["reachable", "is_reachable", "isReachable", "entrypoint_reachable", "reachable_from_entrypoint"]);
  if (typeof v === "boolean") return v;
  return null;
}

/**
 * Parse a code-graph impact payload into a normalized ImpactInfo.
 * Returns null only when the payload is unusable (not an object).
 */
export function normalizeImpact(
  raw: unknown,
  opts: { symbol: string; source: string; maxCallers?: number }
): ImpactInfo | null {
  if (!raw || typeof raw !== "object") return null;
  const max = Math.max(1, opts.maxCallers ?? 20);

  // Callers may sit at the top level or nested under impact/blast_radius.
  const nested = (pick(raw, ["impact", "blast_radius", "blastRadius", "result", "data"]) as Raw) || (raw as Raw);
  const callersRaw = asArray(
    pick(raw, ["callers", "direct_callers", "affected_callers", "affectedCallers", "callsites", "references"]) ??
      pick(nested, ["callers", "direct_callers", "affected_callers", "affectedCallers", "callsites", "references"])
  );
  const callers = callersRaw.map(toRef).filter((r): r is ImpactRef => r !== null);

  const explicitCount = pick(raw, ["caller_count", "callerCount", "direct_caller_count", "directCallerCount", "impacted_count"]) ??
    pick(nested, ["caller_count", "callerCount", "direct_caller_count", "directCallerCount"]);
  const callerCount = typeof explicitCount === "number" ? explicitCount : callers.length;

  const testGapsRaw = asArray(
    pick(raw, ["test_gaps", "testGaps", "untested", "missing_tests", "missingTests", "uncovered"]) ??
      pick(nested, ["test_gaps", "testGaps", "untested", "missing_tests", "uncovered"])
  );
  const testGaps = testGapsRaw.map(toRef).filter((r): r is ImpactRef => r !== null);

  const reviewersRaw = asArray(
    pick(raw, ["suggested_reviewers", "suggestedReviewers", "reviewers", "owners", "codeowners"]) ??
      pick(nested, ["suggested_reviewers", "suggestedReviewers", "reviewers", "owners"])
  );
  const reviewers = reviewersRaw
    .map((r) => ({ name: toReviewer(r), weight: reviewerWeight(r) }))
    .filter((r): r is { name: string; weight: number } => r.name !== null)
    .sort((a, b) => b.weight - a.weight)
    .map((r) => r.name)
    .filter((name, i, arr) => arr.indexOf(name) === i);

  const truncated = callers.length > max || testGaps.length > max;

  return {
    symbol: opts.symbol,
    callerCount,
    callers: callers.slice(0, max),
    reachable: reachabilityOf(raw) ?? reachabilityOf(nested),
    testGaps: testGaps.slice(0, max),
    reviewers,
    source: opts.source,
    truncated,
  };
}
