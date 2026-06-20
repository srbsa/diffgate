// Defensive normalizer: turns a code-graph tool's JSON output into a stable ImpactInfo.
// CodeGraph's analyze_impact / pr_context payload shapes are not strictly versioned, so we
// read from several plausible key names rather than hard-coding one schema.

import type {
  ImpactInfo, ImpactRef, PrContextInfo, EditContext, SecurityVerdict, StaleDoc,
} from "../types.js";

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

function numberOf(raw: unknown, keys: string[]): number | null {
  const v = pick(raw, keys);
  if (typeof v === "number") return v;
  if (typeof v === "string" && /^\d+(\.\d+)?$/.test(v)) return Number(v);
  return null;
}

function boolOf(raw: unknown, keys: string[]): boolean | null {
  const v = pick(raw, keys);
  if (typeof v === "boolean") return v;
  return null;
}

function symbolKey(raw: unknown): string | null {
  const v = pick(raw, ["symbol", "name", "function", "qualified_name", "qualifiedName", "id"]);
  return v != null ? String(v) : null;
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
  const complexity = numberOf(raw, ["complexity", "cyclomatic", "cyclomatic_complexity", "cyclomaticComplexity"]) ??
    numberOf(nested, ["complexity", "cyclomatic", "cyclomatic_complexity"]);
  const staleDoc = boolOf(raw, ["stale_doc", "staleDoc", "doc_stale", "docStale", "stale_docs"]) ??
    boolOf(nested, ["stale_doc", "staleDoc", "doc_stale"]);

  return {
    symbol: opts.symbol,
    callerCount,
    callers: callers.slice(0, max),
    reachable: reachabilityOf(raw) ?? reachabilityOf(nested),
    testGaps: testGaps.slice(0, max),
    reviewers,
    source: opts.source,
    truncated,
    ...(complexity != null ? { complexity } : {}),
    ...(staleDoc != null ? { staleDoc } : {}),
  };
}

/** Parse a find_related_tests payload into a list of covering tests (possibly empty). */
export function normalizeTests(raw: unknown, opts: { maxCallers?: number } = {}): ImpactRef[] {
  const max = Math.max(1, opts.maxCallers ?? 20);
  // Tests may be the top-level array, or under tests/related_tests/covering_tests.
  const arr = Array.isArray(raw)
    ? raw
    : asArray(pick(raw, ["tests", "related_tests", "relatedTests", "covering_tests", "coveringTests", "results"]));
  return arr.map(toRef).filter((r): r is ImpactRef => r !== null).slice(0, max);
}

/** Parse a get_edit_context payload into callers + covering tests + recent history. */
export function normalizeEditContext(
  raw: unknown,
  opts: { source: string; maxCallers?: number }
): EditContext | null {
  if (!raw || typeof raw !== "object") return null;
  const max = Math.max(1, opts.maxCallers ?? 20);
  const callers = asArray(pick(raw, ["callers", "direct_callers", "references", "callsites"]))
    .map(toRef).filter((r): r is ImpactRef => r !== null).slice(0, max);
  const tests = normalizeTests(pick(raw, ["tests", "related_tests", "covering_tests"]) ?? raw, { maxCallers: max });
  const history = asArray(pick(raw, ["history", "recent_changes", "recentChanges", "commits", "blame"]))
    .map((h) => {
      if (typeof h === "string") return h.trim();
      const who = pick(h, ["author", "name", "login"]);
      const what = pick(h, ["message", "subject", "summary", "commit", "sha", "date"]);
      return [who, what].filter(Boolean).map(String).join(" — ");
    })
    .filter(Boolean)
    .slice(0, max);
  return { callers, tests, history, source: opts.source };
}

/** Parse a security_detect_injection / trace_data_flow payload into a taint verdict. */
export function normalizeSecurity(
  raw: unknown,
  opts: { source: string; maxCallers?: number }
): SecurityVerdict | null {
  if (!raw || typeof raw !== "object") return null;
  const max = Math.max(1, opts.maxCallers ?? 20);
  // tainted may be stated directly, or implied by a non-empty data-flow path / vulnerability list.
  let tainted = boolOf(raw, ["tainted", "is_tainted", "vulnerable", "is_vulnerable", "exploitable", "reachable"]);
  const flowRaw = asArray(
    pick(raw, ["data_flow", "dataFlow", "taint_path", "taintPath", "path", "flow", "trace", "findings", "vulnerabilities"])
  );
  const dataFlow = flowRaw.map(toRef).filter((r): r is ImpactRef => r !== null).slice(0, max);
  if (tainted === null) {
    // No explicit flag — infer from evidence: a traced path means tainted; an explicit empty result means clean.
    if (dataFlow.length > 0) tainted = true;
    else if (flowRaw.length === 0 && pick(raw, ["clean", "safe", "no_taint", "noTaint"]) === true) tainted = false;
  }
  const detector = pick(raw, ["detector", "tool", "rule", "check"]);
  return {
    tainted,
    dataFlow,
    ...(detector != null ? { detector: String(detector) } : {}),
    source: opts.source,
  };
}

/** Parse a pr_context payload into per-symbol impact + repo-level stale-doc/commit signals. */
export function normalizePrContext(
  raw: unknown,
  opts: { source: string; maxCallers?: number }
): PrContextInfo | null {
  if (!raw || typeof raw !== "object") return null;
  const max = Math.max(1, opts.maxCallers ?? 20);

  // Changed functions live under one of several keys; each entry is one symbol's blast radius.
  const entries = asArray(
    pick(raw, ["changed_functions", "changedFunctions", "changes", "symbols", "functions", "results", "items"])
  );
  const bySymbol: Record<string, ImpactInfo> = {};
  for (const entry of entries) {
    const sym = symbolKey(entry);
    if (!sym) continue;
    const im = normalizeImpact(entry, { symbol: sym, source: opts.source, maxCallers: max });
    if (im) bySymbol[sym] = im;
  }

  const staleDocs: StaleDoc[] = asArray(
    pick(raw, ["stale_docs", "staleDocs", "stale_documentation", "doc_warnings", "docWarnings"])
  )
    .map((d): StaleDoc | null => {
      if (typeof d === "string") return { note: d.trim() };
      if (!d || typeof d !== "object") return null;
      const sd: StaleDoc = {};
      const sym = symbolKey(d);
      const file = pick(d, ["file", "path", "uri"]);
      const note = pick(d, ["note", "message", "reason", "warning"]);
      if (sym) sd.symbol = sym;
      if (file != null) sd.file = String(file).replace(/^file:\/\//, "");
      if (note != null) sd.note = String(note);
      return sd.symbol || sd.file || sd.note ? sd : null;
    })
    .filter((d): d is StaleDoc => d !== null)
    .slice(0, max);

  const commit = pick(raw, ["commit_hint", "commitHint", "commit_message", "suggested_commit", "commit_subject"]);

  return {
    bySymbol,
    staleDocs,
    ...(commit != null ? { commitHint: String(commit) } : {}),
    source: opts.source,
  };
}
