// Defensive normalizer: turns a code-graph tool's JSON output into a stable ImpactInfo.
// CodeGraph's analyze_impact / pr_context payload shapes are not strictly versioned, so we
// read from several plausible key names rather than hard-coding one schema.

import type {
  ImpactInfo, ImpactRef, PrContextInfo, EditContext, SecurityVerdict, StaleDoc, ReachabilityEntryPoint,
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

/**
 * A symbol's display name from a string, a `{ name | qualified_name | ... }` object, or a wrapper
 * `{ symbol: { name, ... } }`. Real CodeGraph nests the name under `symbol.name` (entry points,
 * callers, traverse nodes, get_symbol_info), so a flat `String(x)` would yield "[object Object]".
 */
function symbolNameOf(x: unknown): string | null {
  if (typeof x === "string") return x.trim() || null;
  if (!x || typeof x !== "object") return null;
  const o = x as Raw;
  for (const k of ["name", "qualified_name", "qualifiedName", "symbol", "function", "caller", "handler"]) {
    const v = o[k];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (v && typeof v === "object") {
      const nm = symbolNameOf(v);
      if (nm) return nm;
    }
  }
  return null;
}

/** True when `file` sits inside `root` (same path or a descendant). Both are plain fs paths. */
function isUnderRoot(file: string, root: string): boolean {
  const f = file.replace(/^file:\/\//, "");
  const r = root.replace(/^file:\/\//, "").replace(/\/+$/, "");
  return f === r || f.startsWith(r + "/");
}

/** Last dotted/`#`/`::`-delimited segment of a symbol (StripeClient.charge → charge). */
function bareName(symbol: string): string {
  const m = symbol.split(/[.#]|::/);
  return m[m.length - 1] || symbol;
}

function toRef(x: unknown): ImpactRef | null {
  if (typeof x === "string") {
    const s = x.trim();
    return s ? { symbol: s } : null;
  }
  if (!x || typeof x !== "object") return null;
  const o = x as Raw;
  const symbol = symbolNameOf(pick(o, ["symbol", "name", "function", "caller", "qualified_name", "qualifiedName"]));
  // Location may be flat on the object, a string under `location`, or nested under
  // `location` / `call_site` / `symbol.location` (CodeGraph's envelope).
  const symObj = o["symbol"] && typeof o["symbol"] === "object" ? (o["symbol"] as Raw) : undefined;
  const locObj = pick(o, ["location", "call_site", "callSite"]) ?? (symObj ? pick(symObj, ["location"]) : undefined);
  const file =
    pick(o, ["file", "uri", "path", "filepath"]) ??
    (typeof locObj === "string" ? locObj : pick(locObj, ["file", "uri", "path", "filepath"]));
  const lineRaw =
    pick(o, ["line", "lineno", "row", "start_line", "startLine", "line_start", "lineStart"]) ??
    pick(locObj, ["line", "lineno", "row", "start_line", "startLine", "line_start", "lineStart"]);
  if (file == null && symbol == null) return null;
  const ref: ImpactRef = {};
  if (file != null) ref.file = String(file).replace(/^file:\/\//, "");
  if (typeof lineRaw === "number") ref.line = lineRaw;
  else if (typeof lineRaw === "string" && /^\d+$/.test(lineRaw)) ref.line = Number(lineRaw);
  if (symbol != null) ref.symbol = symbol;
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
  opts: { symbol: string; source: string; maxCallers?: number; repoRoot?: string }
): ImpactInfo | null {
  if (!raw || typeof raw !== "object") return null;
  const max = Math.max(1, opts.maxCallers ?? 20);

  // Callers may sit at the top level, nested under impact/blast_radius, or — for real
  // analyze_impact — under `impacted` (each entry { name, path, line_start, impact_type }).
  const nested = (pick(raw, ["impact", "blast_radius", "blastRadius", "result", "data"]) as Raw) || (raw as Raw);
  const callerListRaw = pick(raw, ["callers", "direct_callers", "affected_callers", "affectedCallers", "callsites", "references", "impacted"]) ??
    pick(nested, ["callers", "direct_callers", "affected_callers", "affectedCallers", "callsites", "references", "impacted"]);
  const callersRaw = asArray(callerListRaw);
  const callers = callersRaw.map(toRef).filter((r): r is ImpactRef => r !== null);

  // Count: an explicit numeric field wins (real analyze_impact: direct_impacted/total_impacted;
  // pr_context function_details: a numeric `callers`). A `callers` that is itself a list is ignored
  // here (it fell through to callers.length).
  const explicitCount =
    numberOf(raw, ["caller_count", "callerCount", "direct_caller_count", "directCallerCount", "impacted_count",
      "direct_impacted", "directImpacted", "total_impacted", "totalImpacted"]) ??
    numberOf(nested, ["caller_count", "callerCount", "direct_caller_count", "directCallerCount", "direct_impacted", "total_impacted"]) ??
    (typeof callerListRaw === "number" ? callerListRaw : (typeof pick(raw, ["callers"]) === "number" ? (pick(raw, ["callers"]) as number) : null));
  const callerCount = explicitCount != null ? explicitCount : callers.length;

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

  // Breaking-change count (analyze_impact with changeType rename/delete tags sites severity:"breaking").
  const breakingCount = numberOf(raw, ["breaking_changes", "breakingChanges", "breaking"]) ??
    numberOf(nested, ["breaking_changes", "breakingChanges"]);

  // Cross-project consumers: an explicit field, or impacted sites whose file is outside the repo root.
  // These are the consumers in OTHER indexed repos a local diff can't see — the highest-signal blast.
  const explicitCross = asArray(
    pick(raw, ["cross_project", "crossProject", "cross_project_impacts", "crossProjectImpacts", "external_consumers", "externalConsumers"]) ??
      pick(nested, ["cross_project", "crossProject", "cross_project_impacts", "external_consumers"])
  ).map(toRef).filter((r): r is ImpactRef => r !== null);
  const structuralCross = opts.repoRoot
    ? callers.filter((c) => c.file && !isUnderRoot(c.file, opts.repoRoot as string))
    : [];
  const seenCross = new Set<string>();
  const crossProject = [...explicitCross, ...structuralCross]
    .filter((r) => {
      const k = `${r.symbol || ""}|${r.file || ""}`;
      if (seenCross.has(k)) return false;
      seenCross.add(k);
      return true;
    })
    .slice(0, max);

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
    ...(breakingCount != null ? { breakingCount } : {}),
    ...(crossProject.length ? { crossProject } : {}),
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

/**
 * Parse a `find_entry_points` payload into a list of entry points. CodeGraph (community) tags each
 * with a kind such as "http_handler" / "event_handler"; we read the handler name, kind, and (when
 * the framework exposes them) the route + method so the reachability trace can name the source.
 */
export function normalizeEntryPoints(raw: unknown): ReachabilityEntryPoint[] {
  const arr = Array.isArray(raw)
    ? raw
    : asArray(pick(raw, ["entry_points", "entryPoints", "entrypoints", "handlers", "results", "items", "data"]));
  const out: ReachabilityEntryPoint[] = [];
  for (const x of arr) {
    if (typeof x === "string") {
      const s = x.trim();
      if (s) out.push({ name: s, kind: "" });
      continue;
    }
    if (!x || typeof x !== "object") continue;
    const o = x as Raw;
    // Real CodeGraph nests the handler name + declaring file under `symbol` (`symbol.name`,
    // `symbol.location.file`) and tags the entry kind as `entry_type`. Older flat shapes put
    // name/kind/route at the top level; read both.
    const name = symbolNameOf(pick(o, ["name", "symbol", "function", "handler", "qualified_name", "qualifiedName"]));
    if (name == null) continue;
    // `entry_type` must win over the nested `symbol.kind` ("Function"), so check it before `kind`.
    const kind = pick(o, ["entry_type", "entryType", "entrypoint_type", "entrypointType", "kind", "type"]);
    const route = pick(o, ["route", "url", "pattern", "endpoint"]) ?? pick(o, ["path"]);
    const method = pick(o, ["method", "http_method", "httpMethod", "verb"]);
    const symObj = o["symbol"] && typeof o["symbol"] === "object" ? (o["symbol"] as Raw) : undefined;
    const file =
      pick(o, ["file", "uri", "filepath"]) ??
      (symObj ? pick(symObj, ["location", "file", "uri"]) : undefined);
    const fileStr = file != null && typeof file === "object" ? pick(file, ["file", "uri", "path"]) : file;
    const ep: ReachabilityEntryPoint = { name, kind: kind != null ? String(kind) : "" };
    if (route != null) ep.route = String(route);
    if (method != null) ep.method = String(method).toUpperCase();
    if (fileStr != null && fileStr !== route) ep.file = String(fileStr).replace(/^file:\/\//, "");
    out.push(ep);
  }
  return out;
}

/**
 * Parse a `get_callers` / `traverse_graph` payload into the set of ancestor call sites of a symbol.
 * Both tools expose the caller list under a handful of keys (and traverse_graph may nest them under
 * `nodes`); we read whichever is present.
 */
export function normalizeAncestors(raw: unknown, opts: { maxCallers?: number } = {}): ImpactRef[] {
  const max = Math.max(1, opts.maxCallers ?? 50);
  const arr = Array.isArray(raw)
    ? raw
    : asArray(
        pick(raw, ["callers", "direct_callers", "transitive_callers", "transitiveCallers", "ancestors",
          "nodes", "references", "callsites", "results", "paths"]) ??
          pick(pick(raw, ["graph", "result", "data"]), ["callers", "nodes", "ancestors", "references"])
      );
  return arr.map(toRef).filter((r): r is ImpactRef => r !== null).slice(0, max);
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

  // Real CodeGraph pr_context returns a flat caller-edge list (`caller` → `calls`); group it by
  // callee so each changed symbol can name its call sites, not just count them.
  const namedCallers = new Map<string, ImpactRef[]>();
  for (const e of asArray(pick(raw, ["callers", "direct_callers_list", "caller_edges"]))) {
    if (!e || typeof e !== "object") continue;
    const callee = symbolNameOf(pick(e, ["calls", "callee", "target", "to"]));
    if (!callee) continue;
    const callerName = symbolNameOf(pick(e, ["caller", "from", "source"]));
    const file = pick(e, ["file", "path", "uri"]);
    const ref: ImpactRef = {};
    if (callerName) ref.symbol = callerName;
    if (file != null) ref.file = String(file).replace(/^file:\/\//, "");
    if (!ref.symbol && !ref.file) continue;
    for (const key of new Set([callee, bareName(callee)])) {
      const arr = namedCallers.get(key) ?? [];
      arr.push(ref);
      namedCallers.set(key, arr);
    }
  }

  // Functions flagged untested at the PR level (test_gaps entries carry `function`/`name`).
  const untested = new Set<string>();
  for (const t of asArray(pick(raw, ["test_gaps", "testGaps", "untested", "untested_functions", "missing_tests", "missingTests"]))) {
    const nm = symbolNameOf(t && typeof t === "object" ? (pick(t, ["function", "name", "symbol"]) ?? t) : t);
    if (nm) { untested.add(nm); untested.add(bareName(nm)); }
  }

  // PR-level suggested reviewers ([{ author, lines_owned }]) — applied to each changed symbol that
  // doesn't carry its own (real function_details have none; older per-symbol shapes do).
  const prReviewers = asArray(pick(raw, ["suggested_reviewers", "suggestedReviewers", "reviewers", "owners", "codeowners"]))
    .map((r) => ({ name: toReviewer(r), weight: reviewerWeight(r) }))
    .filter((r): r is { name: string; weight: number } => r.name !== null)
    .sort((a, b) => b.weight - a.weight)
    .map((r) => r.name)
    .filter((name, i, arr) => arr.indexOf(name) === i);

  // Per-symbol blast radius: real CodeGraph uses `function_details` (name + numeric caller count +
  // complexity + has_tests); older shapes use changed_functions/symbols with array callers.
  const entries = asArray(
    pick(raw, ["function_details", "functionDetails", "changed_functions", "changedFunctions", "changes", "symbols", "functions", "results", "items"])
  );
  const bySymbol: Record<string, ImpactInfo> = {};
  for (const entry of entries) {
    const sym = symbolKey(entry);
    if (!sym) continue;
    const im = normalizeImpact(entry, { symbol: sym, source: opts.source, maxCallers: max });
    if (!im) continue;
    const named = namedCallers.get(sym) ?? namedCallers.get(bareName(sym)) ?? [];
    if (named.length) {
      im.callers = named.slice(0, max);
      if (!im.callerCount) im.callerCount = named.length;
      im.truncated = im.truncated || named.length > max;
    }
    if ((untested.has(sym) || untested.has(bareName(sym))) && im.testGaps.length === 0) {
      im.testGaps = [{ symbol: sym }];
    }
    if (prReviewers.length && im.reviewers.length === 0) im.reviewers = prReviewers;
    bySymbol[sym] = im;
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
