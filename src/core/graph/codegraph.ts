// CodeGraph driver — one-shot CLI queries against github.com/codegraph-ai/CodeGraph.
//
//   codegraph-server --graph-only --run-tool analyze_impact --tool-args '{"uri":...,"line":...}'
//
// The graph indexes committed/disk state, so "who calls this changed symbol" is robust
// (callers pre-exist). All failures (missing binary, unindexed repo, timeout, bad JSON)
// degrade to null — the caller treats that as "no impact data", never an error.
//
// CodeGraph exposes its tools both bare (`analyze_impact`) and namespaced
// (`codegraph_analyze_impact`) depending on version/profile, so each call tries the bare
// name first and retries with the prefix before giving up.

import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import type {
  GraphConfig, ImpactInfo, PrContextInfo, EditContext, SecurityVerdict, ImpactRef,
  ReachabilityVerdict, ReachabilityEntryPoint,
} from "../types.js";
import type { GraphProvider, ImpactQuery, PrContextQuery, SecurityQuery, ReachabilityQuery } from "./index.js";
import {
  normalizeImpact, normalizePrContext, normalizeEditContext, normalizeSecurity, normalizeTests,
  normalizeEntryPoints, normalizeAncestors,
} from "./normalize.js";

const DEFAULT_COMMAND = "codegraph-server";
const DEFAULT_TIMEOUT = 4000;

/** A run of one graph tool. Returns raw stdout (JSON), or null on any failure. Injectable for tests. */
export type GraphRunner = (call: { tool: string; args: Record<string, unknown> }) => string | null;

export function graphDbDir(): string {
  return path.join(os.homedir(), ".codegraph", "graph.db");
}

/** True if `cmd` is an existing absolute path, or resolves on PATH. Cheap, no tool spawn. */
export function commandAvailable(cmd: string): boolean {
  if (!cmd) return false;
  try {
    if (path.isAbsolute(cmd)) return fs.existsSync(cmd);
    const exts = process.platform === "win32" ? (process.env["PATHEXT"] || ".EXE;.CMD;.BAT").split(";") : [""];
    const dirs = (process.env["PATH"] || "").split(path.delimiter).filter(Boolean);
    for (const dir of dirs) {
      for (const ext of exts) {
        if (fs.existsSync(path.join(dir, cmd + ext))) return true;
      }
    }
  } catch {
    /* fall through */
  }
  return false;
}

/**
 * Cheap, side-effect-free availability check: an indexed RocksDB store exists.
 * Without an index there is nothing to query, so this is the right gate — and it
 * avoids spawning a process on every review just to detect presence.
 */
export function codeGraphAvailable(g: GraphConfig = {}): boolean {
  if (g.mode === "off" || g.enabled === false) return false;
  const cmd = g.command || DEFAULT_COMMAND;
  // An absolute command path that exists is a strong signal regardless of indexing.
  if (path.isAbsolute(cmd) && fs.existsSync(cmd)) return true;
  try {
    return fs.existsSync(graphDbDir());
  } catch {
    return false;
  }
}

function defaultRunner(cwd: string, g: GraphConfig): GraphRunner {
  const command = g.command || DEFAULT_COMMAND;
  const timeout = g.timeoutMs ?? DEFAULT_TIMEOUT;
  return ({ tool, args }) => {
    try {
      const out = execFileSync(
        command,
        ["--graph-only", "--run-tool", tool, "--tool-args", JSON.stringify(args)],
        { cwd, encoding: "utf-8", timeout, stdio: ["ignore", "pipe", "ignore"], maxBuffer: 8 * 1024 * 1024 }
      );
      return out;
    } catch {
      return null;
    }
  };
}

function parseJsonLoose(stdout: string | null): unknown {
  if (!stdout) return null;
  const trimmed = stdout.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    // Tolerate leading log lines: grab the last balanced {...} or [...] block.
    const start = trimmed.search(/[[{]/);
    if (start === -1) return null;
    for (let end = trimmed.length; end > start; end--) {
      const slice = trimmed.slice(start, end);
      try {
        return JSON.parse(slice);
      } catch {
        /* keep shrinking */
      }
    }
    return null;
  }
}

/** Last dotted/`#`/`::`-delimited segment of a symbol (UserController#show → show). */
function bareName(symbol: string): string {
  const m = symbol.split(/[.#]|::/);
  return m[m.length - 1] || symbol;
}

/** The enclosing function CodeGraph resolved for a file:line query — get_callers / get_callees
 *  echo it back as `symbol_name` (after their nearest-symbol fallback), so we can name the sink's
 *  function without a separate get_symbol_info round-trip. */
function enclosingNameOf(raw: unknown): string {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const v = (raw as Record<string, unknown>)["symbol_name"];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return "";
}

/** Best-effort symbol name from a get_symbol_info / get_detailed_symbol payload. */
function symbolNameOf(raw: unknown): string | null {
  if (typeof raw === "string") return raw.trim() || null;
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  for (const k of ["symbol", "name", "function", "enclosing", "enclosingFunction", "enclosing_function", "qualified_name", "qualifiedName"]) {
    const v = o[k];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (v && typeof v === "object") {
      const nm = symbolNameOf(v);
      if (nm) return nm;
    }
  }
  return null;
}

export function makeCodeGraphProvider(cwd: string, g: GraphConfig = {}, runner?: GraphRunner): GraphProvider {
  const run = runner || defaultRunner(cwd, g);
  const maxCallers = g.maxCallers ?? 20;

  // Run a tool by bare name, retrying with the `codegraph_` namespace if the bare call yields nothing.
  const callWith = (runFn: GraphRunner, tool: string, args: Record<string, unknown>): unknown => {
    const first = parseJsonLoose(runFn({ tool, args }));
    if (first != null) return first;
    if (!tool.startsWith("codegraph_")) {
      return parseJsonLoose(runFn({ tool: `codegraph_${tool}`, args }));
    }
    return null;
  };
  const call = (tool: string, args: Record<string, unknown>): unknown => callWith(run, tool, args);

  // Reachability walks (entry points + caller chains) get their own timeout budget. An injected
  // runner (tests) is shared so canned responses still flow through.
  const reachTimeout = g.reachabilityTimeoutMs ?? g.timeoutMs ?? DEFAULT_TIMEOUT;
  const reachRun = runner || defaultRunner(cwd, { ...g, timeoutMs: reachTimeout });
  const reachCall = (tool: string, args: Record<string, unknown>): unknown => callWith(reachRun, tool, args);

  // find_entry_points is identical for every finding in a review — fetch once, memoize.
  // `undefined` = not yet fetched; `null` = fetched and unavailable.
  let entryPointsMemo: ReachabilityEntryPoint[] | null | undefined;
  const getEntryPoints = (): ReachabilityEntryPoint[] | null => {
    if (entryPointsMemo !== undefined) return entryPointsMemo;
    const raw = reachCall("find_entry_points", {});
    entryPointsMemo = raw == null ? null : normalizeEntryPoints(raw);
    return entryPointsMemo;
  };

  // The absolute filesystem path of a finding's file (for display / the reachability trace).
  const absPath = (q: { file: string; cwd?: string }): string =>
    path.isAbsolute(q.file) ? q.file : path.join(q.cwd || cwd, q.file);
  // CodeGraph's uri+line lookups (get_callers, get_symbol_info, analyze_impact, …) require a
  // `file://` URI — a bare path resolves to "Could not find starting node". Always scheme it.
  const absUri = (q: { file: string; cwd?: string }): string => {
    const p = absPath(q);
    return p.startsWith("file://") ? p : `file://${p}`;
  };

  return {
    id: "codegraph",

    impact(query: ImpactQuery): ImpactInfo | null {
      const uri = absUri(query);
      const raw = call("analyze_impact", { uri, file: uri, line: query.line, symbol: query.symbol });
      if (raw == null) return null;
      return normalizeImpact(raw, { symbol: query.symbol, source: "codegraph", maxCallers });
    },

    prContext(query: PrContextQuery): PrContextInfo | null {
      const args: Record<string, unknown> = {};
      if (query.baseBranch) { args["baseBranch"] = query.baseBranch; args["base_branch"] = query.baseBranch; }
      const raw = call("pr_context", args);
      if (raw == null) return null;
      return normalizePrContext(raw, { source: "codegraph", maxCallers });
    },

    relatedTests(query: ImpactQuery): ImpactRef[] | null {
      const uri = absUri(query);
      const raw = call("find_related_tests", { uri, file: uri, line: query.line, symbol: query.symbol });
      if (raw == null) return null;
      return normalizeTests(raw, { maxCallers });
    },

    editContext(query: ImpactQuery): EditContext | null {
      const uri = absUri(query);
      const raw = call("get_edit_context", { uri, file: uri, line: query.line, symbol: query.symbol });
      if (raw == null) return null;
      return normalizeEditContext(raw, { source: "codegraph", maxCallers });
    },

    security(query: SecurityQuery): SecurityVerdict | null {
      const uri = absUri(query);
      const args = { uri, file: uri, line: query.line, symbol: query.symbol, rule: query.ruleId, sink: query.sink };
      // Prefer the dedicated injection detector; fall back to a raw data-flow trace.
      const raw = call("security_detect_injection", args) ?? call("security_trace_data_flow", args);
      if (raw == null) return null;
      return normalizeSecurity(raw, { source: "codegraph", maxCallers });
    },

    // Community-edition precision: walk the (deterministic, AST-derived) call graph from the sink
    // back toward untrusted entry points. No Pro security_* tools required. Any "can't tell" path
    // returns null (= unknown), never a false "unreachable" — the caller's fail-safe depends on it.
    reachability(query: ReachabilityQuery): ReachabilityVerdict | null {
      const kinds = query.untrustedKinds && query.untrustedKinds.length
        ? query.untrustedKinds
        : ["http_handler", "event_handler"];
      const maxDepth = query.maxDepth ?? 6;

      // 1. Untrusted entry points (memoized per review). If the index knows of none, we cannot prove
      //    reachability either way → unknown (null), never "unreachable".
      const entryPoints = getEntryPoints();
      if (!entryPoints || entryPoints.length === 0) return null;
      const untrusted = entryPoints.filter((ep) => kinds.includes(ep.kind));
      if (untrusted.length === 0) return null;

      // 2. Transitive callers of the sink's function — everyone who can reach this code. CodeGraph
      //    resolves the enclosing function from file:line (nearest-symbol fallback) and echoes its
      //    name as `symbol_name`, so callers + the enclosing name come back in one call.
      const uri = absUri(query);
      const callersRaw =
        reachCall("get_callers", { uri, file: uri, line: query.line, depth: maxDepth, maxDepth }) ??
        reachCall("traverse_graph", { uri, file: uri, direction: "incoming", edgeTypes: ["calls"], maxDepth });
      if (callersRaw == null) return null; // graph could not answer → unknown

      // 3. The sink's enclosing function: the finding's own symbol, else the name CodeGraph resolved,
      //    else a direct symbol lookup. Needed so a sink written straight in a handler body matches.
      let enclosing = query.symbol || enclosingNameOf(callersRaw);
      if (!enclosing) {
        const info = reachCall("get_symbol_info", { uri, file: uri, line: query.line })
          ?? reachCall("get_detailed_symbol", { uri, file: uri, line: query.line });
        enclosing = symbolNameOf(info) || "";
      }

      const ancestors = normalizeAncestors(callersRaw, { maxCallers: 100 });

      // Fail-safe: if CodeGraph could neither resolve the sink's enclosing function (no symbol on the
      // finding, no echoed `symbol_name`, no get_symbol_info) NOR return any caller, it could not
      // locate the sink at all — e.g. a cold / partially-built index answering "Could not find
      // starting node". That is UNKNOWN (null), never a false "unreachable". (A function the graph
      // *did* resolve which genuinely has no callers is a legitimate reachable:false below.)
      if (!enclosing && ancestors.length === 0) return null;

      const names = new Set<string>();
      for (const a of ancestors) {
        if (a.symbol) { names.add(a.symbol); names.add(bareName(a.symbol)); }
      }
      // The sink's own function may itself be the handler (sink written directly in the route body).
      if (enclosing) { names.add(enclosing); names.add(bareName(enclosing)); }

      // 4. Reachable iff an untrusted entry point sits in the ancestor set (or is the sink's function).
      const matched = untrusted.filter((ep) => names.has(ep.name) || names.has(bareName(ep.name)));
      const verdict: ReachabilityVerdict = {
        reachable: matched.length > 0,
        source: "codegraph",
        entryPoints: matched.slice(0, maxCallers),
      };
      if (verdict.reachable) {
        const ep = matched[0];
        const sinkRef: ImpactRef = { file: absPath(query), line: query.line };
        if (enclosing) sinkRef.symbol = enclosing;
        const epRef: ImpactRef = { symbol: ep.name };
        if (ep.file) epRef.file = ep.file;
        verdict.path = [sinkRef, epRef];
        verdict.depth = enclosing && (ep.name === enclosing || bareName(ep.name) === bareName(enclosing)) ? 0 : 1;
      }
      return verdict;
    },

    reindex(opts: { full?: boolean } = {}): boolean {
      const out = call("reindex_workspace", { path: cwd, root: cwd, full: opts.full ?? false });
      return out != null;
    },
  };
}
