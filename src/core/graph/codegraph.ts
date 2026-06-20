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
import type { GraphConfig, ImpactInfo, PrContextInfo, EditContext, SecurityVerdict, ImpactRef } from "../types.js";
import type { GraphProvider, ImpactQuery, PrContextQuery, SecurityQuery } from "./index.js";
import { normalizeImpact, normalizePrContext, normalizeEditContext, normalizeSecurity, normalizeTests } from "./normalize.js";

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

export function makeCodeGraphProvider(cwd: string, g: GraphConfig = {}, runner?: GraphRunner): GraphProvider {
  const run = runner || defaultRunner(cwd, g);
  const maxCallers = g.maxCallers ?? 20;

  // Run a tool by bare name, retrying with the `codegraph_` namespace if the bare call yields nothing.
  const call = (tool: string, args: Record<string, unknown>): unknown => {
    const first = parseJsonLoose(run({ tool, args }));
    if (first != null) return first;
    if (!tool.startsWith("codegraph_")) {
      return parseJsonLoose(run({ tool: `codegraph_${tool}`, args }));
    }
    return null;
  };

  const absUri = (q: { file: string; cwd?: string }): string =>
    path.isAbsolute(q.file) ? q.file : path.join(q.cwd || cwd, q.file);

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

    reindex(opts: { full?: boolean } = {}): boolean {
      const out = call("reindex_workspace", { path: cwd, root: cwd, full: opts.full ?? false });
      return out != null;
    },
  };
}
