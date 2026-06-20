// CodeGraph driver — one-shot CLI queries against github.com/codegraph-ai/CodeGraph.
//
//   codegraph-server --graph-only --run-tool analyze_impact --tool-args '{"uri":...,"line":...}'
//
// The graph indexes committed/disk state, so "who calls this changed symbol" is robust
// (callers pre-exist). All failures (missing binary, unindexed repo, timeout, bad JSON)
// degrade to null — the caller treats that as "no impact data", never an error.

import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import type { GraphConfig, ImpactInfo } from "../types.js";
import type { GraphProvider, ImpactQuery } from "./index.js";
import { normalizeImpact } from "./normalize.js";

const DEFAULT_COMMAND = "codegraph-server";
const DEFAULT_TIMEOUT = 4000;

/** A run of one graph tool. Returns raw stdout (JSON), or null on any failure. Injectable for tests. */
export type GraphRunner = (call: { tool: string; args: Record<string, unknown> }) => string | null;

function graphDbDir(): string {
  return path.join(os.homedir(), ".codegraph", "graph.db");
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

/**
 * Build a CodeGraph-backed provider. Pass `runner` to inject a fake (tests); omit to spawn the real CLI.
 */
export function makeCodeGraphProvider(cwd: string, g: GraphConfig = {}, runner?: GraphRunner): GraphProvider {
  const run = runner || defaultRunner(cwd, g);
  const maxCallers = g.maxCallers ?? 20;
  return {
    id: "codegraph",
    impact(query: ImpactQuery): ImpactInfo | null {
      const uri = path.isAbsolute(query.file) ? query.file : path.join(query.cwd || cwd, query.file);
      const raw = parseJsonLoose(
        run({ tool: "analyze_impact", args: { uri, file: uri, line: query.line, symbol: query.symbol } })
      );
      if (raw == null) return null;
      return normalizeImpact(raw, { symbol: query.symbol, source: "codegraph", maxCallers });
    },
  };
}
