// Optional code-graph layer. Provides deterministic cross-file blast radius when a graph
// backend is present; returns null (→ no impact data, never an error) when it is not.

import type { Config, GraphConfig, ImpactInfo } from "../types.js";
import { makeCodeGraphProvider, codeGraphAvailable } from "./codegraph.js";

export interface ImpactQuery {
  /** Symbol name being changed (e.g. an exported function). */
  symbol: string;
  /** Absolute or repo-relative path to the file containing the symbol. */
  file: string;
  /** 1-based line of the symbol. */
  line: number;
  /** Repo root. */
  cwd: string;
}

export interface GraphProvider {
  id: string;
  /** One-shot impact lookup. Returns null on any failure — the caller treats null as "no data". */
  impact(query: ImpactQuery): ImpactInfo | null;
}

export const DEFAULT_GRAPH_CONFIG: Required<Omit<GraphConfig, "command">> & { command: string } = {
  enabled: "auto",
  provider: "codegraph",
  command: "codegraph-server",
  mode: "cli",
  maxCallers: 20,
  escalateThreshold: 1,
  timeoutMs: 4000,
};

export function resolveGraphConfig(config: Partial<Config>): typeof DEFAULT_GRAPH_CONFIG {
  return { ...DEFAULT_GRAPH_CONFIG, ...(config.graph || {}) };
}

/**
 * Resolve a graph provider for this repo, or null when graphing is disabled/unavailable.
 * Pass `opts.provider` to inject one (tests, or an embedding host that owns the graph).
 */
export function getGraph(
  cwd: string,
  config: Partial<Config>,
  opts: { provider?: GraphProvider | null } = {}
): GraphProvider | null {
  if (opts.provider !== undefined) return opts.provider;
  const g = resolveGraphConfig(config);
  if (g.enabled === false || g.mode === "off") return null;
  if (g.provider === "codegraph") {
    if (!codeGraphAvailable(g)) return null;
    return makeCodeGraphProvider(cwd, g);
  }
  return null;
}

export { makeCodeGraphProvider, codeGraphAvailable } from "./codegraph.js";
export { normalizeImpact } from "./normalize.js";
export type { GraphRunner } from "./codegraph.js";
export type { ImpactInfo };
