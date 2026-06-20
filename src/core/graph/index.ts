// Optional code-graph layer. Provides deterministic cross-file blast radius when a graph
// backend is present; returns null (→ no impact data, never an error) when it is not.

import type {
  Config, GraphConfig, ImpactInfo, PrContextInfo, EditContext, SecurityVerdict, ImpactRef,
} from "../types.js";
import { makeCodeGraphProvider, codeGraphAvailable, commandAvailable, graphDbDir } from "./codegraph.js";

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

export interface PrContextQuery {
  /** Repo root. */
  cwd: string;
  /** Branch/ref to diff against (e.g. "main"). Optional — the graph picks a sensible default. */
  baseBranch?: string;
  /** "staged" | "working" — which diff scope to analyze. */
  mode?: string;
}

export interface SecurityQuery extends ImpactQuery {
  /** The injection-class rule that fired (e.g. "sql-injection"), to hint the detector. */
  ruleId: string;
  /** The flagged sink code, when available. */
  sink?: string;
}

export interface GraphProvider {
  id: string;
  /** One-shot impact lookup. Returns null on any failure — the caller treats null as "no data". */
  impact(query: ImpactQuery): ImpactInfo | null;
  /** Whole-diff impact in one call (callers + test gaps + reviewers + stale docs + complexity). Optional. */
  prContext?(query: PrContextQuery): PrContextInfo | null;
  /** Tests that cover a symbol. Empty array = authoritatively untested. Optional. */
  relatedTests?(query: ImpactQuery): ImpactRef[] | null;
  /** Pre-edit context (callers/tests/history) for a symbol. Optional. */
  editContext?(query: ImpactQuery): EditContext | null;
  /** Graph-aware taint verdict for an injection sink (Pro). null = unavailable/unsure. Optional. */
  security?(query: SecurityQuery): SecurityVerdict | null;
  /** (Re)index the workspace. Returns true on success. Optional. */
  reindex?(opts?: { full?: boolean }): boolean;
}

export const DEFAULT_GRAPH_CONFIG: Required<Omit<GraphConfig, "command">> & { command: string } = {
  enabled: "auto",
  provider: "codegraph",
  command: "codegraph-server",
  mode: "cli",
  maxCallers: 20,
  escalateThreshold: 1,
  timeoutMs: 4000,
  prContext: true,
  relatedTests: true,
  editContext: true,
  security: "auto",
  securityDeescalate: false,
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

export interface GraphStatus {
  /** Graphing is turned on in config (not disabled / mode:off). */
  enabled: boolean;
  /** An index exists, so queries can return data right now. */
  indexed: boolean;
  /** The graph binary resolves on PATH (or is an existing absolute path). */
  commandFound: boolean;
  /** Resolved command name/path. */
  command: string;
  /** Expected index location. */
  dbPath: string;
  /** A short human-readable explanation of the current state. */
  reason: string;
}

/**
 * Describe the code-graph setup for `diffgate graph status` and the adoption tip.
 * Filesystem + PATH checks only — never spawns the graph tool.
 */
export function graphStatus(config: Partial<Config>): GraphStatus {
  const g = resolveGraphConfig(config);
  const enabled = !(g.enabled === false || g.mode === "off");
  const indexed = enabled && codeGraphAvailable(g);
  const commandFound = commandAvailable(g.command);
  const dbPath = graphDbDir();
  let reason: string;
  if (!enabled) reason = "Graphing is disabled in config (graph.enabled=false or mode=off).";
  else if (indexed) reason = `Indexed at ${dbPath}.`;
  else if (commandFound) reason = `${g.command} is installed but no index found — run \`diffgate graph index\`.`;
  else reason = `${g.command} not found on PATH — install CodeGraph, then run \`diffgate graph index\`.`;
  return { enabled, indexed, commandFound, command: g.command, dbPath, reason };
}

export { makeCodeGraphProvider, codeGraphAvailable, commandAvailable, graphDbDir } from "./codegraph.js";
export { normalizeImpact, normalizePrContext, normalizeEditContext, normalizeSecurity, normalizeTests } from "./normalize.js";
export type { GraphRunner } from "./codegraph.js";
export type { ImpactInfo };
