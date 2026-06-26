// Optional code-graph layer. Provides deterministic cross-file blast radius when a graph
// backend is present; returns null (→ no impact data, never an error) when it is not.

import fs from "fs";
import type {
  Config, GraphConfig, ImpactInfo, PrContextInfo, EditContext, SecurityVerdict, ImpactRef,
  ReachabilityVerdict,
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

export interface ReachabilityQuery extends ImpactQuery {
  /** Entry-point kinds treated as untrusted taint roots (e.g. ["http_handler", "event_handler"]). */
  untrustedKinds?: string[];
  /** Max caller-chain hops to walk before giving up. */
  maxDepth?: number;
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
  /** Community-edition reachability for an injection sink: is it reachable from an untrusted entry
   *  point? null = unknown (NOT "unreachable"). No Pro binary required. Optional. */
  reachability?(query: ReachabilityQuery): ReachabilityVerdict | null;
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
  reachability: "auto",
  reachabilityDeescalate: false,
  untrustedEntryKinds: ["http_handler", "event_handler"],
  reachabilityMaxDepth: 6,
  reachabilityTimeoutMs: 4000,
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
  /** Reachability escalation is enabled (graph.reachability !== false). */
  reachability: boolean;
  /** Age of the index (ms since its mtime) when indexed; null otherwise. Reachability is only as
   *  good as the index — a stale index can make a reachable sink look unreachable. */
  indexAgeMs: number | null;
  /** A short human-readable explanation of the current state. */
  reason: string;
}

/** Coarse human age ("3 days", "5 hours", "just now") for a millisecond span. */
function humanizeAge(ms: number): string {
  const days = Math.floor(ms / 86_400_000);
  if (days >= 1) return `${days} day${days === 1 ? "" : "s"}`;
  const hours = Math.floor(ms / 3_600_000);
  if (hours >= 1) return `${hours} hour${hours === 1 ? "" : "s"}`;
  const mins = Math.floor(ms / 60_000);
  if (mins >= 1) return `${mins} min`;
  return "just now";
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
  const reachability = enabled && g.reachability !== false;

  let indexAgeMs: number | null = null;
  if (indexed) {
    try {
      indexAgeMs = Math.max(0, Date.now() - fs.statSync(dbPath).mtimeMs);
    } catch {
      indexAgeMs = null;
    }
  }

  let reason: string;
  if (!enabled) reason = "Graphing is disabled in config (graph.enabled=false or mode=off).";
  else if (indexed) {
    const age = indexAgeMs != null ? ` Index is ${humanizeAge(indexAgeMs)} old` : "";
    const stale = indexAgeMs != null && indexAgeMs > 7 * 86_400_000
      ? " — run `diffgate graph index` if your diff touches newer files (reachability depends on the index)." : ".";
    reason = `Indexed at ${dbPath}.${age}${age ? stale : ""}`;
  } else if (commandFound) reason = `${g.command} is installed but no index found — run \`diffgate graph index\`.`;
  else reason = `${g.command} not found on PATH — install CodeGraph, then run \`diffgate graph index\`.`;

  return { enabled, indexed, commandFound, command: g.command, dbPath, reachability, indexAgeMs, reason };
}

export { makeCodeGraphProvider, codeGraphAvailable, commandAvailable, graphDbDir } from "./codegraph.js";
export { normalizeImpact, normalizePrContext, normalizeEditContext, normalizeSecurity, normalizeTests, normalizeEntryPoints, normalizeAncestors } from "./normalize.js";
export type { GraphRunner } from "./codegraph.js";
export type { ImpactInfo };
