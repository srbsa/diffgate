// Borrowed-recall orchestration (docs/DESIGN-recall-and-parity.md, option B). Resolves a recall
// provider (gated: off by default, "ci" only under CI, requires the binary) and attaches its findings
// to a review — diff-scoped, deduped against native findings, ADVISORY-only (never blocking).

import path from "path";
import { overallTier, tierCounts } from "../tiers.js";
import { makeSemgrepProvider, semgrepAvailable, diffScope, dedupeAgainst, toFindings } from "./semgrep.js";
import type { RecallProvider, RawRecallFinding } from "./semgrep.js";
import type { AnalyzeResult, Config, RecallConfig } from "../types.js";

export const DEFAULT_RECALL_CONFIG: Required<RecallConfig> = {
  enabled: false,
  provider: "semgrep",
  command: "semgrep",
  config: "auto",
  timeoutMs: 60000,
};

export function resolveRecallConfig(config: Partial<Config>): Required<RecallConfig> {
  return { ...DEFAULT_RECALL_CONFIG, ...(config.recall || {}) };
}

/** Is borrowed recall active? false (default) → no; "ci" → only under CI; true → always. */
export function recallActive(g: { enabled?: boolean | "ci" }, env: NodeJS.ProcessEnv = process.env): boolean {
  if (g.enabled === true) return true;
  if (g.enabled === "ci") return !!(env["CI"] && env["CI"] !== "false" && env["CI"] !== "0");
  return false;
}

/**
 * Resolve a recall provider, or null when recall is off / unavailable. Pass `opts.provider` to inject
 * one (tests, or a host that owns the scanner). Returns null unless recall is active AND the binary
 * resolves — so the default (recall off) path never spawns anything.
 */
export function getRecallProvider(
  cwd: string,
  config: Partial<Config>,
  opts: { provider?: RecallProvider | null } = {}
): RecallProvider | null {
  if (opts.provider !== undefined) return opts.provider;
  const g = resolveRecallConfig(config);
  if (!recallActive(g)) return null;
  if (g.provider !== "semgrep") return null;
  if (!semgrepAvailable(g.command)) return null;
  return makeSemgrepProvider({ command: g.command, config: g.config, timeoutMs: g.timeoutMs });
}

function recompute(result: AnalyzeResult, findings: AnalyzeResult["findings"]): AnalyzeResult {
  return {
    ...result,
    findings,
    tier: overallTier(findings),
    counts: tierCounts(findings),
    blocking: findings.some((f) => f.blocking),
  };
}

/**
 * Attach borrowed findings to each result. No-op (input returned unchanged) when `provider` is null.
 * Runs ONE batched scan over every file's path (amortizing cold start), then per file: diff-scope to
 * changed lines, drop anything a native finding already covers, map to advisory findings, merge.
 */
export function attachRecall(
  files: AnalyzeResult[],
  opts: { cwd: string; config: Partial<Config>; changed?: Map<string, Set<number> | null>; provider: RecallProvider | null }
): AnalyzeResult[] {
  const provider = opts.provider;
  if (!provider || files.length === 0) return files;

  const paths = files.map((f) => f.filePath);
  let byPath: Map<string, RawRecallFinding[]> | null = null;
  try {
    if (typeof provider.scanFiles === "function") {
      byPath = provider.scanFiles(paths);
    } else {
      byPath = new Map();
      for (const f of files) {
        const r = provider.scan(f.filePath, "");
        if (r) byPath.set(f.filePath, r);
      }
    }
  } catch {
    byPath = null;
  }
  if (!byPath) return files;

  // Match semgrep's echoed path robustly: key a second index by resolved absolute path.
  const resolved = new Map<string, RawRecallFinding[]>();
  for (const [k, v] of byPath) resolved.set(path.resolve(opts.cwd, k), v);

  return files.map((result) => {
    const raw = byPath!.get(result.filePath) ?? resolved.get(path.resolve(opts.cwd, result.filePath)) ?? [];
    if (raw.length === 0) return result;
    const changedLines = opts.changed?.get(result.filePath) ?? null;
    const borrowed = toFindings(dedupeAgainst(diffScope(raw, changedLines), result.findings));
    if (borrowed.length === 0) return result;
    const findings = [...result.findings, ...borrowed].sort((a, b) => a.line - b.line);
    return recompute(result, findings);
  });
}

export {
  makeSemgrepProvider, semgrepAvailable, parseSemgrep, mapSeverityToTier, diffScope, dedupeAgainst, toFindings,
} from "./semgrep.js";
export type { RecallProvider, RawRecallFinding, SemgrepRunner, SemgrepBatchRunner } from "./semgrep.js";
