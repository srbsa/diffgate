export { analyze } from "./analyzer.js";
export { loadConfig, findConfigPath, loadDotenv, isIgnored, DEFAULT_CONFIG } from "./config.js";
export {
  getChangedFiles,
  getChangedLinesForFile,
  getPreviousContent,
  isGitRepo,
  repoRoot,
  headSha,
  blameLine,
} from "./git.js";
export { detectLanguage, hasAstSupport } from "./parsers/index.js";
export { computeChangedLines } from "./linediff.js";
export { getRules, ruleCatalog } from "./rules/index.js";
export type { RuleCatalogEntry } from "./rules/index.js";
export { runGate, runCommand, shouldGate } from "./checks.js";
export {
  explainFinding,
  isAiAvailable,
  aiKeyEnv,
  describeProvider,
  complete,
  resolveProvider,
  selectModel,
  PROVIDERS,
} from "./llm/index.js";
export { deepReview, deepModel } from "./agent/index.js";
export { reviewGuidelines, evaluateGuidelines, resolveGuidelinesForFile, applyDepthCap, STANDARD_GUIDELINE_FILES } from "./guidelines/index.js";
export { loadLearnings, loadMergedLearnings, mergeLearningStores, readStoreFile, recordLearning, applyLearnings, isDismissed, codeHash } from "./learnings.js";
export { TOOLS as agentTools } from "./agent/tools.js";
export { TIERS, TIER_META, TIER_ORDER, maxTier, overallTier, tierCounts, isTier } from "./tiers.js";
export {
  getGraph, resolveGraphConfig, graphStatus, makeCodeGraphProvider, codeGraphAvailable,
  commandAvailable, graphDbDir, normalizeImpact, normalizePrContext, normalizeEditContext,
  normalizeSecurity, normalizeTests, DEFAULT_GRAPH_CONFIG,
} from "./graph/index.js";
export type { GraphProvider, ImpactQuery, PrContextQuery, SecurityQuery, GraphStatus, GraphRunner } from "./graph/index.js";
export { attachImpact, IMPACT_RULES } from "./impact.js";
export { attachSecurity, SECURITY_RULES, labelTrust, trustFor } from "./security.js";
export { buildCapabilities, capabilityHint } from "./capabilities.js";
export type { Capabilities } from "./capabilities.js";
export { predictedSignal, realizedSignal } from "./signal.js";
export { isSanitizerCall, resolvesToSanitizer, classifySecret, shannonEntropy } from "./taint.js";
export { loadState, shouldShowGraphTip, recordGraphTipShown, GRAPH_TIP_LIMIT } from "./state.js";
export { recordTurn, findingFingerprint, loadSession, clearSession, DEFAULT_SESSION_TTL_MS } from "./session.js";

import fs from "fs";
import { analyze } from "./analyzer.js";
import { loadConfig as _loadConfig, isIgnored as _isIgnored } from "./config.js";
import { getChangedFiles as _getChangedFiles, getPreviousContent as _getPreviousContent, repoRoot as _repoRoot } from "./git.js";
import { overallTier as _overallTier, tierCounts as _tierCounts } from "./tiers.js";
import { loadMergedLearnings as _loadMergedLearnings, applyLearnings as _applyLearnings } from "./learnings.js";
import { getGraph as _getGraph } from "./graph/index.js";
import { attachImpact as _attachImpact } from "./impact.js";
import { attachSecurity as _attachSecurity, labelTrust as _labelTrust } from "./security.js";
import type { GraphProvider } from "./graph/index.js";
import type { Config, AnalyzeResult } from "./types.js";

export interface ReviewResult {
  files: AnalyzeResult[];
  tier: string;
  counts: { green: number; yellow: number; orange: number };
  blocking: boolean;
  config: Config;
}

export function reviewChanges(cwd: string, opts: { mode?: string; base?: string; graph?: GraphProvider | null } = {}): ReviewResult {
  const { config } = _loadConfig(cwd);
  const mode = opts.mode || config.gate.mode || "working";
  const base = opts.base;
  const changed = _getChangedFiles(cwd, { mode, base });
  const root = _repoRoot(cwd) || cwd;
  const learnings = _loadMergedLearnings(root, config.learnings?.shared || [], root);
  let files: AnalyzeResult[] = [];

  for (const [filePath, changedLines] of changed) {
    if (_isIgnored(filePath, config, cwd)) continue;
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }
    const previousContent = _getPreviousContent(cwd, filePath, { mode, base });
    const result = _applyLearnings(analyze({ filePath, content, previousContent, changedLines, config }), learnings);
    if (result.findings.length > 0) files.push(result);
  }

  // Cross-file blast radius + graph-aware security (both no-ops when no code graph is available).
  const graph = _getGraph(cwd, config, opts.graph !== undefined ? { provider: opts.graph } : {});
  files = _attachImpact(files, { cwd, config, graph, mode });
  files = _attachSecurity(files, { cwd, config, graph });
  files = _labelTrust(files);

  const allFindings = files.flatMap((f) => f.findings);
  return {
    files,
    tier: _overallTier(allFindings),
    counts: _tierCounts(allFindings),
    blocking: allFindings.some((f) => f.blocking),
    config,
  };
}
