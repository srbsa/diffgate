export { analyze } from "./analyzer.js";
export { loadConfig, findConfigPath, loadDotenv, isIgnored, matchesPathScope, DEFAULT_CONFIG, DEFAULT_IGNORE, HARD_IGNORE, IGNORE_DIR_NAMES } from "./config.js";
export {
  getChangedFiles,
  getChangedLinesForFile,
  getPreviousContent,
  isGitRepo,
  isGitIgnoredPath,
  repoRoot,
  headSha,
  blameLine,
  listCommits,
  getCommitChangedFiles,
  getBlobAtRef,
  isCommitish,
  isValidRange,
  AI_AUTHOR_PATTERN,
} from "./git.js";
export { reviewCommit, reviewHistory } from "./history.js";
export type { HistoryResult } from "./history.js";
export { detectLanguage, hasAstSupport } from "./parsers/index.js";
export { initTreeSitter, treeSitterReady, treeSitterLanguages, parseTs } from "./parsers/treesitter.js";
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
  getGraph, resolveGraphConfig, graphStatus, makeCodeGraphProvider, makeBuiltinProvider, codeGraphAvailable,
  commandAvailable, graphDbDir, graphIndexPath, normalizeImpact, normalizePrContext, normalizeEditContext,
  normalizeSecurity, normalizeTests, normalizeEntryPoints, normalizeAncestors, DEFAULT_GRAPH_CONFIG,
} from "./graph/index.js";
export type { GraphProvider, ImpactQuery, PrContextQuery, SecurityQuery, ReachabilityQuery, GraphStatus, GraphRunner } from "./graph/index.js";
export { attachImpact, IMPACT_RULES } from "./impact.js";
export { attachStructuralImpact, STRUCTURAL_IMPACT_RULES } from "./structural-impact.js";
export { attachSecurity, SECURITY_RULES, labelTrust, trustFor } from "./security.js";
export { attachReachability, REACHABILITY_RULES } from "./reachability.js";
export {
  makeSemgrepProvider, semgrepAvailable, parseSemgrep, mapSeverityToTier, diffScope, dedupeAgainst, toFindings,
  getRecallProvider, attachRecall, resolveRecallConfig, recallActive, DEFAULT_RECALL_CONFIG,
} from "./recall/index.js";
export type { RecallProvider, RawRecallFinding, SemgrepRunner, SemgrepBatchRunner } from "./recall/index.js";
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
import { attachStructuralImpact as _attachStructuralImpact } from "./structural-impact.js";
import { attachSecurity as _attachSecurity, labelTrust as _labelTrust } from "./security.js";
import { attachReachability as _attachReachability } from "./reachability.js";
import { getRecallProvider as _getRecallProvider, attachRecall as _attachRecall } from "./recall/index.js";
import type { GraphProvider } from "./graph/index.js";
import type { RecallProvider } from "./recall/index.js";
import type { Config, AnalyzeResult } from "./types.js";

export interface ReviewResult {
  files: AnalyzeResult[];
  tier: string;
  counts: { green: number; yellow: number; orange: number };
  blocking: boolean;
  config: Config;
}

export function reviewChanges(
  cwd: string,
  opts: { mode?: string; base?: string; graph?: GraphProvider | null; recall?: RecallProvider | null } = {}
): ReviewResult {
  const { config } = _loadConfig(cwd);
  const mode = opts.mode || config.gate.mode || "working";
  const base = opts.base;
  const changed = _getChangedFiles(cwd, { mode, base });
  const root = _repoRoot(cwd) || cwd;
  const learnings = _loadMergedLearnings(root, config.learnings?.shared || [], root);

  // Borrowed recall (off by default; "ci" only under CI; requires the binary). Resolved first because
  // when active we must keep findings-free files in the pipeline too — that's where borrowed recall
  // earns its keep (vulns DiffGate's own rules don't flag). When null, behavior is unchanged.
  const recall = _getRecallProvider(cwd, config, opts.recall !== undefined ? { provider: opts.recall } : {});

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
    if (result.findings.length > 0 || recall) files.push(result);
  }

  // Cross-file blast radius + graph-aware security/reachability (all no-ops without a code graph).
  // Order: security (Pro taint) first so its authoritative verdict wins; community reachability then
  // fills the precision gap for findings it left unconfirmed; trust labels are derived last.
  const graph = _getGraph(cwd, config, opts.graph !== undefined ? { provider: opts.graph } : {});
  files = _attachImpact(files, { cwd, config, graph, mode });
  // Confirms or drops speculative-abstraction findings; drops them all when there is no graph.
  files = _attachStructuralImpact(files, { cwd, config, graph });
  files = _attachSecurity(files, { cwd, config, graph });
  files = _attachReachability(files, { cwd, config, graph });
  files = _labelTrust(files);
  // Borrowed recall last — advisory findings layered on top, then drop any file still finding-free.
  files = _attachRecall(files, { cwd, config, changed, provider: recall });
  if (recall) files = files.filter((f) => f.findings.length > 0);

  const allFindings = files.flatMap((f) => f.findings);
  return {
    files,
    tier: _overallTier(allFindings),
    counts: _tierCounts(allFindings),
    blocking: allFindings.some((f) => f.blocking),
    config,
  };
}
