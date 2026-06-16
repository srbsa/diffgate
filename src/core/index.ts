export { analyze } from "./analyzer.js";
export { loadConfig, findConfigPath, isIgnored, DEFAULT_CONFIG } from "./config.js";
export {
  getChangedFiles,
  getChangedLinesForFile,
  getPreviousContent,
  isGitRepo,
  repoRoot,
  blameLine,
} from "./git.js";
export { detectLanguage, hasAstSupport } from "./parsers/index.js";
export { computeChangedLines } from "./linediff.js";
export { getRules } from "./rules/index.js";
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
export { loadLearnings, recordLearning, applyLearnings, isDismissed, codeHash } from "./learnings.js";
export { TOOLS as agentTools } from "./agent/tools.js";
export { TIERS, TIER_META, TIER_ORDER, maxTier, overallTier, tierCounts, isTier } from "./tiers.js";

import fs from "fs";
import { analyze } from "./analyzer.js";
import { loadConfig as _loadConfig, isIgnored as _isIgnored } from "./config.js";
import { getChangedFiles as _getChangedFiles, getPreviousContent as _getPreviousContent, repoRoot as _repoRoot } from "./git.js";
import { overallTier as _overallTier, tierCounts as _tierCounts } from "./tiers.js";
import { loadLearnings as _loadLearnings, applyLearnings as _applyLearnings } from "./learnings.js";
import type { Config, AnalyzeResult } from "./types.js";

export interface ReviewResult {
  files: AnalyzeResult[];
  tier: string;
  counts: { green: number; yellow: number; orange: number };
  blocking: boolean;
  config: Config;
}

export function reviewChanges(cwd: string, opts: { mode?: string } = {}): ReviewResult {
  const { config } = _loadConfig(cwd);
  const mode = opts.mode || config.gate.mode || "working";
  const changed = _getChangedFiles(cwd, { mode });
  const learnings = _loadLearnings(_repoRoot(cwd) || cwd);
  const files: AnalyzeResult[] = [];

  for (const [filePath, changedLines] of changed) {
    if (_isIgnored(filePath, config, cwd)) continue;
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }
    const previousContent = _getPreviousContent(cwd, filePath, { mode });
    const result = _applyLearnings(analyze({ filePath, content, previousContent, changedLines, config }), learnings);
    if (result.findings.length > 0) files.push(result);
  }

  const allFindings = files.flatMap((f) => f.findings);
  return {
    files,
    tier: _overallTier(allFindings),
    counts: _tierCounts(allFindings),
    blocking: allFindings.some((f) => f.blocking),
    config,
  };
}
