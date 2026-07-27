import { analyze } from "./analyzer.js";
import { loadConfig, isIgnored } from "./config.js";
import { listCommits, getCommitChangedFiles, getBlobAtRef, repoRoot } from "./git.js";
import { overallTier, tierCounts, recomputeResult } from "./tiers.js";
import { loadMergedLearnings, applyLearnings } from "./learnings.js";
import { CONFIRMATION_REQUIRED_RULES } from "./structural-impact.js";
import type { AnalyzeResult, Commit, CommitReview, Config, HistorySelection } from "./types.js";
import type { LearningStore } from "./learnings.js";

export interface HistoryResult {
  commits: CommitReview[];
  scanned: number;
  withFindings: number;
}

/**
 * Review a single historical commit's diff. Unlike `reviewChanges` (which reads the working
 * tree from disk), content is sourced from git objects at the commit — so this is faithful for
 * any commit in history and never touches the working tree. Graph passes (impact/security/
 * reachability) are skipped: they're no-ops without a code graph, so rules + learnings is the
 * faithful core for a per-commit audit.
 *
 * The one thing skipping those passes does NOT make quiet is a rule that emits optimistically and
 * expects to be confirmed later — without its attach-pass it would print raw, unconfirmed
 * candidates. Those rules are dropped outright here; see `CONFIRMATION_REQUIRED_RULES`.
 */
export function reviewCommit(
  cwd: string,
  commit: Commit,
  config: Config,
  learnings: LearningStore,
  root: string
): CommitReview {
  const changed = getCommitChangedFiles(root, commit.sha);
  const files: AnalyzeResult[] = [];
  for (const [filePath, changedLines] of changed) {
    if (isIgnored(filePath, config, root)) continue;
    const content = getBlobAtRef(root, commit.sha, filePath);
    if (content === null) continue; // deleted at this commit — nothing to review
    const previousContent = getBlobAtRef(root, `${commit.sha}^`, filePath);
    const analyzed = applyLearnings(
      analyze({ filePath, content, previousContent, changedLines, config }),
      learnings
    );
    const kept = analyzed.findings.filter((f) => !CONFIRMATION_REQUIRED_RULES.has(f.ruleId));
    const result = kept.length === analyzed.findings.length ? analyzed : recomputeResult(analyzed, kept);
    if (result.findings.length > 0) files.push(result);
  }
  const allFindings = files.flatMap((f) => f.findings);
  return {
    commit,
    files,
    tier: overallTier(allFindings),
    counts: tierCounts(allFindings),
    blocking: allFindings.some((f) => f.blocking),
  };
}

/** Resolve a selection to commits and review each one's diff. */
export function reviewHistory(cwd: string, sel: HistorySelection = {}): HistoryResult {
  const { config } = loadConfig(cwd);
  const root = repoRoot(cwd) || cwd;
  const learnings = loadMergedLearnings(root, config.learnings?.shared || [], root);
  const commits = listCommits(root, sel);
  const reviews = commits.map((cm) => reviewCommit(cwd, cm, config, learnings, root));
  return {
    commits: reviews,
    scanned: reviews.length,
    withFindings: reviews.filter((r) => r.files.length > 0).length,
  };
}
