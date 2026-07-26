/**
 * Confirmation for reinvented-helper findings.
 *
 * `reinvented-helper` is emitted by a rule that only sees one file at a time — it knows a new
 * function was written, not whether similar logic already exists elsewhere in the repo. This pass
 * builds (or reads from cache) a shape index of all existing functions and filters findings to
 * keep only those with surviving matches.
 *
 * CRITICAL DESIGN NOTE: The error direction here is the OPPOSITE of `single-caller-abstraction`.
 * For `single-caller-abstraction` a partial/incomplete walk could report zero callers for a
 * symbol that has many, so an unconfirmed finding must be dropped. For `reinvented-helper` an
 * incomplete walk can only cause us to MISS a duplicate (lost recall), never to invent one — a
 * match is positive evidence on its own. So a truncated walk is acceptable and the finding still
 * stands. We do NOT drop findings when the walk is partial; that would be cargo-culted wrong.
 */

import fs from "fs";
import path from "path";
import type { AnalyzeResult, Config, Finding } from "./types.js";
import { shapeFunctions, nameTokens, tokenOverlap, type FnShape } from "./fingerprint.js";
import { detectLanguage, AST_LANGUAGES } from "./parsers/index.js";
import { parseTs, treeSitterReady } from "./parsers/treesitter.js";
import { parseJs } from "./parsers/javascript.js";
import { isIgnored, IGNORE_DIR_NAMES } from "./config.js";
import { isGitIgnoredPath } from "./git.js";
import { recomputeResult } from "./tiers.js";

/** Languages supported by tree-sitter in the call graph. */
const TREE_SITTER_LANGUAGES = new Set(["python", "go", "java", "kotlin", "ruby", "php", "csharp", "c#"]);

/** TTL for the per-cwd shape index cache, in milliseconds. */
const SHAPE_INDEX_CACHE_TTL_MS = 30_000;

/** Minimum Jaccard overlap of name tokens for a shape match to count. See gate 4 for the calibration. */
const NAME_OVERLAP_FLOOR = 0.25;

/** Cache keyed by cwd: { index, builtAt }. */
const shapeIndexCache = new Map<
  string,
  { index: Map<string, Array<FnShape & { file: string }>>; builtAt: number }
>();

/** Build (or read from cache) an index of function shapes keyed by shapeHash. */
function buildShapeIndex(
  cwd: string,
  config: Partial<Config>,
  maxFiles: number = 3000,
  budgetMs: number = 8000
): Map<string, Array<FnShape & { file: string }>> {
  // Check cache first, honoring TTL.
  const cached = shapeIndexCache.get(cwd);
  if (cached && Date.now() - cached.builtAt < SHAPE_INDEX_CACHE_TTL_MS) {
    return cached.index;
  }

  const index = new Map<string, Array<FnShape & { file: string }>>();
  const startedAt = Date.now();
  let parsed = 0;

  // Walk the repo like buildCallGraph does: respect .ignore, gitignore, skip large files.
  function walkDir(dir: string) {
    if (Date.now() - startedAt > budgetMs || parsed >= maxFiles) return;

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (Date.now() - startedAt > budgetMs || parsed >= maxFiles) return;

      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIR_NAMES.has(entry.name)) {
          walkDir(fullPath);
        }
      } else if (entry.isFile()) {
        // Respect ignore config and gitignore. Cast to Config since we control the structure.
        if (isIgnored(fullPath, config as Config, cwd) || isGitIgnoredPath(cwd, fullPath)) continue;

        // Skip large files (100KB).
        try {
          const stats = fs.statSync(fullPath);
          if (stats.size > 100 * 1024) continue;
        } catch {
          continue;
        }

        // Parse the file and extract function shapes.
        try {
          let content: string;
          try {
            content = fs.readFileSync(fullPath, "utf-8");
          } catch {
            continue;
          }

          const language = detectLanguage(fullPath);
          if (!language) continue;

          const lines = content.split("\n");
          let shapes: FnShape[] = [];

          // Tree-sitter path for tree-sitter languages (Python, Go, etc.).
          if (TREE_SITTER_LANGUAGES.has(language)) {
            try {
              const tsTree = parseTs(content, language);
              shapes = shapeFunctions({ language, tsTree, lines });
            } catch {
              // Parse error; skip this file.
            }
          } else if (AST_LANGUAGES.has(language)) {
            // Babel path for JS/TS.
            try {
              const ast = parseJs(content, language);
              shapes = shapeFunctions({ language, ast, lines });
            } catch {
              // Parse error; skip this file.
            }
          }

          // Index each shape by its shapeHash (if non-empty).
          for (const shape of shapes) {
            if (shape.shapeHash) {
              const existing = index.get(shape.shapeHash) || [];
              existing.push({ ...shape, file: fullPath });
              index.set(shape.shapeHash, existing);
            }
          }

          parsed++;
        } catch {
          // Any error during parsing/indexing: skip this file.
        }
      }
    }
  }

  walkDir(cwd);

  // Cache the result.
  shapeIndexCache.set(cwd, { index, builtAt: Date.now() });

  return index;
}

/**
 * Is a file path a test file? Check each path component, not the whole path.
 *
 * Exported because the `reinvented-helper` detector must apply the identical test — a substring
 * match on the full path treats any directory merely containing "test" (a `.test-tmp-` fixture dir,
 * `src/test-utils/`) as a test file, and a detector that skips files the attach pass would have
 * accepted is a silent recall hole rather than a visible failure.
 */
export function isTestFile(filePath: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, "/");
  // Check if any path component is a test-related directory.
  const pathParts = normalizedPath.split("/");
  for (const part of pathParts) {
    if (/^(__tests__|test|spec)$|\.test\.|\.spec\./.test(part)) {
      return true;
    }
  }
  return false;
}

/**
 * Confirm or drop every `reinvented-helper` finding.
 *
 * Kept when a match in the shape index survives all gates. Dropped when no match survives.
 * Unlike `attachStructuralImpact` for `single-caller-abstraction`, a truncated/partial repo
 * walk does NOT cause us to drop findings — a match is positive evidence that cannot be invented
 * by an incomplete walk.
 */
export function attachReinvention(
  files: AnalyzeResult[],
  opts: { cwd: string; config: Partial<Config> }
): AnalyzeResult[] {
  // Short-circuit: if there are no reinvented-helper findings, don't scan the repo.
  const hasReinvention = files.some((f) => f.findings.some((finding) => finding.ruleId === "reinvented-helper"));
  if (!hasReinvention) return files;

  // Build the shape index (or read from cache).
  const shapeIndex = buildShapeIndex(opts.cwd, opts.config);

  // Collect all changed files in this run.
  const changedFiles = new Set(files.map((f) => f.filePath));

  // Process each file, filtering its reinvention findings.
  const result: AnalyzeResult[] = [];
  for (const file of files) {
    const filtered: Finding[] = [];

    for (const finding of file.findings) {
      if (finding.ruleId !== "reinvented-helper") {
        // Keep non-reinvention findings as-is.
        filtered.push(finding);
        continue;
      }

      // This is a reinvented-helper finding. Check if it has a surviving match.
      const meta = finding.meta as Record<string, unknown> | undefined;
      if (!meta) {
        // No metadata; drop it (no shape to match against).
        continue;
      }

      const shapeHash = meta.shapeHash as string | undefined;
      const arity = meta.arity as number | undefined;
      const statementCount = meta.statementCount as number | undefined;
      const name = meta.name as string | undefined;

      // Validate metadata.
      if (!shapeHash || typeof arity !== "number" || typeof statementCount !== "number" || !name) {
        continue;
      }

      // Gate 1: shapeHash is non-empty and matches.
      const candidates = shapeIndex.get(shapeHash);
      if (!candidates || candidates.length === 0) {
        continue;
      }

      // Gate 2-6: find a match that survives all gates.
      let bestMatch: FnShape & { file: string } | null = null;
      for (const candidate of candidates) {
        // Gate 2: arity must be equal.
        if (candidate.arity !== arity) continue;

        // Gate 3: statementCount >= 5.
        if (candidate.statementCount < 5) continue;

        // Gate 4: the names must be lexically related.
        //
        // Calibrated against the canonical reinvention: same verb, synonym noun — `resolveThresholds`
        // rewritten as `resolveLimits`. Two two-token names sharing one token score exactly 1/3, so a
        // 0.34 floor rejected precisely the case this rule exists to catch. 0.25 admits it while still
        // requiring real kinship: two three-token names sharing only one score 0.2 and stay out.
        //
        // The name is deliberately the weaker gate. An identical body fingerprint plus identical arity
        // over 5+ statements is already strong evidence; the name only has to corroborate it.
        const overlap = tokenOverlap(nameTokens(name), nameTokens(candidate.name));
        if (overlap < NAME_OVERLAP_FLOOR) continue;

        // Gate 5: match is NOT in the same file as the finding.
        if (candidate.file === file.filePath) continue;

        // Gate 6: match's file is NOT a test file.
        if (isTestFile(candidate.file)) continue;

        // Gate 7: match's file is NOT one of the changed files in this run.
        if (changedFiles.has(candidate.file)) continue;

        // This candidate survived all gates. Pick the best one (lowest file path, then lowest startLine).
        if (!bestMatch || candidate.file < bestMatch.file || (candidate.file === bestMatch.file && candidate.startLine < bestMatch.startLine)) {
          bestMatch = candidate;
        }
      }

      if (bestMatch) {
        // Rewrite the message to name the existing code concretely. The path is relativized to the
        // repo root: the index stores absolute paths, but an absolute path in a finding is unusable
        // noise in CLI output, a PR comment, or an agent's context window — every other finding in
        // the engine reads as repo-relative, and this message is the whole value of the rule.
        const relPath = path.relative(opts.cwd, bestMatch.file) || bestMatch.file;
        const newMessage = `⚡ Reinvented helper: ${name} duplicates ${bestMatch.name} at ${relPath}:${bestMatch.startLine}. Reuse it or delete one.`;
        filtered.push({
          ...finding,
          message: newMessage,
        });
      }
      // else: no surviving match, drop the finding.
    }

    // Recompute the file's tier/counts/blocking based on filtered findings.
    // Always recompute when we've processed reinvention findings (even if count didn't change,
    // messages may have been rewritten).
    const hasReinvention = file.findings.some((f) => f.ruleId === "reinvented-helper");
    if (filtered.length !== file.findings.length || hasReinvention) {
      result.push(recomputeResult(file, filtered));
    } else {
      result.push(file);
    }
  }

  return result;
}

/** Recompute tier, counts, and blocking for a file based on its findings. */
