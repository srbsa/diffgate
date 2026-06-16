import fs from "fs";
import path from "path";
import { loadConfig } from "../config.js";
import { getChangedFiles, repoRoot } from "../git.js";
import { isIgnored } from "../config.js";
import { detectLanguage } from "../parsers/index.js";
import { evaluateGuidelines } from "./evaluate.js";
import type { GuidelineEvalResult, GuidelineFileInput } from "./evaluate.js";

export { resolveGuidelinesForFile, applyDepthCap, STANDARD_GUIDELINE_FILES } from "./resolve.js";
export { evaluateGuidelines } from "./evaluate.js";
export type { GuidelineEvalResult, GuidelinePayload, GuidelineFileInput } from "./evaluate.js";

/** Resolve changed files from git, then evaluate them against their guideline sets. */
export async function reviewGuidelines(
  cwd: string,
  opts: { mode?: string; signal?: AbortSignal; log?: (msg: string) => void } = {}
): Promise<GuidelineEvalResult> {
  const { config } = loadConfig(cwd);
  const root = repoRoot(cwd) || cwd;
  const mode = opts.mode || config.gate.mode || "working";
  const changed = getChangedFiles(cwd, { mode });
  const files: GuidelineFileInput[] = [];
  for (const [filePath, changedLines] of changed) {
    if (isIgnored(filePath, config, cwd)) continue;
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }
    files.push({
      filePath,
      rel: path.relative(root, filePath),
      language: detectLanguage(filePath),
      content,
      changedLines: changedLines ? [...changedLines] : null,
    });
  }
  return evaluateGuidelines({ root, config, files, signal: opts.signal, log: opts.log });
}
