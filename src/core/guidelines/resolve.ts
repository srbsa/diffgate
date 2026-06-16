import fs from "fs";
import path from "path";
import type { Config, GuidelineRuleSet } from "../types.js";

// The de-facto guideline filenames coding agents already read. A file applies to
// its own directory and all subdirectories (the AGENTS.md/CodeRabbit convention).
export const STANDARD_GUIDELINE_FILES = [
  "AGENTS.md",
  "CLAUDE.md",
  "GEMINI.md",
  ".cursorrules",
  ".windsurfrules",
  ".clinerules",
  ".github/copilot-instructions.md",
];

// Headings whose sections carry review-relevant rules; operational sections
// (setup/build/deploy) are dropped when a file exceeds the byte budget.
const RELEVANT_HEADING = /(style|convention|rule|guideline|standard|security|naming|error|lint|test|do not|don't|avoid|must|never|always|forbidden|require)/i;
const OPERATIONAL_HEADING = /(setup|install|getting started|build command|run|deploy|environment|prerequisite|quick ?start|architecture overview|overview)/i;

function guidelineNamesFor(config: Config): string[] {
  const g = config.guidelines || {};
  const names = g.autoDetect === false ? [] : [...STANDARD_GUIDELINE_FILES];
  for (const f of g.files || []) if (!names.includes(f)) names.push(f);
  return names;
}

/** Walk from a directory up to (and including) the repo root, collecting guideline files at each level, nearest-first. */
function collectUpTree(startDir: string, root: string, names: string[]): string[] {
  const found: string[] = [];
  let dir = path.resolve(startDir);
  const stop = path.resolve(root);
  while (true) {
    for (const name of names) {
      const candidate = path.join(dir, name);
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) found.push(candidate);
    }
    if (dir === stop) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return found; // nearest-first
}

/**
 * Cap the guideline set when nesting is deep: keep the (maxDepth-1) NEAREST files
 * (most specific to the changed file) plus the repo-ROOT-most file (canonical
 * project-wide rules), and drop the middle. Returns [kept, dropped].
 */
export function applyDepthCap(nearestFirst: string[], maxDepth: number): { kept: string[]; dropped: string[] } {
  if (nearestFirst.length <= maxDepth) return { kept: nearestFirst, dropped: [] };
  const rootMost = nearestFirst[nearestFirst.length - 1];
  const kept = nearestFirst.slice(0, Math.max(1, maxDepth - 1));
  if (!kept.includes(rootMost)) kept.push(rootMost);
  const dropped = nearestFirst.filter((f) => !kept.includes(f));
  return { kept, dropped };
}

/** Pull review-relevant sections out of an oversized markdown file. */
function extractRelevant(md: string, budget: number): string {
  const lines = md.split("\n");
  const sections: { heading: string; body: string[] }[] = [{ heading: "", body: [] }];
  for (const line of lines) {
    if (/^#{1,6}\s/.test(line)) sections.push({ heading: line.replace(/^#+\s*/, ""), body: [line] });
    else sections[sections.length - 1].body.push(line);
  }
  const keep = sections.filter(
    (s) => s.heading === "" || (RELEVANT_HEADING.test(s.heading) && !OPERATIONAL_HEADING.test(s.heading))
  );
  let out = (keep.length > 1 ? keep : sections).map((s) => s.body.join("\n")).join("\n").trim();
  if (out.length > budget) out = out.slice(0, budget) + "\n…[truncated]";
  return out;
}

function readGuideline(file: string, budget: number): string {
  let md: string;
  try {
    md = fs.readFileSync(file, "utf-8");
  } catch {
    return "";
  }
  return md.length > budget ? extractRelevant(md, budget) : md.trim();
}

/**
 * Resolve the applicable guideline rule set for a single changed file.
 * Dedupes identical files by realpath; respects the configured depth cap and byte budget.
 */
export function resolveGuidelinesForFile(filePath: string, root: string, config: Config): GuidelineRuleSet | null {
  const g = config.guidelines || {};
  if (g.enabled === false) return null;
  const names = guidelineNamesFor(config);
  if (names.length === 0) return null;

  const all = collectUpTree(path.dirname(path.resolve(filePath)), root, names);
  // dedupe by realpath (monorepos symlink/duplicate guideline files)
  const seen = new Set<string>();
  const unique = all.filter((f) => {
    let real = f;
    try { real = fs.realpathSync(f); } catch { /* keep raw path */ }
    if (seen.has(real)) return false;
    seen.add(real);
    return true;
  });
  if (unique.length === 0) return null;

  const { kept, dropped } = applyDepthCap(unique, g.maxDepth ?? 3);
  const budget = g.maxBytesPerFile ?? 8000;
  const blocks = kept
    .map((f) => ({ f, text: readGuideline(f, budget) }))
    .filter((b) => b.text.length > 0);
  if (blocks.length === 0) return null;

  const text = blocks
    .map((b) => `### Guidelines from ${path.relative(root, b.f)}\n${b.text}`)
    .join("\n\n");
  return {
    sources: blocks.map((b) => path.relative(root, b.f)),
    text,
    dropped: dropped.map((f) => path.relative(root, f)),
  };
}
