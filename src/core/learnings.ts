import crypto from "crypto";
import fs from "fs";
import path from "path";
import { overallTier, tierCounts } from "./tiers.js";
import type { AnalyzeResult, Finding } from "./types.js";

export interface Learning {
  id: string;
  ruleId: string;
  /** sha1 of the trimmed flagged code — lets a dismissal match the same pattern across occurrences. */
  codeHash: string;
  file?: string;
  verdict: "dismiss" | "confirm";
  note?: string;
  at: string;
}

export interface LearningStore {
  version: number;
  entries: Learning[];
}

const DIR = ".diffgate";
const FILE = "learnings.json";

function storePath(root: string): string {
  return path.join(root, DIR, FILE);
}

export function codeHash(code: string): string {
  return crypto.createHash("sha1").update(code.trim()).digest("hex").slice(0, 16);
}

export function loadLearnings(root: string): LearningStore {
  try {
    const raw = JSON.parse(fs.readFileSync(storePath(root), "utf-8"));
    if (raw && Array.isArray(raw.entries)) return { version: raw.version || 1, entries: raw.entries };
  } catch {
    /* no store yet */
  }
  return { version: 1, entries: [] };
}

/** Resolve a shared-learnings entry (repo root, .diffgate dir, or direct file) to a store path. */
function resolveSharedPath(entry: string, baseDir: string): string {
  const p = path.isAbsolute(entry) ? entry : path.resolve(baseDir, entry);
  try {
    if (fs.statSync(p).isDirectory()) {
      const inDir = path.join(p, DIR, FILE);
      if (fs.existsSync(inDir)) return inDir;
      return path.join(p, FILE); // e.g. pointed straight at a .diffgate dir
    }
  } catch {
    /* not a dir / missing */
  }
  return p;
}

/** Merge the repo's own learnings with org-wide shared stores. Later (local) entries win per id. */
export function loadMergedLearnings(root: string, shared: string[] = [], baseDir = root): LearningStore {
  const byId = new Map<string, Learning>();
  for (const entry of shared) {
    const sp = resolveSharedPath(entry, baseDir);
    try {
      const raw = JSON.parse(fs.readFileSync(sp, "utf-8"));
      if (raw && Array.isArray(raw.entries)) for (const e of raw.entries as Learning[]) byId.set(e.id, e);
    } catch {
      /* missing shared store is fine */
    }
  }
  for (const e of loadLearnings(root).entries) byId.set(e.id, e); // local overrides shared
  return { version: 1, entries: [...byId.values()] };
}

export function recordLearning(
  root: string,
  input: { ruleId: string; code: string; verdict: "dismiss" | "confirm"; file?: string; note?: string; now?: string }
): Learning {
  const store = loadLearnings(root);
  const hash = codeHash(input.code);
  const entry: Learning = {
    id: `${input.ruleId}:${hash}`,
    ruleId: input.ruleId,
    codeHash: hash,
    file: input.file,
    verdict: input.verdict,
    note: input.note,
    at: input.now || new Date().toISOString(),
  };
  // one entry per (ruleId, codeHash): latest verdict wins
  store.entries = store.entries.filter((e) => !(e.ruleId === entry.ruleId && e.codeHash === entry.codeHash));
  store.entries.push(entry);
  fs.mkdirSync(path.join(root, DIR), { recursive: true });
  fs.writeFileSync(storePath(root), JSON.stringify(store, null, 2) + "\n");
  return entry;
}

/** True if this finding was previously dismissed as noise. */
export function isDismissed(finding: Pick<Finding, "ruleId" | "code">, learnings: LearningStore): boolean {
  const hash = codeHash(finding.code);
  return learnings.entries.some((e) => e.verdict === "dismiss" && e.ruleId === finding.ruleId && e.codeHash === hash);
}

/** Drop findings the team has dismissed as noise; recompute tier/counts/blocking. */
export function applyLearnings(result: AnalyzeResult, learnings: LearningStore): AnalyzeResult {
  if (learnings.entries.length === 0) return result;
  const kept = result.findings.filter((f) => !isDismissed(f, learnings));
  if (kept.length === result.findings.length) return result;
  return { ...result, findings: kept, tier: overallTier(kept), counts: tierCounts(kept), blocking: kept.some((f) => f.blocking) };
}
