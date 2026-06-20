import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "ignore"],
    maxBuffer: 64 * 1024 * 1024,
  });
}

function tryGit(args: string[], cwd: string): string | null {
  try {
    return git(args, cwd);
  } catch {
    return null;
  }
}

function realp(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

export function isGitRepo(cwd: string): boolean {
  const out = tryGit(["rev-parse", "--is-inside-work-tree"], cwd);
  return out !== null && out.trim() === "true";
}

export function repoRoot(cwd: string): string | null {
  const out = tryGit(["rev-parse", "--show-toplevel"], cwd);
  return out ? out.trim() : null;
}

export function headSha(cwd: string): string | null {
  const out = tryGit(["rev-parse", "HEAD"], cwd);
  return out ? out.trim() : null;
}

function hasHead(cwd: string): boolean {
  return tryGit(["rev-parse", "--verify", "HEAD"], cwd) !== null;
}

function resolveRel(cwd: string, filePath: string): { root: string; rel: string } {
  const root = repoRoot(cwd) || cwd;
  let abs = path.isAbsolute(filePath) ? filePath : path.resolve(cwd, filePath);
  abs = realp(abs);
  return { root, rel: path.relative(root, abs) };
}

function parseChangedLines(diff: string | null): Set<number> {
  const changed = new Set<number>();
  if (!diff) return changed;
  const hunkRe = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/;
  for (const line of diff.split("\n")) {
    const m = line.match(hunkRe);
    if (!m) continue;
    const start = parseInt(m[1], 10);
    const count = m[2] === undefined ? 1 : parseInt(m[2], 10);
    if (count === 0) {
      changed.add(Math.max(1, start));
    } else {
      for (let i = 0; i < count; i++) changed.add(start + i);
    }
  }
  return changed;
}

// `base` (a git ref) diffs the whole PR/branch against that ref — used in CI, where the
// working tree is clean so `git diff HEAD` would be empty. Otherwise diff staged/working.
function diffArgsForMode(mode: string, base?: string): string[] {
  if (base) return ["diff", base];
  return mode === "staged" ? ["diff", "--cached"] : ["diff", "HEAD"];
}

export function getChangedLinesForFile(cwd: string, filePath: string, opts: { mode?: string; base?: string } = {}): Set<number> | null {
  const mode = opts.mode || "working";
  if (!isGitRepo(cwd) || !hasHead(cwd)) return null;
  const { root, rel } = resolveRel(cwd, filePath);
  if (!opts.base) {
    const untracked = tryGit(["ls-files", "--others", "--exclude-standard", "--", rel], root);
    if (untracked && untracked.trim() === rel) return null;
  }
  const diff = tryGit([...diffArgsForMode(mode, opts.base), "--unified=0", "--no-color", "--", rel], root);
  if (diff === null) return null;
  return parseChangedLines(diff);
}

export function getChangedFiles(cwd: string, opts: { mode?: string; base?: string } = {}): Map<string, Set<number> | null> {
  const mode = opts.mode || "working";
  const result = new Map<string, Set<number> | null>();
  if (!isGitRepo(cwd)) return result;
  const root = repoRoot(cwd) || cwd;
  if (!hasHead(cwd)) {
    const all = tryGit(["ls-files", "--cached", "--others", "--exclude-standard"], root) || "";
    for (const rel of all.split("\n").filter(Boolean)) {
      result.set(path.join(root, rel), null);
    }
    return result;
  }
  const nameStatus = tryGit([...diffArgsForMode(mode, opts.base), "--name-only", "--no-color"], root) || "";
  for (const rel of nameStatus.split("\n").filter(Boolean)) {
    result.set(path.join(root, rel), getChangedLinesForFile(root, rel, { mode, base: opts.base }));
  }
  if (mode !== "staged" && !opts.base) {
    const untracked = tryGit(["ls-files", "--others", "--exclude-standard"], root) || "";
    for (const rel of untracked.split("\n").filter(Boolean)) {
      result.set(path.join(root, rel), null);
    }
  }
  return result;
}

export function getPreviousContent(cwd: string, filePath: string, opts: { mode?: string; base?: string } = {}): string | null {
  if (!isGitRepo(cwd) || !hasHead(cwd)) return null;
  const { root, rel } = resolveRel(cwd, filePath);
  const refSpec = opts.base ? `${opts.base}:${rel}` : opts.mode === "staged" ? `:${rel}` : `HEAD:${rel}`;
  return tryGit(["show", refSpec], root);
}

export interface BlameInfo {
  author: string | null;
  authorTime: string | null;
  summary: string | null;
  hash: string | null;
}

export function blameLine(cwd: string, filePath: string, line: number): BlameInfo | null {
  if (!isGitRepo(cwd) || !hasHead(cwd)) return null;
  const { root, rel } = resolveRel(cwd, filePath);
  const out = tryGit(["blame", "-L", `${line},${line}`, "--porcelain", "--", rel], root);
  if (!out) return null;
  const get = (key: string): string | null => {
    const m = out.match(new RegExp(`^${key} (.*)$`, "m"));
    return m ? m[1] : null;
  };
  const hash = out.split("\n")[0]?.split(" ")[0] || null;
  return {
    author: get("author"),
    authorTime: get("author-time"),
    summary: get("summary"),
    hash: hash && /^[0-9a-f]{7,40}$/.test(hash) ? hash.slice(0, 8) : null,
  };
}
