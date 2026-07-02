import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import type { Commit, HistorySelection } from "./types.js";

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

// --- history scan (check --since/--author/<commit>) ---------------------------

/** Common AI-agent authorship signatures for the `--ai` preset. Heuristic — may false-positive. */
export const AI_AUTHOR_PATTERN = /claude|copilot|cursor|codex|chatgpt|gpt-|gemini|aider|devin|\bbot\b/i;

const CO_AUTHOR_RE = /^co-authored-by:\s*(.+?)\s*$/gim;

function parseCoAuthors(body: string): string[] {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  CO_AUTHOR_RE.lastIndex = 0;
  while ((m = CO_AUTHOR_RE.exec(body)) !== null) out.push(m[1]);
  return out;
}

function matchesAuthor(cm: Commit, pattern: string | undefined, ai: boolean | undefined): boolean {
  if (!pattern && !ai) return true;
  const haystack = [cm.author, cm.email, ...cm.coAuthors].join("\n");
  if (ai && AI_AUTHOR_PATTERN.test(haystack)) return true;
  if (pattern) {
    try {
      if (new RegExp(pattern, "i").test(haystack)) return true;
    } catch {
      // Not a valid regex — fall back to a case-insensitive substring match.
      if (haystack.toLowerCase().includes(pattern.toLowerCase())) return true;
    }
  }
  return false;
}

/**
 * Resolve a history selection to a list of commits (most-recent first), applying the
 * author/AI filter in JS so it also catches `Co-authored-by:` trailers (which git's own
 * `--author` flag ignores — and where most agent attribution actually lives).
 */
export function listCommits(cwd: string, sel: HistorySelection = {}): Commit[] {
  if (!isGitRepo(cwd) || !hasHead(cwd)) return [];
  const root = repoRoot(cwd) || cwd;
  const limit = sel.limit && sel.limit > 0 ? sel.limit : 50;
  const filtering = !!(sel.author || sel.ai);
  // Field sep = US (\x1f), record sep = RS (\x1e); body (%b) is last so embedded newlines are safe.
  const fmt = "%H%x1f%an%x1f%ae%x1f%aI%x1f%s%x1f%b%x1e";
  const args = ["log", "--no-merges", `--format=${fmt}`];

  if (sel.commit) {
    args.push("-1", sel.commit);
  } else if (sel.range) {
    args.push(`-n`, String(limit), sel.range);
  } else if (sel.since) {
    // A rev endpoint (HEAD~20, a sha, a tag) → range; otherwise a git date expression.
    if (tryGit(["rev-parse", "--verify", "--quiet", `${sel.since}^{commit}`], root) !== null) {
      args.push(`-n`, String(limit), `${sel.since}..HEAD`);
    } else {
      args.push(`-n`, String(filtering ? 1000 : limit), `--since=${sel.since}`);
    }
  } else {
    // No range: most recent commits. When filtering, over-fetch then trim to `limit`.
    args.push(`-n`, String(filtering ? 1000 : limit));
  }

  const raw = tryGit(args, root);
  if (raw === null) return [];
  const commits: Commit[] = [];
  for (const rec of raw.split("\x1e")) {
    const r = rec.replace(/^\n+/, "");
    if (!r.trim()) continue;
    const [sha, author, email, date, subject, body = ""] = r.split("\x1f");
    if (!sha) continue;
    commits.push({
      sha,
      shortSha: sha.slice(0, 8),
      author: author || "",
      email: email || "",
      date: date || "",
      subject: subject || "",
      coAuthors: parseCoAuthors(body),
    });
  }
  const filtered = filtering ? commits.filter((cm) => matchesAuthor(cm, sel.author, sel.ai)) : commits;
  return filtered.slice(0, limit);
}

/** True if `ref` resolves to a commit in this repo (used to disambiguate a positional sha from a path). */
export function isCommitish(cwd: string, ref: string): boolean {
  if (!isGitRepo(cwd)) return false;
  return tryGit(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], repoRoot(cwd) || cwd) !== null;
}

/** True if `range` (A..B, A...B, a rev expression) parses to a revision list. Catches typo'd
 *  ranges that would otherwise make `git log` fail silently and scan 0 commits. */
export function isValidRange(cwd: string, range: string): boolean {
  if (!isGitRepo(cwd)) return false;
  return tryGit(["rev-list", "-n", "0", range], repoRoot(cwd) || cwd) !== null;
}

/** The empty-tree object hash, for diffing a root commit (which has no parent). */
function emptyTree(cwd: string): string {
  return (tryGit(["hash-object", "-t", "tree", "/dev/null"], cwd) || "4b825dc642cb6eb9a060e54bf8d69288fbee4904").trim();
}

/** Changed files + changed line numbers for a single commit's diff (parent → commit). */
export function getCommitChangedFiles(cwd: string, sha: string): Map<string, Set<number>> {
  const result = new Map<string, Set<number>>();
  if (!isGitRepo(cwd)) return result;
  const root = repoRoot(cwd) || cwd;
  const parent = tryGit(["rev-parse", "--verify", "--quiet", `${sha}^`], root) ? `${sha}^` : emptyTree(root);
  const names = tryGit(["diff", parent, sha, "--name-only", "--no-color"], root) || "";
  for (const rel of names.split("\n").filter(Boolean)) {
    const diff = tryGit(["diff", parent, sha, "--unified=0", "--no-color", "--", rel], root);
    result.set(path.join(root, rel), parseChangedLines(diff));
  }
  return result;
}

/** File content at a given ref (`git show <ref>:<path>`); null if absent (e.g. deleted). */
export function getBlobAtRef(cwd: string, ref: string, filePath: string): string | null {
  if (!isGitRepo(cwd)) return null;
  const { root, rel } = resolveRel(cwd, filePath);
  return tryGit(["show", `${ref}:${rel}`], root);
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
