// SPIKE (docs/DESIGN-recall-and-parity.md, option B): borrow recall from Semgrep and run it THROUGH
// DiffGate's gate, instead of hand-rolling a rule per language. The contract that keeps the low-noise
// brand intact:
//   • optional — shells out to `semgrep`; absent / failed / bad JSON → null (no-op), never an error.
//   • diff-scoped — only findings on changed lines survive (semgrep scans whole files).
//   • advisory-only — a borrowed finding NEVER auto-blocks; severity maps to tier but blocking=false,
//     exactly like `sql-injection-candidate`. Reachability/learnings decide escalation, not raw recall.
//   • deduped — when a native DiffGate finding already covers a line, the borrowed one is dropped
//     (our hand-tuned rule stays authoritative).
//
// This module is the integration + the pieces a measurement harness needs; it is deliberately NOT yet
// wired into `reviewChanges` (that is productionization, gated on the spike's go/no-go numbers).

import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import type { Finding, Tier } from "../types.js";

/** A raw finding from an external recall engine, before it is mapped onto a DiffGate tier. */
export interface RawRecallFinding {
  ruleId: string;
  line: number;
  endLine?: number;
  /** Engine-native severity (semgrep: ERROR | WARNING | INFO). */
  severity: string;
  message: string;
  file?: string;
}

export interface RecallProvider {
  id: string;
  /** External findings for one file, or null when the engine is unavailable / could not answer. */
  scan(file: string, content: string): RawRecallFinding[] | null;
  /** Batched scan of many files in ONE engine invocation (amortizes cold-start latency — the whole
   *  point of using this at the CI gate). Returns findings keyed by file path, or null if unavailable. */
  scanFiles?(files: string[]): Map<string, RawRecallFinding[]> | null;
}

/** Injectable for tests (canned semgrep JSON) — mirrors GraphRunner. Returns raw stdout or null. */
export type SemgrepRunner = (file: string, content: string) => string | null;
/** Injectable batched runner: all files in one invocation → combined JSON stdout (or null). */
export type SemgrepBatchRunner = (files: string[]) => string | null;

const DEFAULT_COMMAND = "semgrep";
const DEFAULT_TIMEOUT = 20000;

/** True if the semgrep binary resolves on PATH (or is an existing absolute path). No spawn. */
export function semgrepAvailable(cmd: string = DEFAULT_COMMAND): boolean {
  if (!cmd) return false;
  try {
    if (path.isAbsolute(cmd)) return fs.existsSync(cmd);
    const dirs = (process.env["PATH"] || "").split(path.delimiter).filter(Boolean);
    return dirs.some((d) => fs.existsSync(path.join(d, cmd)));
  } catch {
    return false;
  }
}

function runSemgrep(cmd: string, timeout: number, config: string, files: string[]): string | null {
  if (files.length === 0) return null;
  try {
    return execFileSync(
      cmd,
      ["scan", "--json", "--quiet", "--no-git-ignore", "--timeout", "15", "--config", config, ...files],
      { encoding: "utf-8", timeout, stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 }
    );
  } catch (e) {
    // semgrep exits non-zero when findings exist; execFileSync throws but still captures stdout.
    const out = (e as { stdout?: string }).stdout;
    return typeof out === "string" && out.trim() ? out : null;
  }
}

function defaultRunner(cmd: string, timeout: number, config: string): SemgrepRunner {
  return (file: string) => runSemgrep(cmd, timeout, config, [file]);
}

function defaultBatchRunner(cmd: string, timeout: number, config: string): SemgrepBatchRunner {
  return (files: string[]) => runSemgrep(cmd, timeout, config, files);
}

/** Group raw findings by their `file` (semgrep's reported `path`). */
function groupByFile(raw: RawRecallFinding[]): Map<string, RawRecallFinding[]> {
  const byFile = new Map<string, RawRecallFinding[]>();
  for (const f of raw) {
    const key = f.file ?? "";
    const arr = byFile.get(key) ?? [];
    arr.push(f);
    byFile.set(key, arr);
  }
  return byFile;
}

/** Parse semgrep `--json` output into raw findings. Tolerant of the absent/garbage cases. */
export function parseSemgrep(stdout: string | null): RawRecallFinding[] | null {
  if (!stdout || !stdout.trim()) return null;
  let doc: unknown;
  try {
    doc = JSON.parse(stdout);
  } catch {
    return null;
  }
  const results = (doc as { results?: unknown }).results;
  if (!Array.isArray(results)) return null;
  const out: RawRecallFinding[] = [];
  for (const r of results) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    const start = o["start"] as { line?: unknown } | undefined;
    const end = o["end"] as { line?: unknown } | undefined;
    const extra = (o["extra"] as Record<string, unknown>) || {};
    const line = typeof start?.line === "number" ? start.line : undefined;
    if (line === undefined) continue;
    const f: RawRecallFinding = {
      ruleId: String(o["check_id"] ?? "semgrep"),
      line,
      severity: String(extra["severity"] ?? "INFO"),
      message: String(extra["message"] ?? ""),
    };
    if (typeof end?.line === "number") f.endLine = end.line;
    if (typeof o["path"] === "string") f.file = o["path"] as string;
    out.push(f);
  }
  return out;
}

/**
 * Severity → tier map for borrowed findings. They are ADVISORY: capped at **yellow** so they never
 * trip the default `failOn: orange` gate (which fires on `tier >= failOn` OR `blocking`), and blocking
 * is always false. Same posture as `sql-injection-candidate` — recall surfaces it, it doesn't block on
 * its own. ERROR/WARNING → yellow (review); INFO → green (fyi).
 */
export function mapSeverityToTier(severity: string): { tier: Tier; blocking: false } {
  const s = severity.toUpperCase();
  if (s === "INFO" || s === "LOW") return { tier: "green", blocking: false };
  return { tier: "yellow", blocking: false };
}

/** Keep only findings on changed lines (null = whole-file mode → keep all). */
export function diffScope(findings: RawRecallFinding[], changedLines: Set<number> | null): RawRecallFinding[] {
  if (!changedLines) return findings;
  return findings.filter((f) => changedLines.has(f.line));
}

// Coarse vulnerability classes, so dedup is by KIND, not just line. Drop a borrowed finding only when
// a native DiffGate finding of the SAME class sits on the same line (ours is the precise one). A native
// finding of a different class on that line (e.g. `network-call` vs semgrep SSRF) must NOT suppress it.
// Order matters: more specific patterns first (sql before the generic `exec`/`execute`).
const CLASS_PATTERNS: [string, RegExp][] = [
  ["sql", /sql[-_ ]?inj|\bsqli\b|sql.*injection/i],
  ["nosql", /nosql|mongo.*inject/i],
  ["xss", /\bxss\b|cross.?site.?script|mark_safe|innerhtml/i],
  ["path", /path.?travers|directory.?travers|\blfi\b|file.?(read|disclosure)/i],
  ["ssrf", /\bssrf\b|server.?side.?request/i],
  ["redirect", /open.?redirect/i],
  ["cors", /\bcors\b|allow.?origin/i],
  ["exec", /command.?inj|os.?command|dangerous.?exec|system.?call|\bshell\b|subprocess|\bexec\b|\brce\b|code.?exec/i],
  ["deserialize", /deserializ|pickle|yaml.?(load|unsafe)|\bmarshal\b/i],
  ["crypto", /weak.?(hash|crypto|cipher)|\bmd5\b|\bsha1\b|insecure.?(hash|cipher|crypto)/i],
  ["secret", /secret|hardcoded|api.?key|credential/i],
];

/** Coarse vulnerability class of a rule id (native or semgrep check_id), or null if uncategorized. */
export function classOf(ruleId: string): string | null {
  for (const [cls, re] of CLASS_PATTERNS) if (re.test(ruleId)) return cls;
  return null;
}

/** Drop borrowed findings already covered by a native DiffGate finding of the SAME class on the SAME
 *  line (ours wins). Different-class native findings on that line do not suppress; uncategorized
 *  borrowed findings are kept (net-new information). */
export function dedupeAgainst(recall: RawRecallFinding[], native: Finding[]): RawRecallFinding[] {
  const nativeClassesByLine = new Map<number, Set<string>>();
  for (const n of native) {
    const cls = classOf(n.ruleId);
    if (cls === null) continue;
    const set = nativeClassesByLine.get(n.line) ?? new Set<string>();
    set.add(cls);
    nativeClassesByLine.set(n.line, set);
  }
  return recall.filter((f) => {
    const cls = classOf(f.ruleId);
    if (cls === null) return true; // uncategorized → keep, it's net-new
    return !nativeClassesByLine.get(f.line)?.has(cls);
  });
}

/** Map raw borrowed findings onto advisory DiffGate findings (ruleId namespaced, never blocking). */
export function toFindings(recall: RawRecallFinding[]): Finding[] {
  return recall.map((r) => {
    const { tier, blocking } = mapSeverityToTier(r.severity);
    const shortId = r.ruleId.split(".").pop() || r.ruleId;
    return {
      ruleId: `semgrep:${shortId}`,
      tier,
      blocking,
      title: `Semgrep: ${shortId}`,
      message: r.message,
      line: r.line,
      column: 0,
      endLine: r.endLine ?? r.line,
      endColumn: 0,
      code: "",
      fix: null,
      symbol: null,
      trust: "unconfirmed",
    } as Finding;
  });
}

export function makeSemgrepProvider(
  opts: { command?: string; timeoutMs?: number; config?: string; runner?: SemgrepRunner; batchRunner?: SemgrepBatchRunner } = {}
): RecallProvider {
  const cmd = opts.command || DEFAULT_COMMAND;
  const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT;
  const config = opts.config || "auto";
  const run = opts.runner || defaultRunner(cmd, timeout, config);
  const runBatch = opts.batchRunner || defaultBatchRunner(cmd, timeout, config);
  return {
    id: "semgrep",
    scan(file: string, _content: string): RawRecallFinding[] | null {
      return parseSemgrep(run(file, _content));
    },
    scanFiles(files: string[]): Map<string, RawRecallFinding[]> | null {
      const raw = parseSemgrep(runBatch(files));
      return raw === null ? null : groupByFile(raw);
    },
  };
}
