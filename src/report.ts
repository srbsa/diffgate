import path from "path";
import { TIER_META } from "./core/tiers.js";
import type { Tier, TierCounts, AnalyzeResult, CommitReview } from "./core/types.js";

const useColor = process.stdout.isTTY && !process.env["NO_COLOR"];
const wrap = (open: string) => (s: string) => (useColor ? `\x1b[${open}m${s}\x1b[0m` : String(s));

export const c = {
  bold: wrap("1"),
  dim: wrap("2"),
  green: wrap("38;2;166;227;161"),
  yellow: wrap("38;2;249;226;175"),
  orange: wrap("38;2;250;179;135"),
  red: wrap("38;2;243;139;168"),
  blue: wrap("38;2;137;180;250"),
  gray: wrap("90"),
};

const TIER_COLOR: Partial<Record<Tier, (s: string) => string>> = {
  green: c.green,
  yellow: c.yellow,
  orange: c.orange,
};

export function tierColor(tier: string): (s: string) => string {
  return TIER_COLOR[tier as Tier] || ((s: string) => s);
}

export function badge(tier: string): string {
  const meta = TIER_META[tier as Tier] || TIER_META.green;
  return tierColor(tier)(`${meta.icon} ${meta.label.toUpperCase()}`);
}

export function summaryLine(counts: TierCounts): string {
  return [
    c.green(`🟢 ${counts.green}`),
    c.yellow(`🟡 ${counts.yellow}`),
    c.orange(`🟠 ${counts.orange}`),
  ].join("  ");
}

function firstSentence(text: string): string {
  const m = text.match(/^.*?[.!?](\s|$)/);
  return (m ? m[0] : text).trim();
}

type Finding = AnalyzeResult["findings"][number];

function impactLine(f: Finding): string | null {
  const im = f.impact;
  if (!im) return null;
  if (f.tierAdjusted === "deescalated") {
    return c.gray("⚡ no callers in the code graph — exported but unused (down-tiered)");
  }
  if (im.callerCount === 0 && im.testGaps.length === 0) return null;
  const fileCount = new Set(im.callers.map((r) => r.file).filter(Boolean)).size;
  const count = im.truncated ? `${im.callerCount}+` : String(im.callerCount);
  const bits = [`⚡ ${count} call site${im.callerCount === 1 ? "" : "s"}${fileCount ? ` · ${fileCount} file${fileCount === 1 ? "" : "s"}` : ""}`];
  if (im.reachable === true) bits.push("reachable");
  if (im.reviewers.length) bits.push("route " + im.reviewers.slice(0, 3).map((r) => "@" + r).join(", "));
  if (typeof im.complexity === "number" && im.complexity >= 10) bits.push("complexity " + im.complexity);
  if (im.staleDoc) bits.push("stale docs");
  if (im.testGaps.length) bits.push("⚠ untested: " + im.testGaps.slice(0, 3).map((t) => t.symbol || t.file).join(", "));
  const colored = f.tierAdjusted === "escalated" ? c.orange : c.gray;
  return colored(bits.join(" · "));
}

// Graph-aware taint verdict line for injection-class findings.
function securityLine(f: Finding): string | null {
  const s = f.security;
  if (!s) return null;
  if (s.tainted === true) {
    const hops = s.dataFlow.map((r) => r.symbol || r.file || "?").slice(0, 5).join(" → ");
    return c.orange("🔓 taint path confirmed" + (hops ? ": " + hops : ""));
  }
  if (s.tainted === false) {
    return c.gray("🛡 no taint path in the code graph" + (f.tierAdjusted === "deescalated" ? " (down-tiered)" : ""));
  }
  return null;
}

export function formatFile(fileResult: AnalyzeResult, cwd: string): string {
  const rel = path.relative(cwd, fileResult.filePath) || fileResult.filePath;
  const lines = [`  ${c.bold(c.blue(rel))}`];
  for (const f of fileResult.findings) {
    const loc = `L${String(f.line).padEnd(4)}`;
    const fixHint = f.fix ? c.green("  ↪ fix available") : "";
    lines.push(`   ${badge(f.tier)}  ${c.dim(loc)} ${f.title}${fixHint}`);
    lines.push(`        ${c.gray("└ " + firstSentence(f.message))}  ${c.dim("[" + f.ruleId + "]")}`);
    const im = impactLine(f);
    if (im) lines.push(`        ${im}`);
    const sec = securityLine(f);
    if (sec) lines.push(`        ${sec}`);
    if (f.code) lines.push(`        ${c.dim(c.gray(truncate(f.code, 78)))}`);
  }
  return lines.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export function formatReport(files: AnalyzeResult[], { counts, tier }: { counts: TierCounts; tier: string }, cwd: string): string {
  const total = files.reduce((n, f) => n + f.findings.length, 0);
  const fileWord = files.length === 1 ? "file" : "files";
  const header =
    `${c.bold("🛡  DiffGate")} ${c.dim("—")} ` +
    `${files.length} ${fileWord}, ${total} finding${total === 1 ? "" : "s"}   ${summaryLine(counts)}`;
  if (total === 0) {
    return `${header}\n\n  ${c.green("✔ No DiffGate findings on changed lines. Clear to merge.")}`;
  }
  return header + "\n\n" + files.map((f) => formatFile(f, cwd)).join("\n\n");
}

export function heading(text: string): string {
  return c.bold(c.blue(text));
}

function relativeDate(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const secs = Math.max(0, (Date.now() - t) / 1000);
  const units: [number, string][] = [
    [31536000, "year"], [2592000, "month"], [604800, "week"],
    [86400, "day"], [3600, "hour"], [60, "minute"],
  ];
  for (const [size, name] of units) {
    const n = Math.floor(secs / size);
    if (n >= 1) return `${n} ${name}${n === 1 ? "" : "s"} ago`;
  }
  return "just now";
}

/** Renders a history scan as a per-commit story: each flagged commit with attribution, then a
 *  one-line tally of the clean ones ("8 other commits: clean ✅"). */
export function formatHistory(
  result: { commits: CommitReview[]; scanned: number; withFindings: number },
  cwd: string
): string {
  const flagged = result.commits.filter((r) => r.files.length > 0);
  const header =
    `${c.bold("🛡  DiffGate")} ${c.dim("—")} history scan: ` +
    `${result.scanned} commit${result.scanned === 1 ? "" : "s"}, ` +
    `${result.withFindings} with findings`;
  if (result.scanned === 0) {
    return `${header}\n\n  ${c.dim("No commits matched the selection.")}`;
  }
  if (flagged.length === 0) {
    return `${header}\n\n  ${c.green("✔ No DiffGate findings across the scanned commits. Clear ✅")}`;
  }
  const blocks = flagged.map((r) => {
    const cm = r.commit;
    const author = cm.coAuthors[0] ? `${cm.author} + ${shortAuthor(cm.coAuthors[0])}` : cm.author;
    const head =
      `${c.bold(c.blue(cm.shortSha))}  ${c.dim(`(${author}, ${relativeDate(cm.date)})`)}  ${cm.subject}`;
    const body = r.files.map((f) => formatFile(f, cwd)).join("\n");
    return `${head}\n${body}`;
  });
  const cleanCount = result.scanned - flagged.length;
  const footer =
    cleanCount > 0
      ? `\n\n  ${c.dim(`${cleanCount} other commit${cleanCount === 1 ? "" : "s"}:`)} ${c.green("clean ✅")}`
      : "";
  return header + "\n\n" + blocks.join("\n\n") + footer;
}

function shortAuthor(coAuthor: string): string {
  // "Claude <noreply@anthropic.com>" → "Claude"
  const m = coAuthor.match(/^\s*([^<]+?)\s*(?:<|$)/);
  return (m ? m[1] : coAuthor).trim();
}
