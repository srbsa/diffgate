import path from "path";
import { TIER_META } from "./core/tiers.js";
import type { Tier, TierCounts, AnalyzeResult } from "./core/types.js";

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

export function formatFile(fileResult: AnalyzeResult, cwd: string): string {
  const rel = path.relative(cwd, fileResult.filePath) || fileResult.filePath;
  const lines = [`  ${c.bold(c.blue(rel))}`];
  for (const f of fileResult.findings) {
    const loc = `L${String(f.line).padEnd(4)}`;
    const fixHint = f.fix ? c.green("  ↪ fix available") : "";
    lines.push(`   ${badge(f.tier)}  ${c.dim(loc)} ${f.title}${fixHint}`);
    lines.push(`        ${c.gray("└ " + firstSentence(f.message))}  ${c.dim("[" + f.ruleId + "]")}`);
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
    `${c.bold("🛡  Guardrail Review")} ${c.dim("—")} ` +
    `${files.length} ${fileWord}, ${total} finding${total === 1 ? "" : "s"}   ${summaryLine(counts)}`;
  if (total === 0) {
    return `${header}\n\n  ${c.green("✔ No guardrail findings on changed lines. Clear to merge.")}`;
  }
  return header + "\n\n" + files.map((f) => formatFile(f, cwd)).join("\n\n");
}

export function heading(text: string): string {
  return c.bold(c.blue(text));
}
