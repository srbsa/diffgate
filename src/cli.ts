import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import chokidar from "chokidar";
import { toSarif } from "./sarif.js";

import {
  analyze,
  loadConfig,
  isIgnored,
  getChangedLinesForFile,
  getPreviousContent,
  isGitRepo,
  repoRoot,
  headSha,
  runGate,
  explainFinding,
  deepReview,
  isAiAvailable,
  aiKeyEnv,
  describeProvider,
  tierCounts,
  overallTier,
  TIER_ORDER,
  reviewChanges,
  reviewGuidelines,
  recordLearning,
  loadLearnings,
  loadMergedLearnings,
  applyLearnings,
  predictedSignal,
  realizedSignal,
  graphStatus,
  resolveGraphConfig,
  makeCodeGraphProvider,
  IMPACT_RULES,
  shouldShowGraphTip,
  recordGraphTipShown,
} from "./core/index.js";
import { c, formatReport, formatFile, badge, summaryLine } from "./report.js";
import { runMcpServer } from "./mcp.js";
import { buildPrReview, resolveGithubContext, postPrReview } from "./github.js";
import { runBench, CORPUS } from "./bench.js";
import { complianceReport } from "./compliance.js";
import { buildMetrics, agentVerdict } from "./metrics.js";
import { detectProjectDefaults, tailorConfig } from "./scaffold.js";
import type { Finding, AnalyzeResult, Config, Tier } from "./core/types.js";

declare const __DIFFGATE_VERSION__: string;
const CLI_PATH = fileURLToPath(import.meta.url);
const VERSION = typeof __DIFFGATE_VERSION__ !== "undefined" ? __DIFFGATE_VERSION__ : "0.0.0";

function parseArgs(argv: string[]): { pos: string[]; flags: Record<string, string | true> } {
  const flags: Record<string, string | true> = {};
  const pos: string[] = [];
  for (const a of argv) {
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=");
      flags[k] = v === undefined ? true : v;
    } else if (a.startsWith("-") && a.length > 1) {
      flags[a.slice(1)] = true;
    } else {
      pos.push(a);
    }
  }
  return { pos, flags };
}

function fail(msg: string): never {
  console.error(c.red(`✖ ${msg}`));
  process.exit(2);
}

function resolveMode(flags: Record<string, string | true>, config: Config): string {
  if (flags["staged"]) return "staged";
  if (flags["working"]) return "working";
  return config.gate.mode || "working";
}

async function printAiExplanations(findings: Finding[], files: AnalyzeResult[], config: Config, limit = 8): Promise<void> {
  if (!isAiAvailable(config)) {
    console.log(c.dim(`\n  (AI explanations off — set ai.enabled in .diffgate.json and export $${aiKeyEnv(config)} to enable.)`));
    return;
  }
  const byFile = new Map(files.map((f) => [f.filePath, f]));
  const targets = findings.filter((f) => f.tier === "orange" || f.blocking).slice(0, limit);
  if (targets.length === 0) return;
  console.log(c.bold("\n🤖 AI review") + c.dim(` (${describeProvider(config)})\n`));
  for (const finding of targets) {
    const file = findFileFor(finding, files);
    const fileRes = file ? byFile.get(file.filePath) : undefined;
    const snippet = fileRes ? snippetAround(fileRes, finding) : (finding.code || "");
    try {
      const { text, model } = await explainFinding({
        finding,
        snippet,
        language: fileRes?.language || "text",
        config,
      });
      console.log(`  ${badge(finding.tier)} ${c.bold(finding.title)} ${c.dim("(" + model + ")")}`);
      console.log(indent(text, 4) + "\n");
    } catch (e) {
      console.log(c.dim(`  (AI explanation failed: ${(e as Error).message})\n`));
    }
  }
}

function findFileFor(finding: Finding, files: AnalyzeResult[]): AnalyzeResult | undefined {
  return files.find((f) => f.findings.includes(finding));
}

async function printDeepReviews(findings: Finding[], files: AnalyzeResult[], config: Config, cwd: string, limit = 5): Promise<void> {
  if (!isAiAvailable(config)) {
    console.log(c.dim(`\n  (Deep Review needs AI — set ai.enabled and $${aiKeyEnv(config)}, or use a local provider.)`));
    return;
  }
  const root = repoRoot(cwd) || cwd;
  const targets = findings.filter((f) => f.tier === "orange" || f.blocking).slice(0, limit);
  if (targets.length === 0) {
    console.log(c.dim("\n  (No orange findings to deep-review.)"));
    return;
  }
  console.log(c.bold("\n🔬 Deep Review") + c.dim(` (${describeProvider(config)} · agentic)\n`));
  for (const f of targets) {
    const fileRes = findFileFor(f, files);
    if (!fileRes) continue;
    const rel = path.relative(root, fileRes.filePath);
    console.log(`  ${badge(f.tier)} ${c.bold(f.title)} ${c.dim(rel + ":" + f.line)}`);
    try {
      const res = await deepReview({
        finding: f,
        filePath: rel,
        snippet: snippetAround(fileRes, f, 6),
        language: fileRes.language,
        cwd: root,
        config,
        onStep: ({ name, input }) =>
          console.log(c.gray(`    ⚙ ${name}(${JSON.stringify(input).slice(0, 70)})`)),
      });
      console.log(c.dim(`    ↳ ${res.steps} step(s) · ${res.model}`));
      console.log(indent(res.verdict, 4) + "\n");
    } catch (e) {
      console.log(c.dim(`    (deep review failed: ${(e as Error).message})\n`));
    }
  }
}

function snippetAround(fileRes: AnalyzeResult, finding: Finding, radius = 4): string {
  if (!fileRes) return finding.code || "";
  try {
    const content = fs.readFileSync(fileRes.filePath, "utf-8").split("\n");
    const start = Math.max(0, finding.line - 1 - radius);
    const end = Math.min(content.length, finding.line + radius);
    return content.slice(start, end).join("\n");
  } catch {
    return finding.code || "";
  }
}

function indent(text: string, n: number): string {
  const pad = " ".repeat(n);
  return text.split("\n").map((l) => pad + l).join("\n");
}

async function cmdCheck(pos: string[], flags: Record<string, string | true>): Promise<void> {
  const cwd = path.resolve(pos[0] || ".");
  if (!isGitRepo(cwd)) {
    console.log(c.yellow("⚠ Not a git repository.") + ` ${c.dim("`diffgate check` reviews your diff. Use `diffgate scan` to analyze files directly.")}`);
    process.exit(0);
  }
  const { config } = loadConfig(cwd);
  const mode = resolveMode(flags, config);
  const base = typeof flags["base"] === "string" ? (flags["base"] as string) : undefined;
  const review = reviewChanges(cwd, { mode, base });
  const allFindings = review.files.flatMap((f) => f.findings);

  if (flags["json"]) {
    console.log(JSON.stringify({ mode, ...stripForJson(review) }, null, 2));
    return;
  }

  if (flags["sarif"] || flags["format"] === "sarif") {
    console.log(toSarif(review.files, cwd, VERSION));
    return;
  }

  if (flags["github"] || flags["format"] === "github") {
    printGithubAnnotations(review.files, cwd);
    const failOn = (flags["fail-on"] as string) || config.gate.failOn || "orange";
    const failRank = TIER_ORDER[failOn] ?? 2;
    const blocked = allFindings.some((f) => f.blocking || (TIER_ORDER[f.tier] ?? 0) >= failRank);
    process.exit(blocked && !flags["no-fail"] ? 1 : 0);
  }

  if (flags["agent"]) {
    const modeOverride = typeof flags["agent-mode"] === "string" ? (flags["agent-mode"] as "advisory" | "gated" | "off") : undefined;
    const agentCfg = { ...config.gate.agent, ...(modeOverride ? { mode: modeOverride } : {}) };
    const v = agentVerdict(review.files, agentCfg);
    console.log(JSON.stringify(v, null, 2));
    process.exit(v.verdict === "blocked" && !flags["no-fail"] ? 1 : 0);
  }

  if (flags["pr"] || flags["pr-dry-run"]) {
    await runPrReview(review.files, cwd, config, flags);
    return;
  }

  console.log(formatReport(review.files, review, cwd));
  console.log(c.dim(`\n  diff mode: ${mode}`));
  maybeGraphTip(allFindings, config, cwd);

  if (flags["deep"]) await printDeepReviews(allFindings, review.files, config, cwd);
  else if (flags["ai"]) await printAiExplanations(allFindings, review.files, config);

  let gateFailed = false;
  if (!flags["no-gate"]) {
    const gate = await runGate({ cwd, config, findings: allFindings });
    if (gate.ran) {
      const gateRes = gate as { success?: boolean; durationMs?: number; code?: number; command?: string; stdout?: string; stderr?: string };
      const status = gateRes.success
        ? c.green(`✓ passed (${((gateRes.durationMs ?? 0) / 1000).toFixed(1)}s)`)
        : c.red(`✗ failed (exit ${gateRes.code})`);
      console.log(`\n  ${c.bold("Gate:")} ${c.dim(config.testCommand ?? "")} — ${status}`);
      if (!gateRes.success) {
        gateFailed = true;
        const out = ((gateRes.stdout || "") + (gateRes.stderr || "")).trim().split("\n").slice(-15).join("\n");
        console.log(indent(c.dim(out), 4));
      }
    }
  }

  const failOn = (flags["fail-on"] as string) || config.gate.failOn || "orange";
  const failRank = TIER_ORDER[failOn] ?? 2;
  const tripped = allFindings.some((f) => f.blocking || (TIER_ORDER[f.tier] ?? 0) >= failRank);
  const blocked = tripped || gateFailed;

  console.log("");
  if (blocked) {
    const reasons: string[] = [];
    if (tripped) reasons.push(`findings at/above ${failOn}`);
    if (gateFailed) reasons.push("gate command failed");
    console.log(c.red(`✖ Blocked — ${reasons.join(" + ")}.`));
  } else {
    console.log(c.green("✔ Passed — clear to commit."));
  }
  process.exit(blocked && !flags["no-fail"] ? 1 : 0);
}

function stripForJson(review: ReturnType<typeof reviewChanges>) {
  return {
    tier: review.tier,
    counts: review.counts,
    blocking: review.blocking,
    files: review.files.map((f) => ({
      file: f.filePath,
      language: f.language,
      tier: f.tier,
      findings: f.findings,
    })),
  };
}

const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
  ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mov", ".mp3", ".wasm", ".so", ".dylib",
  ".class", ".jar", ".lock",
]);

function isProbablyBinary(filePath: string): boolean {
  if (BINARY_EXT.has(path.extname(filePath).toLowerCase())) return true;
  try {
    const fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(1024);
    const n = fs.readSync(fd, buf, 0, 1024, 0);
    fs.closeSync(fd);
    return buf.subarray(0, n).includes(0);
  } catch {
    return true;
  }
}

function* walkFiles(dir: string, config: Config, root: string): Generator<string> {
  let entries: fs.Dirent[] = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const fp = path.join(dir, entry.name);
    if (isIgnored(fp, config, root)) continue;
    if (entry.isDirectory()) {
      yield* walkFiles(fp, config, root);
    } else if (entry.isFile()) {
      try {
        if (fs.statSync(fp).size > 1024 * 1024) continue;
      } catch {
        continue;
      }
      if (isProbablyBinary(fp)) continue;
      yield fp;
    }
  }
}

async function cmdScan(pos: string[], flags: Record<string, string | true>): Promise<void> {
  const target = path.resolve(pos[0] || ".");
  let stat: fs.Stats | undefined;
  try {
    stat = fs.statSync(target);
  } catch {
    fail(`No such file or directory: ${target}`);
  }
  const baseDir = stat!.isDirectory() ? target : path.dirname(target);
  const { config } = loadConfig(baseDir);

  const filePaths = stat!.isDirectory()
    ? [...walkFiles(target, config, target)]
    : [target];

  const learnings = loadLearnings(repoRoot(baseDir) || baseDir);
  const files: AnalyzeResult[] = [];
  for (const fp of filePaths) {
    let content: string;
    try {
      content = fs.readFileSync(fp, "utf-8");
    } catch {
      continue;
    }
    const res = applyLearnings(analyze({ filePath: fp, content, config }), learnings);
    if (res.findings.length > 0) files.push(res);
  }

  const allFindings = files.flatMap((f) => f.findings);
  const review = { files, counts: tierCounts(allFindings), tier: overallTier(allFindings), blocking: allFindings.some((f) => f.blocking) };

  if (flags["json"]) {
    console.log(JSON.stringify(stripForJson({ ...review, config }), null, 2));
    return;
  }

  const reviewCwd = stat!.isDirectory() ? target : baseDir;

  if (flags["sarif"] || flags["format"] === "sarif") {
    console.log(toSarif(files, reviewCwd));
    return;
  }
  console.log(formatReport(files, review, reviewCwd));
  if (flags["deep"]) await printDeepReviews(allFindings, files, config, reviewCwd);
  else if (flags["ai"]) await printAiExplanations(allFindings, files, config);

  if (flags["fail-on"]) {
    const failRank = TIER_ORDER[flags["fail-on"] as string] ?? 2;
    const tripped = allFindings.some((f) => f.blocking || (TIER_ORDER[f.tier] ?? 0) >= failRank);
    process.exit(tripped ? 1 : 0);
  }
}

function cmdWatch(pos: string[], _flags: Record<string, string | true>): void {
  const cwd = path.resolve(pos[0] || ".");
  const { config, path: cfgPath } = loadConfig(cwd);
  const git = isGitRepo(cwd);

  console.log(c.bold("🛡  DiffGate — live review") + c.dim(`  watching ${cwd}`));
  console.log(c.dim(
    `  ${cfgPath ? "config: " + path.relative(cwd, cfgPath) : "no .diffgate.json (defaults)"} · ` +
    `${git ? "diff-aware (vs HEAD)" : "whole-file (not a git repo)"} · Ctrl-C to stop`
  ));
  console.log(c.gray("  " + "─".repeat(70)));

  const watcher = chokidar.watch(cwd, {
    ignored: [/(^|[\/\\])\../, "**/node_modules/**", "**/.git/**", "**/dist/**"],
    ignoreInitial: true,
    persistent: true,
  });

  watcher.on("change", async (fp: string) => {
    if (isIgnored(fp, config, cwd)) return;
    let content: string;
    try {
      content = fs.readFileSync(fp, "utf-8");
    } catch {
      return;
    }
    const changedLines = git ? getChangedLinesForFile(cwd, fp, { mode: "working" }) : null;
    const previousContent = git ? getPreviousContent(cwd, fp, { mode: "working" }) : null;
    const res = analyze({ filePath: fp, content, previousContent, changedLines, config });
    const t = new Date().toLocaleTimeString();
    if (res.findings.length === 0) {
      console.log(`${c.gray(t)} ${badge("green")} ${c.dim(path.relative(cwd, fp))} — clear`);
      return;
    }
    console.log(`${c.gray(t)} ${path.relative(cwd, fp)}  ${summaryLine(res.counts)}`);
    console.log(formatFile(res, cwd));
  });

  watcher.on("error", (e: Error) => console.error(c.red(`watch error: ${e.message}`)));
}

async function cmdExplain(pos: string[], flags: Record<string, string | true>): Promise<void> {
  const target = path.resolve(pos[0] || "");
  if (!pos[0] || !fs.existsSync(target)) fail("Usage: diffgate explain <file>");
  const { config } = loadConfig(path.dirname(target));
  if (!isAiAvailable(config)) {
    fail(`AI is not configured. Set "ai": { "enabled": true } in .diffgate.json and export $${aiKeyEnv(config)}.`);
  }
  const content = fs.readFileSync(target, "utf-8");
  const res = analyze({ filePath: target, content, config });
  if (res.findings.length === 0) {
    console.log(c.green("✔ No findings to explain."));
    return;
  }
  console.log(formatReport([res], { counts: res.counts, tier: res.tier }, path.dirname(target)));
  if (flags["deep"]) await printDeepReviews(res.findings, [res], config, path.dirname(target));
  else await printAiExplanations(res.findings, [res], config, 20);
}

// GitHub Actions workflow-command annotations — render inline on the PR "Files changed" tab.
function ghEscapeData(s: string): string {
  return s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}
function ghEscapeProp(s: string): string {
  return ghEscapeData(s).replace(/,/g, "%2C").replace(/:/g, "%3A");
}
function printGithubAnnotations(files: AnalyzeResult[], cwd: string): void {
  const level: Record<string, string> = { orange: "error", yellow: "warning", green: "notice" };
  for (const file of files) {
    const rel = path.relative(cwd, file.filePath);
    for (const f of file.findings) {
      const props = [
        `file=${ghEscapeProp(rel)}`,
        `line=${f.line}`,
        f.endLine ? `endLine=${f.endLine}` : "",
        `title=${ghEscapeProp("DiffGate: " + f.title)}`,
      ].filter(Boolean).join(",");
      // f.message already carries the blast-radius summary when the impact pass enriched it.
      console.log(`::${level[f.tier] || "warning"} ${props}::${ghEscapeData(f.message)}`);
    }
  }
}

async function runPrReview(files: AnalyzeResult[], cwd: string, config: Config, flags: Record<string, string | true>): Promise<void> {
  const failOn = ((flags["fail-on"] as string) || config.gate.failOn || "orange") as Tier;
  const payload = buildPrReview(files, cwd, { failOn });
  const prFlag = typeof flags["pr"] === "string" ? (flags["pr"] as string) : undefined;
  const ctx = resolveGithubContext(process.env, prFlag, (p) => {
    try { return fs.readFileSync(p, "utf-8"); } catch { return null; }
  });
  if (!ctx.sha) ctx.sha = headSha(cwd);

  if (flags["pr-dry-run"] || !ctx.token) {
    if (!flags["pr-dry-run"] && !ctx.token) console.error(c.dim("(no GITHUB_TOKEN — dry-run; showing the payload that would be posted)"));
    console.log(JSON.stringify({ context: { repo: ctx.repo, prNumber: ctx.prNumber, sha: ctx.sha, hasToken: !!ctx.token }, ...payload }, null, 2));
  } else {
    const r = await postPrReview(payload, ctx, fetch as unknown as Parameters<typeof postPrReview>[2]);
    if (r.posted) console.log(c.green(`✔ Posted DiffGate review to ${ctx.repo}${ctx.prNumber ? ` PR #${ctx.prNumber}` : ""} (${payload.event})`));
    else console.log(c.yellow(`⚠ Did not post: ${r.reason}`));
  }
  process.exit(payload.blocked && !flags["no-fail"] ? 1 : 0);
}

async function cmdReport(pos: string[], flags: Record<string, string | true>): Promise<void> {
  const cwd = path.resolve(pos[0] || ".");
  if (!isGitRepo(cwd)) fail("`diffgate report` needs a git repo (it summarizes your diff). Use `diffgate scan` for whole-file analysis.");
  const { config } = loadConfig(cwd);
  const mode = resolveMode(flags, config);
  const base = typeof flags["base"] === "string" ? (flags["base"] as string) : undefined;
  const review = reviewChanges(cwd, { mode, base });
  const root = repoRoot(cwd) || cwd;

  if (flags["compliance"]) {
    const rep = complianceReport(review.files);
    if (flags["json"]) { console.log(JSON.stringify(rep, null, 2)); return; }
    console.log(c.bold("🛡  DiffGate — SOC 2 control evidence") + c.dim(`  (diff mode: ${mode})\n`));
    if (rep.evidence.length === 0) {
      console.log(c.dim("  No control-relevant findings in the changed lines."));
    } else {
      for (const e of rep.evidence) {
        console.log(`  ${c.bold(e.control.id)}  ${e.control.title}`);
        console.log(`     ${c.dim(`${e.findings} finding(s) · ${e.rules.join(", ")}`)}`);
      }
    }
    console.log("");
    console.log(c.dim(`  The orange gate enforces CC8.1 (changes reviewed before deploy). ${rep.blocked ? c.orange("Gate would block this change.") : "No blocking findings."}`));
    if (rep.unmapped.length) console.log(c.dim(`  Unmapped findings: ${rep.unmapped.join(", ")}`));
    return;
  }

  const learnings = loadMergedLearnings(root, config.learnings?.shared || [], root);
  const m = buildMetrics(review.files, learnings, root);
  if (flags["json"]) { console.log(JSON.stringify(m, null, 2)); return; }

  console.log(c.bold("🛡  DiffGate — review metrics") + c.dim(`  (diff mode: ${mode})\n`));
  console.log(`  ${summaryLine(m.counts)}   ${c.dim(`${m.total} findings across ${m.filesWithFindings} file(s)`)}`);
  console.log(`  ${m.blocked ? c.red("✖ would block merge") : c.green("✔ clear to merge")}\n`);
  if (m.topRules.length) {
    console.log(c.bold("  Top rules"));
    for (const r of m.topRules) console.log(`     ${String(r.count).padStart(3)} × ${r.rule}`);
    console.log("");
  }
  if (m.topFiles.some((f) => f.total > 0)) {
    console.log(c.bold("  Hotspot files"));
    for (const f of m.topFiles.filter((f) => f.total > 0)) console.log(`     ${c.dim(`🟠${f.orange} / ${f.total}`)}  ${f.file}`);
    console.log("");
  }
  console.log(c.bold("  Learnings (noise-reduction loop)"));
  console.log(`     ${m.learnings.dismissed} dismissed · ${m.learnings.confirmed} confirmed · ${m.learnings.total} total`);
  if (m.learnings.noisiestRules.length) {
    console.log(c.dim(`     noisiest: ${m.learnings.noisiestRules.map((r) => `${r.rule}(${r.count})`).join(", ")}`));
  }
}

function cmdBench(pos: string[], flags: Record<string, string | true>): void {
  const result = runBench(analyze, CORPUS);
  if (flags["json"]) { console.log(JSON.stringify(result, null, 2)); return; }
  console.log(c.bold("🛡  DiffGate — noise benchmark") + c.dim(`  ${result.cases} cases (${result.positives} positive, ${result.cleanCases} clean)\n`));
  console.log(c.bold("  rule".padEnd(26) + "prec   rec    f1    tp/fp/fn"));
  for (const r of result.rules) {
    console.log(
      "  " + r.rule.padEnd(24) +
      `${pct(r.precision)}  ${pct(r.recall)}  ${pct(r.f1)}  ${c.dim(`${r.tp}/${r.fp}/${r.fn}`)}`
    );
  }
  const o = result.overall;
  console.log(c.bold("\n  overall".padEnd(26) + `${pct(o.precision)}  ${pct(o.recall)}  ${pct(o.f1)}  ${c.dim(`${o.tp}/${o.fp}/${o.fn}`)}`));
  const blocks = result.falseBlocksPerCleanCase;
  const blocksStr = `${blocks.toFixed(2)} false BLOCK(s) per clean change`;
  console.log(`  ${c.bold("Gate noise:")} ${blocks === 0 ? c.green(blocksStr) : c.red(blocksStr)}  ${c.dim(`(${result.advisoriesPerCleanCase.toFixed(2)} advisory/clean change)`)}`);
  console.log(c.dim("\n  Methodology: BENCHMARK.md. Corpus is versioned in src/bench.ts — reproduce with `diffgate bench --json`."));
}

function pct(n: number): string {
  return (n * 100).toFixed(0).padStart(3) + "%";
}

async function cmdGuidelines(pos: string[], flags: Record<string, string | true>): Promise<void> {
  const cwd = path.resolve(pos[0] || ".");
  const mode = flags["staged"] ? "staged" : "working";
  const res = await reviewGuidelines(cwd, { mode, log: (m) => console.log(c.dim(m)) });
  if (flags["json"]) { console.log(JSON.stringify(res, null, 2)); return; }
  if (res.mode === "host") {
    // No model configured — guideline review needs either a provider or an agent host.
    if (res.payload.groups.length === 0) { console.log(c.green("✔ No coding-guideline files apply to the changed files.")); return; }
    console.log(c.yellow("No AI model configured for guideline review."));
    console.log(c.dim(`Found guidelines in: ${res.payload.groups.flatMap((g) => g.sources).join(", ")}`));
    console.log(c.dim("Configure ai.* in .diffgate.json, or run DiffGate via an MCP agent (diffgate_guidelines) to evaluate with the agent's own model."));
    return;
  }
  if (res.findings.length === 0) { console.log(c.green("✔ No coding-guideline violations in the changed lines.")); return; }
  for (const f of res.findings) {
    console.log(`${badge(f.tier)} ${c.bold(f.title)} ${c.dim(f.ruleId)}`);
    console.log(`  ${f.message}`);
    if (f.code) console.log(c.dim(`  ${f.line}: ${f.code}`));
  }
}

function cmdFeedback(pos: string[], flags: Record<string, string | true>): void {
  const ruleId = pos[0];
  const fileArg = pos[1];
  const lineArg = pos[2];
  if (!ruleId || !fileArg || !lineArg) {
    fail('Usage: diffgate feedback <ruleId> <file> <line> [--confirm] [--note=...]   (default: dismiss as noise)');
  }
  const abs = path.resolve(fileArg);
  if (!fs.existsSync(abs)) fail(`No such file: ${abs}`);
  const line = parseInt(lineArg, 10);
  if (!Number.isInteger(line) || line < 1) fail(`Invalid line number: ${lineArg}`);
  const code = (fs.readFileSync(abs, "utf-8").split("\n")[line - 1] ?? "").trim();
  if (!code) fail(`Line ${line} of ${fileArg} is empty — nothing to record.`);
  const verdict = flags["confirm"] ? "confirm" : "dismiss";
  const root = repoRoot(path.dirname(abs)) || path.dirname(abs);
  const entry = recordLearning(root, { ruleId, code, verdict, file: path.relative(root, abs), note: flags["note"] as string });
  console.log(c.green(`✔ Recorded ${verdict} for ${c.bold(ruleId)} on ${path.relative(root, abs)}:${line}`));
  if (verdict === "dismiss") console.log(c.dim(`  This exact flagged code won't be reported again. Stored in .diffgate/learnings.json (${entry.id}).`));
}
function cmdStats(pos: string[], flags: Record<string, string | true>): void {
  const cwd = path.resolve(pos[0] || ".");
  const root = repoRoot(cwd) || cwd;
  const realized = realizedSignal(loadLearnings(root));

  let predicted: ReturnType<typeof predictedSignal> | null = null;
  if (isGitRepo(cwd)) {
    try {
      predicted = predictedSignal(reviewChanges(cwd, { mode: resolveMode(flags, loadConfig(cwd).config) }).counts);
    } catch {
      /* best-effort */
    }
  }

  if (flags["json"]) {
    console.log(JSON.stringify({ realized, predicted }, null, 2));
    return;
  }

  console.log(`${c.bold("🛡  DiffGate")} ${c.dim("— signal report")}\n`);

  console.log(c.bold("Realized") + c.dim("  (from reviewer verdicts in .diffgate/learnings.json)"));
  if (realized.total === 0) {
    console.log(c.dim("  No verdicts recorded yet. Run `diffgate feedback <ruleId> <file> <line>` to start measuring.\n"));
  } else {
    const ratioStr = realized.signalRatio >= 0.6 ? c.green(pct(realized.signalRatio)) : c.orange(pct(realized.signalRatio));
    console.log(`  ${c.green(realized.confirmed + " confirmed")} · ${c.dim(realized.dismissed + " dismissed")} · signal ratio ${ratioStr}`);
    if (realized.chronicNoise.length) {
      console.log("\n  " + c.bold("Chronically noisy rules") + c.dim(" (high dismiss rate)"));
      for (const r of realized.chronicNoise) {
        console.log(
          `   ${c.orange(r.ruleId.padEnd(22))} ${r.dismissed}/${r.total} dismissed ${c.dim("(" + pct(r.dismissRate) + " noise)")} ` +
            c.dim(`→ "rules": { "${r.ruleId}": false }`)
        );
      }
    }
    console.log("");
  }

  if (predicted) {
    console.log(c.bold("Predicted") + c.dim("  (current diff: 🟠/🟡 = signal, 🟢 = low-signal)"));
    console.log(`  ${summaryLine({ green: predicted.t3, yellow: predicted.t2, orange: predicted.t1 })}   signal ratio ${c.bold(pct(predicted.ratio))}`);
  }
}

// One-line, non-nagging nudge: only when graphing is on, no index exists, AND the diff actually
// contains a public-surface finding that a code graph would have enriched. CodeGraph is strictly
// optional (the engine is fully useful without it), so the tip fades out after a few shows.
function maybeGraphTip(findings: Finding[], config: Config, cwd: string): void {
  const status = graphStatus(config);
  if (!status.enabled || status.indexed) return;
  if (!findings.some((f) => IMPACT_RULES.has(f.ruleId))) return;
  const root = repoRoot(cwd) || cwd;
  if (!shouldShowGraphTip(root)) return;
  const how = status.commandFound ? "diffgate graph index" : "install CodeGraph, then `diffgate graph index`";
  console.log(c.dim(`\n  💡 Optional: cross-file blast radius is off — ${how} to route reviewers by caller count.`));
  recordGraphTipShown(root);
}

function cmdGraph(pos: string[], flags: Record<string, string | true>): void {
  const sub = pos[0] || "status";
  const cwd = path.resolve(pos[1] || ".");
  const { config } = loadConfig(cwd);
  const g = resolveGraphConfig(config);
  const status = graphStatus(config);

  if (sub === "status") {
    if (flags["json"]) { console.log(JSON.stringify(status, null, 2)); return; }
    const dot = (ok: boolean) => (ok ? c.green("●") : c.gray("○"));
    console.log(`${c.bold("🛡  DiffGate")} ${c.dim("— code graph")}\n`);
    console.log(`  ${dot(status.enabled)} enabled       ${c.dim(status.enabled ? "yes" : "no (graph.enabled=false / mode=off)")}`);
    console.log(`  ${dot(status.commandFound)} ${("`" + status.command + "`").padEnd(20)} ${c.dim(status.commandFound ? "found on PATH" : "not on PATH")}`);
    console.log(`  ${dot(status.indexed)} indexed       ${c.dim(status.indexed ? status.dbPath : "no index")}`);
    console.log(`\n  ${status.indexed ? c.green("✔ " + status.reason) : c.yellow(status.reason)}`);
    return;
  }

  if (sub === "index") {
    if (g.enabled === false || g.mode === "off") {
      fail("Graphing is disabled in .diffgate.json (graph.enabled=false / mode=off).");
    }
    if (!status.commandFound) {
      console.log(c.yellow(`✖ ${g.command} not found on PATH.`));
      console.log(c.dim("\n  Install CodeGraph (github.com/codegraph-ai/CodeGraph), e.g.:"));
      console.log("    " + c.bold("npm i -g @codegraph-ai/codegraph") + c.dim("   # or download a release binary"));
      console.log(c.dim(`  Then re-run ${c.bold("diffgate graph index")}. Set "graph.command" if the binary is named differently.`));
      process.exit(1);
    }
    console.log(c.dim(`Indexing ${cwd} with ${g.command}${flags["full"] ? " (full reindex)" : ""}…`));
    const provider = makeCodeGraphProvider(cwd, g);
    const ok = typeof provider.reindex === "function" ? provider.reindex({ full: !!flags["full"] }) : false;
    if (ok) {
      console.log(c.green(`✔ Indexed. Cross-file blast radius is now active for ${path.basename(cwd)}.`));
      console.log(c.dim("  CodeGraph keeps the index fresh via filesystem events; re-run after large refactors."));
    } else {
      console.log(c.yellow("⚠ Index command returned no confirmation."));
      console.log(c.dim(`  Verify ${g.command} runs standalone, or index manually per CodeGraph's docs. Checked: ${status.dbPath}`));
      process.exit(1);
    }
    return;
  }

  fail(`Unknown graph subcommand: ${sub}. Use \`diffgate graph status\` or \`diffgate graph index\`.`);
}

const INIT_TEMPLATE = {
  testCommand: null,
  gate: { mode: "working", failOn: "orange" },
  ai: { enabled: false, model: "claude-sonnet-4-6", apiKeyEnv: "ANTHROPIC_API_KEY" },
  deprecated: [{ pattern: "OldService.legacyMethod", replacedBy: "NewService.method", author: "Your Team", pr: "PR #000" }],
  customPatterns: [{ id: "no-direct-process-env", tier: "yellow", pattern: "process\\.env\\.", message: "Read config through the typed config module, not process.env directly." }],
  rules: {},
  guidelines: { enabled: true, autoDetect: true, maxDepth: 3, tier: "yellow", blocking: false, evaluator: "auto" },
  graph: { enabled: "auto", provider: "codegraph", command: "codegraph-server", mode: "cli", escalateThreshold: 1 },
  ignore: ["**/node_modules/**", "**/dist/**", "**/build/**"],
};

function cmdInit(pos: string[], flags: Record<string, string | true>): void {
  const cwd = path.resolve(pos[0] || ".");
  const target = path.join(cwd, ".diffgate.json");
  if (fs.existsSync(target) && !flags["force"]) {
    fail(`.diffgate.json already exists. Use --force to overwrite.`);
  }
  let template: Record<string, unknown> = INIT_TEMPLATE;
  if (!flags["minimal"]) {
    const detected = detectProjectDefaults(cwd);
    template = tailorConfig(INIT_TEMPLATE, detected);
    console.log(c.bold("🛡  DiffGate — analyzing project…"));
    for (const r of detected.reasons) console.log(c.dim(`  • ${r}`));
    console.log("");
  }
  fs.writeFileSync(target, JSON.stringify(template, null, 2) + "\n");
  console.log(c.green(`✔ Wrote ${path.relative(process.cwd(), target)}`));
  console.log(c.dim("  Next: `diffgate check` to review your diff, or `diffgate install-hook` for a pre-commit gate."));
}

function cmdInstallHook(pos: string[], flags: Record<string, string | true>): void {
  const cwd = path.resolve(pos[0] || ".");
  if (!isGitRepo(cwd)) fail("Not a git repository — cannot install a pre-commit hook.");
  const root = repoRoot(cwd) || cwd;
  const hookDir = path.join(root, ".git", "hooks");
  const hookPath = path.join(hookDir, "pre-commit");
  if (fs.existsSync(hookPath) && !flags["force"]) {
    fail(`${hookPath} already exists. Use --force to overwrite.`);
  }
  const script = `#!/bin/sh
# Installed by diffgate — blocks commits with high-impact findings.
if command -v diffgate >/dev/null 2>&1; then
  diffgate check --staged
else
  node "${CLI_PATH}" check --staged
fi
`;
  fs.mkdirSync(hookDir, { recursive: true });
  fs.writeFileSync(hookPath, script, { mode: 0o755 });
  console.log(c.green(`✔ Installed pre-commit hook at ${path.relative(cwd, hookPath)}`));
  console.log(c.dim("  It runs `diffgate check --staged` before every commit. Bypass with `git commit --no-verify`."));
}

function help(): void {
  console.log(`${c.bold("🛡  DiffGate")} ${c.dim("v" + VERSION)} — diff-aware, three-tiered code review

${c.bold("Usage")}
  diffgate <command> [path] [options]

${c.bold("Commands")}
  ${c.blue("check")}        Review pending git changes; gate commits/CI    ${c.dim("(default)")}
  ${c.blue("scan")}         Analyze a file or directory in full
  ${c.blue("watch")}        Live review as you edit
  ${c.blue("report")}       Review metrics (tiers, hotspots, learnings) · --compliance for SOC 2
  ${c.blue("bench")}        Run the noise benchmark (precision/recall/FP-per-clean-change)
  ${c.blue("explain")}      AI-explain findings for a file (needs API key)
  ${c.blue("guidelines")}   Review diff against AGENTS.md/CLAUDE.md/.cursorrules etc.
  ${c.blue("feedback")}     <ruleId> <file> <line> — dismiss as noise / --confirm (learns)
  ${c.blue("stats")}        Signal-vs-noise report (realized verdicts + predicted diff)
  ${c.blue("graph")}        Code-graph status / index (cross-file blast radius)
  ${c.blue("init")}         Write a tailored .diffgate.json (auto-detects test cmd/langs)
  ${c.blue("install-hook")} Install a git pre-commit gate
  ${c.blue("mcp")}          Start the MCP stdio server (for coding agents)

${c.bold("Options")}
  --staged           Review staged changes only (good for pre-commit)
  --working          Review all uncommitted changes (default)
  --base=<ref>       Review the whole branch/PR against a base ref (for CI, e.g. origin/main)
  --fail-on=<tier>   green|yellow|orange — exit 1 at/above this tier (default orange)
  --no-gate          Skip running the configured testCommand
  --no-fail          Always exit 0 (report only)
  --ai               Add Claude explanations for orange findings
  --json             Machine-readable output
  --sarif            SARIF 2.1.0 output (GitHub code scanning)
  --github           GitHub Actions inline PR annotations
  --pr[=<n>]         Post a PR review + commit status (needs GITHUB_TOKEN); --pr-dry-run to preview
  --agent            Compact JSON verdict for coding agents (pass/blocked)

${c.bold("Examples")}
  diffgate check --staged
  diffgate scan src/ --fail-on=yellow
  diffgate check --pr             ${c.dim("# in CI: post review to the PR")}
  diffgate report --compliance    ${c.dim("# SOC 2 control evidence")}
  diffgate bench                  ${c.dim("# noise benchmark")}
`);
}

async function main(): Promise<void> {
  const [, , maybeCmd, ...rest] = process.argv;
  const known = ["check", "scan", "watch", "report", "bench", "explain", "guidelines", "feedback", "stats", "graph", "init", "install-hook", "mcp"];
  let cmd = maybeCmd;
  let argv = rest;
  if (!cmd || cmd.startsWith("-")) {
    if (cmd === "--version" || cmd === "-v") { console.log(VERSION); return; }
    if (cmd === "--help" || cmd === "-h" || !cmd) { help(); return; }
    cmd = "check";
    argv = process.argv.slice(2);
  } else if (!known.includes(cmd)) {
    cmd = "check";
    argv = process.argv.slice(2);
  }
  const { pos, flags } = parseArgs(argv);
  if (flags["help"] || flags["h"]) { help(); return; }

  try {
    switch (cmd) {
      case "check": return await cmdCheck(pos, flags);
      case "scan": return await cmdScan(pos, flags);
      case "watch": return cmdWatch(pos, flags);
      case "report": return await cmdReport(pos, flags);
      case "bench": return cmdBench(pos, flags);
      case "explain": return await cmdExplain(pos, flags);
      case "guidelines": return await cmdGuidelines(pos, flags);
      case "feedback": return cmdFeedback(pos, flags);
      case "stats": return cmdStats(pos, flags);
      case "graph": return cmdGraph(pos, flags);
      case "init": return cmdInit(pos, flags);
      case "install-hook": return cmdInstallHook(pos, flags);
      case "mcp": return runMcpServer();
      default: return help();
    }
  } catch (e) {
    fail((e as Error).message);
  }
}

main();
