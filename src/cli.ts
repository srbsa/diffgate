import fs from "fs";
import path from "path";
import { execSync } from "child_process";
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
  complete,
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
  mergeLearningStores,
  readStoreFile,
  applyLearnings,
  predictedSignal,
  realizedSignal,
  graphStatus,
  resolveGraphConfig,
  makeCodeGraphProvider,
  IMPACT_RULES,
  shouldShowGraphTip,
  recordGraphTipShown,
  recordTurn,
  hasAstSupport,
} from "./core/index.js";
import { c, formatReport, formatFile, badge, summaryLine } from "./report.js";
import { runMcpServer } from "./mcp.js";
import { buildPrReview, resolveGithubContext, postPrReview } from "./github.js";
import { runBench, CORPUS } from "./bench.js";
import { runMarginalSampled, modelRunner, scenariosForMode, SCENARIOS, type SampledResult, type Mode } from "./marginal.js";
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

const AGENT_MODES = ["advisory", "gated", "off"] as const;

/** Resolve `--agent-mode=<mode>`, warning on the two footguns: the space form (`--agent-mode gated`,
 *  which the `key=value` parser drops) and an unknown value. Returns undefined → use configured mode. */
function resolveAgentMode(flags: Record<string, string | true>): (typeof AGENT_MODES)[number] | undefined {
  const raw = flags["agent-mode"];
  if (raw === undefined) return undefined;
  if (raw === true) {
    console.error(c.yellow("⚠ --agent-mode needs a value: use --agent-mode=advisory|gated|off (the space form is ignored). Falling back to configured mode."));
    return undefined;
  }
  if (!(AGENT_MODES as readonly string[]).includes(raw)) {
    console.error(c.yellow(`⚠ Unknown --agent-mode=${raw}; expected advisory|gated|off. Falling back to configured mode.`));
    return undefined;
  }
  return raw as (typeof AGENT_MODES)[number];
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
    const modeOverride = resolveAgentMode(flags);
    const agentCfg = { ...config.gate.agent, ...(modeOverride ? { mode: modeOverride } : {}) };
    // Budget enforcement is opt-in (a session id) so CI/one-shot runs stay deterministic. With a
    // session, findings that outlast escalateAfterTurns are promoted to a human-review escalation.
    const sessionId = typeof flags["session"] === "string" ? (flags["session"] as string) : process.env.DIFFGATE_AGENT_SESSION || undefined;
    let overBudget: Set<string> | undefined;
    if (sessionId && agentCfg.mode !== "off") {
      const root = repoRoot(cwd) || cwd;
      const entries = review.files.flatMap((fr) => fr.findings.map((f) => ({ file: fr.filePath, finding: f })));
      overBudget = recordTurn(root, sessionId, entries, { escalateAfterTurns: agentCfg.escalateAfterTurns ?? 2 }).overBudget;
    }
    const v = agentVerdict(review.files, agentCfg, overBudget ? { overBudget } : {});
    console.log(JSON.stringify(v, null, 2));
    process.exit(v.verdict === "blocked" && !flags["no-fail"] ? 1 : 0);
  }

  if (flags["pr"] || flags["pr-dry-run"]) {
    await runPrReview(review.files, cwd, config, flags);
    return;
  }

  console.log(formatReport(review.files, review, cwd));
  console.log(c.dim(`\n  diff mode: ${mode}`));
  maybeGraphTip(review.files, config, cwd);

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

async function cmdMarginal(pos: string[], flags: Record<string, string | true>): Promise<void> {
  const cwd = pos[0] ? path.resolve(pos[0]) : process.cwd();
  const { config: base } = loadConfig(cwd);

  // Build the agent's model config: start from any .diffgate.json `ai` block, override with flags.
  // Defaults target a local LM Studio endpoint — most privacy-conscious users run a local model.
  const provider = (flags["provider"] as string) || base.ai?.provider || "lmstudio";
  const baseURL = (flags["base-url"] as string) || base.ai?.baseURL || process.env["DIFFGATE_MARGINAL_BASE_URL"] || undefined;
  const model = (flags["model"] as string) || (typeof base.ai?.model === "string" ? base.ai.model : undefined) || process.env["DIFFGATE_MARGINAL_MODEL"];
  // Reasoning models (e.g. Qwen on LM Studio) need headroom: a small budget gets consumed by the
  // <think> block, leaving no code. Default generously; override with --max-tokens.
  const maxTokens = flags["max-tokens"] ? parseInt(flags["max-tokens"] as string, 10) : base.ai?.maxTokens || 4096;
  // Sampling for confidence: --samples=K runs each scenario K times; --temperature controls variance.
  // K>1 at temperature 0 is pointless (every sample identical) — default to 0.7 when sampling.
  const samples = flags["samples"] ? Math.max(1, parseInt(flags["samples"] as string, 10)) : 1;
  const temperature =
    flags["temperature"] !== undefined ? parseFloat(flags["temperature"] as string)
    : base.ai?.temperature ?? (samples > 1 ? 0.7 : 0);
  // Which mode(s): greenfield (whole-file generation), edit (edit a seed, analyze changed lines), or both.
  const modeFlag = ((flags["mode"] as string) || "greenfield").toLowerCase();
  const modes: Mode[] = modeFlag === "both" ? ["greenfield", "edit"] : modeFlag === "edit" ? ["edit"] : ["greenfield"];
  // OpenAI's gpt-5.x / o-series reject `max_tokens` — they require `max_completion_tokens`. Pick the
  // right param from the model id unless the user pins one with --token-param.
  const tokenParam =
    (flags["token-param"] as string) || base.ai?.tokenParam ||
    (model && /^(gpt-5|o[1-9])/.test(model) ? "max_completion_tokens" : undefined);
  // If --provider is explicit, start from a clean ai block: inheriting .diffgate.json's apiKeyEnv /
  // model / wire would bind the new provider to the wrong key (e.g. an Anthropic key env for OpenAI).
  const inherited = flags["provider"] ? {} : base.ai;
  const config = { ...base, ai: { ...inherited, enabled: true, provider, maxTokens, temperature, ...(tokenParam ? { tokenParam } : {}), ...(baseURL ? { baseURL } : {}), ...(model ? { model } : {}) } } as Config;

  if (!model) {
    fail("No model set. Pass --model=<id> (e.g. --model=qwen/qwen3.5-9b) or set ai.model in .diffgate.json.");
    return;
  }

  const scenarios = flags["limit"] ? SCENARIOS.slice(0, parseInt(flags["limit"] as string, 10)) : SCENARIOS;
  const completeFn = async (args: { system: string; prompt: string; config: Partial<Config>; noThink?: boolean }) =>
    complete({ system: args.system, prompt: args.prompt, config: args.config, noThink: args.noThink });
  const runner = modelRunner(completeFn, config);
  const analyzeFn = (a: { filePath: string; content: string; previousContent?: string | null; changedLines?: Set<number> | null; config: Config }) => analyze(a);
  const outDir = flags["out"] as string | undefined;
  const scen = new Map(SCENARIOS.map((s) => [s.id, s]));

  const results: SampledResult[] = [];
  for (const mode of modes) {
    const n = scenariosForMode(scenarios, mode).length;
    if (!flags["json"]) {
      process.stderr.write(c.dim(
        `Asking ${c.bold(describeProvider(config))} · ${model} for ${n} ${mode} tasks × ${samples} sample(s) @ temp ${temperature}…\n`));
    }
    const result = await runMarginalSampled(scenarios, runner, analyzeFn, {
      mode, samples, capture: !!outDir,
      onSample: (i) => { if (!flags["json"] && samples > 1) process.stderr.write(c.dim(`  ${mode} sample ${i + 1}/${samples} done\n`)); },
    });
    if (outDir) {
      result.runs.forEach((run, i) => {
        const dir = path.join(outDir, mode, `sample-${i + 1}`);
        fs.mkdirSync(dir, { recursive: true });
        for (const r of run.byScenario) {
          if (r.code != null) fs.writeFileSync(path.join(dir, scen.get(r.id)?.filename || `${r.id}.txt`), r.code);
          if (r.raw != null) fs.writeFileSync(path.join(dir, `${r.id}.raw.md`), r.raw);
        }
      });
      process.stderr.write(c.dim(`Wrote generated code (${mode}, ${samples} sample(s)) to ${path.join(outDir, mode)}\n`));
    }
    results.push(result);
  }

  if (flags["json"]) {
    // Keep captured code out of the machine-readable JSON; the files are the artifact.
    const json = results.map((r) => ({ ...r, runs: r.runs.map((run) => ({ ...run, byScenario: run.byScenario.map(({ code: _c, raw: _r, ...rest }) => rest) })) }));
    console.log(JSON.stringify(json.length === 1 ? json[0] : json, null, 2));
    return;
  }
  for (const result of results) renderMarginal(result, model);
}

function renderMarginal(result: SampledResult, model: string): void {
  const pct = (x: number) => `${(x * 100).toFixed(0)}%`;
  console.log(c.bold("🛡  DiffGate — marginal-catch experiment") +
    c.dim(`  ${result.scenarios} ${result.mode} tasks × ${result.samples} sample(s) · agent: ${model}\n`));
  for (const a of result.byScenario) {
    const freq = a.samples - a.errors > 0 ? `${a.defect}/${a.samples - a.errors}` : "—";
    const tag =
      a.defect > 0 ? c.orange("DEFECT  ") :
      a.advisory > 0 ? c.yellow("advisory") :
      a.errors === a.samples ? c.yellow("err     ") :
      c.green("clean   ");
    const gap = a.knownGap ? c.dim(" [gap]") : "";
    const detail = a.knownGap
      ? c.dim(`clean=${a.clean}/${a.samples - a.errors} — DiffGate has no rule; inspect code`)
      : c.dim(`defect ${freq}` + (a.advisory ? `, advisory ${a.advisory}` : ""));
    console.log(`  ${tag}  ${a.id.padEnd(24)}${gap} ${detail}`);
  }
  const rate = result.defectRate;
  const headline = `${pct(rate)} marginal defect-catch rate`;
  const colored = rate >= 0.5 ? c.orange(headline) : rate > 0 ? c.yellow(headline) : c.green(headline);
  console.log(c.bold("\n  " + colored) +
    c.dim(`  95% CI [${pct(result.ci.low)}, ${pct(result.ci.high)}]  (${result.defectCatches}/${result.trials} non-gap trials shipped unsafe code DiffGate caught)`));
  console.log(c.dim(`  + ${pct(result.advisoryRate)} advisory rate (auth-crypto / destructive-migration / shell-out) — fire on correct code too, reported separately.`));
  if (result.gapClean) console.log(c.dim(`  ${result.gapClean} known-gap sample(s) scored clean — DiffGate has no rule; inspect captured code to tell model-safe from a miss.`));
  if (result.errors) console.log(c.dim(`  ${result.errors} sample(s) errored (model unreachable / empty output).`));
  console.log(c.dim("\n  Reads as: how often the agent SHIPS unsafe code DiffGate would catch, with no security hint."));
  console.log(c.dim("  High ⇒ before-the-diff catches real diffs you'd otherwise see. Low ⇒ the model already avoids these.\n"));
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

// One-line, non-nagging nudge for CodeGraph, fading out after a few shows. Two triggers, because
// the value is highest in two cases the deterministic core can't fully serve:
//   1. a public-surface finding (JS/TS) that cross-file blast radius would enrich, or
//   2. findings in a NON-AST language (Python/Go/Java/…), which only get pattern-rule precision
//      in-file — exactly the users CodeGraph helps most (cross-file caller/taint across 38+ langs).
// Only fires when graphing is enabled and there is no index yet.
function maybeGraphTip(files: AnalyzeResult[], config: Config, cwd: string): void {
  const status = graphStatus(config);
  if (!status.enabled || status.indexed) return;
  const root = repoRoot(cwd) || cwd;
  if (!shouldShowGraphTip(root)) return;

  const findings = files.flatMap((f) => f.findings);
  const hasImpactFinding = findings.some((f) => IMPACT_RULES.has(f.ruleId));
  const nonAstLangs = [...new Set(files.filter((f) => f.findings.length > 0 && !hasAstSupport(f.language)).map((f) => f.language))];
  if (!hasImpactFinding && nonAstLangs.length === 0) return;

  const how = status.commandFound ? "`diffgate graph index`" : "install CodeGraph, then `diffgate graph index`";
  if (!hasImpactFinding && nonAstLangs.length > 0) {
    const label = nonAstLangs.length === 1 ? cap(nonAstLangs[0]) : "This codebase";
    console.log(c.dim(`\n  💡 Optional: ${label} gets pattern-rule precision in-file. CodeGraph adds cross-file caller & taint analysis (38+ languages) — ${how}.`));
  } else {
    console.log(c.dim(`\n  💡 Optional: cross-file blast radius is off — ${how} to route reviewers by caller count.`));
  }
  recordGraphTipShown(root);
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
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
  "//testScope": "Down-tier non-exempt orange findings in test/fixture files (orange → yellow, non-blocking) so test scaffolding doesn't block the gate. Secrets & destructive schema stay blocking. Set false to gate test code like prod.",
  testScope: true,
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

  // --demo: skip config write, run a scan of the bundled mock_project so new users
  // see what DiffGate output looks like before they have any uncommitted changes.
  if (flags["demo"]) {
    const mockDir = path.resolve(path.dirname(CLI_PATH), "..", "mock_project");
    if (!fs.existsSync(mockDir)) {
      console.log(c.yellow("mock_project not found — run `diffgate scan <path>` against your own files."));
      return;
    }
    const { config } = loadConfig(cwd);
    const filePaths = [...walkFiles(mockDir, config, mockDir)];
    const files: AnalyzeResult[] = [];
    for (const fp of filePaths) {
      let content: string;
      try { content = fs.readFileSync(fp, "utf-8"); } catch { continue; }
      const res = analyze({ filePath: fp, content, config });
      if (res.findings.length > 0) files.push(res);
    }
    const allFindings = files.flatMap((f) => f.findings);
    const review = { files, counts: tierCounts(allFindings), tier: overallTier(allFindings), blocking: allFindings.some((f) => f.blocking) };
    console.log(c.bold("\n🛡  DiffGate — demo scan of bundled mock_project\n"));
    console.log(c.dim("  This is what DiffGate looks like on real code. Run `diffgate check` on your own diff.\n"));
    console.log(formatReport(files, review, mockDir));
    console.log(c.dim("\n  Next: `diffgate init` to write a config, or `diffgate check` to review your pending changes."));
    return;
  }

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
  console.log(c.dim("  Next: `diffgate check` to review your diff, `diffgate init --demo` to see example output, or `diffgate install-hook` for a pre-commit gate."));
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

  // Wire the learnings.json merge driver so parallel dismissals on different branches
  // auto-merge without conflicts. The driver calls `diffgate merge-driver` on PATH (with a
  // node fallback), so there is no fragile node_modules path to resolve.
  try {
    const attrPath = path.join(root, ".gitattributes");
    const attrLine = ".diffgate/learnings.json merge=diffgate-learnings";
    const existing = fs.existsSync(attrPath) ? fs.readFileSync(attrPath, "utf-8") : "";
    if (!existing.includes(attrLine)) {
      fs.appendFileSync(attrPath, (existing.endsWith("\n") || existing === "" ? "" : "\n") + attrLine + "\n");
      console.log(c.green(`✔ Added merge driver attribute to ${path.relative(cwd, attrPath)}`));
    }
    // Register the driver in .git/config (local, not global — no side effects outside this repo).
    // %A = ours (written back), %B = theirs. Base (%O) is not needed for a set-union merge.
    const driverCmd = `sh -c 'if command -v diffgate >/dev/null 2>&1; then diffgate merge-driver "$1" "$2"; else node "${CLI_PATH}" merge-driver "$1" "$2"; fi' --`;
    execSync(`git config merge.diffgate-learnings.name "DiffGate learnings merge driver"`, { cwd: root, stdio: "ignore" });
    execSync(`git config 'merge.diffgate-learnings.driver' '${driverCmd} %A %B'`, { cwd: root, stdio: "ignore" });
    console.log(c.green(`✔ Registered learnings.json merge driver (auto-merges parallel verdicts)`));
  } catch {
    console.log(c.dim("  Tip: set up the merge driver manually — see README › Team adoption › Step 3."));
  }
}

/** Git merge driver for .diffgate/learnings.json. Args: <ours> <theirs>. Writes the union to <ours>. */
function cmdMergeDriver(pos: string[]): void {
  const [ours, theirs] = pos;
  if (!ours || !theirs) fail("merge-driver expects: diffgate merge-driver <ours> <theirs>");
  const merged = mergeLearningStores(readStoreFile(ours), readStoreFile(theirs));
  fs.writeFileSync(ours, JSON.stringify(merged, null, 2) + "\n");
  // exit 0 → conflict resolved
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
  ${c.blue("marginal")}     Marginal-catch experiment: how often an agent ships code DiffGate would catch
               --mode=greenfield|edit|both  --samples=K  --temperature=T  --model=  --provider=  --out=
  ${c.blue("explain")}      AI-explain findings for a file (needs API key)
  ${c.blue("guidelines")}   Review diff against AGENTS.md/CLAUDE.md/.cursorrules etc.
  ${c.blue("feedback")}     <ruleId> <file> <line> — dismiss as noise / --confirm (learns)
  ${c.blue("stats")}        Signal-vs-noise report (realized verdicts + predicted diff)
  ${c.blue("graph")}        Code-graph status / index (cross-file blast radius)
  ${c.blue("init")}         Write a tailored .diffgate.json (auto-detects test cmd/langs) · --demo to preview output
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
  --agent            Compact JSON verdict for coding agents (pass/review/blocked)
  --agent-mode=<m>   advisory|gated|off — override gate.agent.mode (note: the = is required)
  --session=<id>     Track findings across calls in this id; escalate ones that outlast the budget

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
  const known = ["check", "scan", "watch", "report", "bench", "marginal", "explain", "guidelines", "feedback", "stats", "graph", "init", "install-hook", "merge-driver", "mcp"];
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
      case "marginal": return await cmdMarginal(pos, flags);
      case "explain": return await cmdExplain(pos, flags);
      case "guidelines": return await cmdGuidelines(pos, flags);
      case "feedback": return cmdFeedback(pos, flags);
      case "stats": return cmdStats(pos, flags);
      case "graph": return cmdGraph(pos, flags);
      case "init": return cmdInit(pos, flags);
      case "install-hook": return cmdInstallHook(pos, flags);
      case "merge-driver": return cmdMergeDriver(pos);
      case "mcp": return runMcpServer();
      default: return help();
    }
  } catch (e) {
    fail((e as Error).message);
  }
}

main();
