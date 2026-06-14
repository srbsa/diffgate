import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import chokidar from "chokidar";

import {
  analyze,
  loadConfig,
  isIgnored,
  getChangedLinesForFile,
  getPreviousContent,
  isGitRepo,
  repoRoot,
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
} from "./core/index.js";
import { c, formatReport, formatFile, badge, summaryLine } from "./report.js";
import { runMcpServer } from "./mcp.js";
import type { Finding, AnalyzeResult, Config } from "./core/types.js";

const CLI_PATH = fileURLToPath(import.meta.url);
const VERSION = "0.1.1";

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
    console.log(c.dim(`\n  (AI explanations off — set ai.enabled in .guardrails.json and export $${aiKeyEnv(config)} to enable.)`));
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
    console.log(c.yellow("⚠ Not a git repository.") + ` ${c.dim("`guardrail check` reviews your diff. Use `guardrail scan` to analyze files directly.")}`);
    process.exit(0);
  }
  const { config } = loadConfig(cwd);
  const mode = resolveMode(flags, config);
  const review = reviewChanges(cwd, { mode });
  const allFindings = review.files.flatMap((f) => f.findings);

  if (flags["json"]) {
    console.log(JSON.stringify({ mode, ...stripForJson(review) }, null, 2));
    return;
  }

  console.log(formatReport(review.files, review, cwd));
  console.log(c.dim(`\n  diff mode: ${mode}`));

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

  const files: AnalyzeResult[] = [];
  for (const fp of filePaths) {
    let content: string;
    try {
      content = fs.readFileSync(fp, "utf-8");
    } catch {
      continue;
    }
    const res = analyze({ filePath: fp, content, config });
    if (res.findings.length > 0) files.push(res);
  }

  const allFindings = files.flatMap((f) => f.findings);
  const review = { files, counts: tierCounts(allFindings), tier: overallTier(allFindings), blocking: allFindings.some((f) => f.blocking) };

  if (flags["json"]) {
    console.log(JSON.stringify(stripForJson({ ...review, config }), null, 2));
    return;
  }
  const reviewCwd = stat!.isDirectory() ? target : baseDir;
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

  console.log(c.bold("🛡  Guardrail — live review") + c.dim(`  watching ${cwd}`));
  console.log(c.dim(
    `  ${cfgPath ? "config: " + path.relative(cwd, cfgPath) : "no .guardrails.json (defaults)"} · ` +
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
  if (!pos[0] || !fs.existsSync(target)) fail("Usage: guardrail explain <file>");
  const { config } = loadConfig(path.dirname(target));
  if (!isAiAvailable(config)) {
    fail(`AI is not configured. Set "ai": { "enabled": true } in .guardrails.json and export $${aiKeyEnv(config)}.`);
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

const INIT_TEMPLATE = {
  testCommand: null,
  gate: { mode: "working", failOn: "orange" },
  ai: { enabled: false, model: "claude-sonnet-4-6", apiKeyEnv: "ANTHROPIC_API_KEY" },
  deprecated: [{ pattern: "OldService.legacyMethod", replacedBy: "NewService.method", author: "Your Team", pr: "PR #000" }],
  customPatterns: [{ id: "no-direct-process-env", tier: "yellow", pattern: "process\\.env\\.", message: "Read config through the typed config module, not process.env directly." }],
  rules: {},
  ignore: ["**/node_modules/**", "**/dist/**", "**/build/**"],
};

function cmdInit(pos: string[], flags: Record<string, string | true>): void {
  const cwd = path.resolve(pos[0] || ".");
  const target = path.join(cwd, ".guardrails.json");
  if (fs.existsSync(target) && !flags["force"]) {
    fail(`.guardrails.json already exists. Use --force to overwrite.`);
  }
  fs.writeFileSync(target, JSON.stringify(INIT_TEMPLATE, null, 2) + "\n");
  console.log(c.green(`✔ Wrote ${path.relative(process.cwd(), target)}`));
  console.log(c.dim("  Edit it to add deprecated APIs, custom rules, and your testCommand."));
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
# Installed by guardrail-review-engine — blocks commits with high-impact findings.
if command -v guardrail >/dev/null 2>&1; then
  guardrail check --staged
else
  node "${CLI_PATH}" check --staged
fi
`;
  fs.mkdirSync(hookDir, { recursive: true });
  fs.writeFileSync(hookPath, script, { mode: 0o755 });
  console.log(c.green(`✔ Installed pre-commit hook at ${path.relative(cwd, hookPath)}`));
  console.log(c.dim("  It runs `guardrail check --staged` before every commit. Bypass with `git commit --no-verify`."));
}

function help(): void {
  console.log(`${c.bold("🛡  guardrail")} ${c.dim("v" + VERSION)} — diff-aware, three-tiered code review

${c.bold("Usage")}
  guardrail <command> [path] [options]

${c.bold("Commands")}
  ${c.blue("check")}        Review pending git changes; gate commits/CI    ${c.dim("(default)")}
  ${c.blue("scan")}         Analyze a file or directory in full
  ${c.blue("watch")}        Live review as you edit
  ${c.blue("explain")}      AI-explain findings for a file (needs API key)
  ${c.blue("init")}         Write a starter .guardrails.json
  ${c.blue("install-hook")} Install a git pre-commit gate
  ${c.blue("mcp")}          Start the MCP stdio server (for coding agents)

${c.bold("Options")}
  --staged           Review staged changes only (good for pre-commit)
  --working          Review all uncommitted changes (default)
  --fail-on=<tier>   green|yellow|orange — exit 1 at/above this tier (default orange)
  --no-gate          Skip running the configured testCommand
  --no-fail          Always exit 0 (report only)
  --ai               Add Claude explanations for orange findings
  --json             Machine-readable output

${c.bold("Examples")}
  guardrail check --staged
  guardrail scan src/ --fail-on=yellow
  guardrail watch
`);
}

async function main(): Promise<void> {
  const [, , maybeCmd, ...rest] = process.argv;
  const known = ["check", "scan", "watch", "explain", "init", "install-hook", "mcp"];
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
      case "explain": return await cmdExplain(pos, flags);
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
