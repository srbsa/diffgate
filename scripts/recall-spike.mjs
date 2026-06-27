// Recall-spike measurement harness (docs/DESIGN-recall-and-parity.md).
// Computes the three go/no-go numbers for borrowing Semgrep recall and running it through the gate:
//   1. recall gain    — net-new findings Semgrep surfaces that DiffGate misses (after diff-scope + dedupe)
//   2. false-block     — borrowed findings that would block the gate (must be 0 by construction)
//   3. latency         — per-file Semgrep cost vs DiffGate
// Usage: SEMGREP_BIN=/path/to/semgrep node scripts/recall-spike.mjs <corpusDir>
//   corpusDir contains vuln/ and clean/ subdirs of source files.
import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import {
  analyze, initTreeSitter, parseSemgrep, diffScope, dedupeAgainst, toFindings,
} from "../dist/core/index.js";

const SEMGREP = process.env.SEMGREP_BIN || "semgrep";
const CONFIG = process.env.SEMGREP_CONFIG || "p/python";
const corpusDir = process.argv[2];
if (!corpusDir) { console.error("usage: node scripts/recall-spike.mjs <corpusDir>"); process.exit(2); }

await initTreeSitter();

function listFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith(".py")).map((f) => path.join(dir, f));
}

function runSemgrep(file) {
  const t0 = performance.now();
  let out = null;
  try {
    out = execFileSync(SEMGREP, ["scan", "--json", "--quiet", "--no-git-ignore", "--config", CONFIG, file],
      { encoding: "utf-8", timeout: 60000, maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
  } catch (e) { out = e.stdout || null; }
  return { ms: performance.now() - t0, raw: parseSemgrep(out) };
}

function diffgate(file) {
  const t0 = performance.now();
  const r = analyze({ filePath: file, content: fs.readFileSync(file, "utf-8") });
  return { ms: performance.now() - t0, findings: r.findings };
}

function report(label, files) {
  let dgTotal = 0, sgRaw = 0, borrowed = 0, blockBorrowed = 0, dgMs = 0, sgMs = 0, sgOk = 0;
  const rows = [];
  for (const file of files) {
    const dg = diffgate(file);
    const sg = runSemgrep(file);
    dgMs += dg.ms; sgMs += sg.ms;
    const native = dg.findings;
    dgTotal += native.length;
    if (sg.raw === null) { rows.push(`  ${path.basename(file).padEnd(16)} dg=${native.length}  semgrep=(unavailable)`); continue; }
    sgOk++;
    const newBorrowed = toFindings(dedupeAgainst(diffScope(sg.raw, null), native));
    sgRaw += sg.raw.length; borrowed += newBorrowed.length;
    blockBorrowed += newBorrowed.filter((f) => f.blocking).length;
    rows.push(`  ${path.basename(file).padEnd(16)} dg=${String(native.length).padEnd(2)} semgrepRaw=${String(sg.raw.length).padEnd(2)} net-new(deduped)=${newBorrowed.length}  [${newBorrowed.map((f) => f.ruleId.replace("semgrep:", "")).join(", ")}]`);
  }
  console.log(`\n## ${label} (${files.length} files, semgrep answered ${sgOk})`);
  rows.forEach((r) => console.log(r));
  return { dgTotal, sgRaw, borrowed, blockBorrowed, dgMs, sgMs, n: files.length, sgOk };
}

console.log(`semgrep=${SEMGREP}  config=${CONFIG}`);
let ver = "?";
try { ver = execFileSync(SEMGREP, ["--version"], { encoding: "utf-8" }).trim(); } catch { ver = "NOT AVAILABLE"; }
console.log(`semgrep version: ${ver}`);

const vuln = report("VULN corpus (recall gain)", listFiles(path.join(corpusDir, "vuln")));
const clean = report("CLEAN corpus (noise / false-block)", listFiles(path.join(corpusDir, "clean")));

console.log("\n===== GO / NO-GO =====");
console.log(`1. recall gain        : ${vuln.borrowed} net-new findings on vuln files DiffGate missed (semgrep raw ${vuln.sgRaw}, dg native ${vuln.dgTotal})`);
console.log(`2. false-block        : ${vuln.blockBorrowed + clean.blockBorrowed} borrowed findings would block the gate (MUST be 0)`);
console.log(`   clean-corpus noise : ${clean.borrowed} borrowed findings on KNOWN-CLEAN code (advisory; lower is better)`);
const fmt = (s) => `${(s.sgMs / Math.max(1, s.n)).toFixed(0)}ms semgrep vs ${(s.dgMs / Math.max(1, s.n)).toFixed(1)}ms diffgate /file`;
console.log(`3. latency            : ${fmt({ sgMs: vuln.sgMs + clean.sgMs, dgMs: vuln.dgMs + clean.dgMs, n: vuln.n + clean.n })}`);
