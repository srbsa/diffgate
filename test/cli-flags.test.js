import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(__dirname, "..", "dist", "cli.js");

function runGit(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
}

function makeRepo() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grg-cli-flags-"));
  runGit(tmp, "init", "-q");
  runGit(tmp, "config", "user.email", "t@t.dev");
  runGit(tmp, "config", "user.name", "Test");
  fs.writeFileSync(path.join(tmp, "math.js"), `function add(a, b) {\n  return a + b;\n}\n`);
  runGit(tmp, "add", "-A");
  runGit(tmp, "commit", "-q", "-m", "A: base");
  fs.writeFileSync(path.join(tmp, "math.js"), `function add(a, b) {\n  return a + b;\n}\n// note\n`);
  runGit(tmp, "add", "-A");
  runGit(tmp, "commit", "-q", "-m", "B: tweak");
  return tmp;
}

function runCheck(cwd, args) {
  try {
    const out = execFileSync("node", [CLI, "check", ...args], { cwd, encoding: "utf-8" });
    return { status: 0, stdout: out };
  } catch (e) {
    return { status: e.status, stdout: e.stdout, stderr: e.stderr };
  }
}

test("check --since=<rev> (equals form) enters history mode", () => {
  const tmp = makeRepo();
  try {
    const { stdout } = runCheck(tmp, ["--since=HEAD~1", "--json"]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.scanned, 1, "should scan exactly commit B");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --since <rev> (space form) also enters history mode", () => {
  const tmp = makeRepo();
  try {
    const { stdout } = runCheck(tmp, ["--since", "HEAD~1", "--json"]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.scanned, 1, "space-separated --since must behave like --since=");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --range <A..B> (space form) does not misfire the not-a-git-repo warning", () => {
  const tmp = makeRepo();
  try {
    const head = runGit(tmp, "rev-parse", "HEAD").trim();
    const root = runGit(tmp, "rev-list", "--max-parents=0", "HEAD").trim();
    const { stdout, stderr } = runCheck(tmp, ["--range", `${root}..${head}`, "--json"]);
    assert.ok(!/Not a git repository/.test(stdout + (stderr || "")), "must not misreport as non-git repo");
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.scanned, 1, "range should cover exactly commit B");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --limit <n> (space form) caps commits like --limit=<n>", () => {
  const tmp = makeRepo();
  try {
    const { stdout } = runCheck(tmp, ["--since", "HEAD~1", "--limit", "1", "--json"]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.scanned, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// --- silent-failure sweep: the gate must never exit 0 when it didn't (or shouldn't) pass ------

test("check in a non-git dir exits 2 (not a silent pass) and keeps stdout JSON-free", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grg-nongit-"));
  try {
    const { status, stdout, stderr } = runCheck(tmp, ["--json"]);
    assert.equal(status, 2, "must not exit 0 when the gate cannot run");
    assert.ok(/Not a git repository/.test(stderr || ""), "reason on stderr");
    assert.ok(!/Not a git repository/.test(stdout || ""), "stdout stays clean for parsers");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --base with an unresolvable ref exits 2 instead of diffing nothing", () => {
  const tmp = makeRepo();
  try {
    const { status, stderr } = runCheck(tmp, ["--base", "origin/does-not-exist", "--json"]);
    assert.equal(status, 2);
    assert.ok(/--base ref not found/.test(stderr || ""));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --range with a typo'd range exits 2 instead of scanning 0 commits", () => {
  const tmp = makeRepo();
  try {
    const { status, stderr } = runCheck(tmp, ["--range", "nope..alsonope"]);
    assert.equal(status, 2);
    assert.ok(/--range does not resolve/.test(stderr || ""));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --fail-on with an invalid tier exits 2 instead of silently gating at orange", () => {
  const tmp = makeRepo();
  try {
    const { status, stderr } = runCheck(tmp, ["--fail-on", "oragne"]);
    assert.equal(status, 2);
    assert.ok(/--fail-on expects/.test(stderr || ""));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --json exits 1 on a blocking finding (no false pass in machine-readable mode)", () => {
  const tmp = makeRepo();
  try {
    fs.writeFileSync(path.join(tmp, "config.js"), `const key = "sk_live_abcdef0123456789abcd";\n`);
    const { status, stdout } = runCheck(tmp, ["--json"]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.blocking, true, "the secret must be found and blocking");
    assert.equal(status, 1, "--json must carry the gate exit code");
    // --no-fail is still the report-only escape hatch.
    const soft = runCheck(tmp, ["--json", "--no-fail"]);
    assert.equal(soft.status, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("check --json exits 0 on a clean diff", () => {
  const tmp = makeRepo();
  try {
    const { status, stdout } = runCheck(tmp, ["--json"]);
    JSON.parse(stdout);
    assert.equal(status, 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("history --json honors --fail-on with an exit code", () => {
  const tmp = makeRepo();
  try {
    fs.writeFileSync(path.join(tmp, "config.js"), `const key = "sk_live_abcdef0123456789abcd";\n`);
    runGit(tmp, "add", "-A");
    runGit(tmp, "commit", "-q", "-m", "C: add secret");
    const { status, stdout } = runCheck(tmp, ["--since", "HEAD~1", "--json", "--fail-on", "orange"]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.scanned, 1);
    assert.equal(status, 1, "--fail-on must apply to --json history output too");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
