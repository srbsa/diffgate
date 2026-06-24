import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";

import { analyze, DEFAULT_CONFIG } from "../dist/core/index.js";
import { isIgnored, loadConfig, loadDotenv } from "../dist/core/config.js";
import { getChangedLinesForFile, reviewChanges, buildCapabilities, capabilityHint } from "../dist/core/index.js";

const cfg = DEFAULT_CONFIG;
const find = (res, ruleId) => res.findings.find((f) => f.ruleId === ruleId);

test("detects hardcoded secrets as blocking orange", () => {
  const res = analyze({
    filePath: "config.js",
    content: `const apiKey = "supersecretvalue123";\n`,
    config: cfg,
  });
  const f = find(res, "hardcoded-secret");
  assert.ok(f, "expected a hardcoded-secret finding");
  assert.equal(f.tier, "orange");
  assert.equal(f.blocking, true);
  assert.equal(res.tier, "orange");
});

test("flags destructive schema changes as blocking", () => {
  const res = analyze({
    filePath: "migrate.js",
    content: `await db.query("ALTER TABLE users DROP COLUMN email");\n`,
    config: cfg,
  });
  assert.ok(find(res, "db-schema-destructive"), "destructive rule should fire");
  assert.ok(find(res, "raw-query"), "raw-query should also fire");
  assert.equal(res.blocking, true);
});

test("deprecated API uses AST (precise) and offers a fix", () => {
  const res = analyze({
    filePath: "pay.js",
    content: `const r = StripeClient.charge(amount, token);\n`,
    config: cfg,
  });
  const f = find(res, "deprecated-api");
  assert.ok(f, "expected deprecated-api finding");
  assert.ok(f.fix, "expected a quick-fix");
  assert.match(f.fix.newText, /createPaymentIntent/);
});

test("deprecated API in a comment is NOT flagged (AST precision)", () => {
  const res = analyze({
    filePath: "pay.js",
    content: `// StripeClient.charge(amount, token) is old\nconst x = 1;\n`,
    config: cfg,
  });
  assert.equal(find(res, "deprecated-api"), undefined);
});

test("flags public API surface changes", () => {
  const res = analyze({
    filePath: "api.js",
    content: `export function getThing(id) { return id; }\n`,
    config: cfg,
  });
  assert.ok(find(res, "public-api-change"));
});

test("detects exported signature drift vs previous content", () => {
  const res = analyze({
    filePath: "math.js",
    previousContent: `export function add(a, b) {\n  return a + b;\n}\n`,
    content: `export function add(a, b, c) {\n  return a + b + c;\n}\n`,
    changedLines: new Set([1, 2]),
    config: cfg,
  });
  const f = find(res, "signature-drift");
  assert.ok(f, "expected signature-drift finding");
  assert.match(f.message, /add/);
});

test("is diff-aware: ignores findings outside changed lines", () => {
  const content = `const ok = 1;\nconst ok2 = 2;\nconst apiKey = "supersecretvalue123";\n`;
  const res = analyze({
    filePath: "x.js",
    content,
    changedLines: new Set([1]), // secret is on line 3, not changed
    config: cfg,
  });
  assert.equal(find(res, "hardcoded-secret"), undefined);
  assert.equal(res.findings.length, 0);
});

test("language-agnostic rules work on Python", () => {
  const res = analyze({
    filePath: "tool.py",
    content: `import os\nos.system(user_input)\n`,
    config: cfg,
  });
  assert.ok(find(res, "dangerous-exec"), "dangerous-exec should fire on Python");
});

test("does not throw on unparseable source, still runs pattern rules", () => {
  const res = analyze({
    filePath: "broken.js",
    content: `function ( { const apiKey = "supersecretvalue123"\n`,
    config: cfg,
  });
  assert.ok(Array.isArray(res.findings));
  assert.ok(find(res, "hardcoded-secret"), "pattern rules run even when AST fails");
});

test("ignore globs match nested node_modules", () => {
  const cwd = "/repo";
  assert.equal(isIgnored("/repo/node_modules/x/index.js", cfg, cwd), true);
  assert.equal(isIgnored("/repo/src/index.js", cfg, cwd), false);
  assert.equal(isIgnored("/repo/a/b/c.min.js", cfg, cwd), true);
});

test("loadDotenv parses .env into process.env without clobbering existing vars", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "diffgate-env-"));
  fs.writeFileSync(path.join(dir, ".env"), [
    "# a comment",
    "",
    "DG_PLAIN=hello",
    "export DG_EXPORTED=world",
    'DG_QUOTED="a b c"',
    "DG_PREEXISTING=fromfile",
  ].join("\n"));
  process.env.DG_PREEXISTING = "fromenv";
  try {
    const loaded = loadDotenv(dir);
    assert.equal(loaded, path.join(dir, ".env"));
    assert.equal(process.env.DG_PLAIN, "hello");
    assert.equal(process.env.DG_EXPORTED, "world");
    assert.equal(process.env.DG_QUOTED, "a b c");
    assert.equal(process.env.DG_PREEXISTING, "fromenv"); // real env var wins
  } finally {
    delete process.env.DG_PLAIN; delete process.env.DG_EXPORTED;
    delete process.env.DG_QUOTED; delete process.env.DG_PREEXISTING;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- git integration ---------------------------------------------------------

function runGit(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
}

test("git diff-awareness end-to-end via reviewChanges", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "grg-"));
  try {
    runGit(tmp, "init", "-q");
    runGit(tmp, "config", "user.email", "t@t.dev");
    runGit(tmp, "config", "user.name", "Test");
    const file = path.join(tmp, "math.js");
    fs.writeFileSync(file, `export function add(a, b) {\n  return a + b;\n}\n`);
    runGit(tmp, "add", "-A");
    runGit(tmp, "commit", "-q", "-m", "base");

    // Now change the signature and add a secret.
    fs.writeFileSync(
      file,
      `export function add(a, b, c) {\n  return a + b + c;\n}\nconst apiKey = "supersecretvalue123";\n`
    );

    const changed = getChangedLinesForFile(tmp, "math.js");
    assert.ok(changed instanceof Set && changed.size > 0, "should detect changed lines");

    const review = reviewChanges(tmp);
    assert.ok(review.files.length >= 1, "should find the changed file");
    assert.equal(review.tier, "orange");
    assert.equal(review.blocking, true);
    const all = review.files.flatMap((f) => f.findings).map((f) => f.ruleId);
    assert.ok(all.includes("hardcoded-secret"));
    assert.ok(all.includes("signature-drift"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- new rules

test("sql-injection: fires on template literal in db.query", () => {
  const res = analyze({ filePath: "r.js", content: "db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n", config: cfg });
  assert.ok(find(res, "sql-injection"), "sql-injection should fire");
  assert.equal(find(res, "sql-injection").blocking, true);
});

test("sql-injection: does NOT fire on parameterized query", () => {
  const res = analyze({ filePath: "r.js", content: 'db.query("SELECT * FROM users WHERE id = ?", [id]);\n', config: cfg });
  assert.equal(find(res, "sql-injection"), undefined);
});

test("permissive-cors: fires on cors({ origin: '*' })", () => {
  const res = analyze({ filePath: "s.js", content: "app.use(cors({ origin: '*' }));\n", config: cfg });
  assert.ok(find(res, "permissive-cors"), "permissive-cors should fire");
});

test("permissive-cors: does NOT fire on explicit origin", () => {
  const res = analyze({ filePath: "s.js", content: "app.use(cors({ origin: 'https://app.example.com' }));\n", config: cfg });
  assert.equal(find(res, "permissive-cors"), undefined);
});

test("xss-sink: fires on innerHTML assignment", () => {
  const res = analyze({ filePath: "u.js", content: "el.innerHTML = userInput;\n", config: cfg });
  assert.ok(find(res, "xss-sink"), "xss-sink should fire");
});

test("xss-sink: does NOT fire on textContent assignment", () => {
  const res = analyze({ filePath: "u.js", content: "el.textContent = userInput;\n", config: cfg });
  assert.equal(find(res, "xss-sink"), undefined);
});

test("path-traversal: fires when req.params used in path.join", () => {
  const res = analyze({ filePath: "f.js", content: "const fp = path.join(__dirname, req.params.filename);\n", config: cfg });
  assert.ok(find(res, "path-traversal"), "path-traversal should fire");
});

test("path-traversal: does NOT fire on static path.join", () => {
  const res = analyze({ filePath: "f.js", content: "const fp = path.join(__dirname, 'static', 'index.html');\n", config: cfg });
  assert.equal(find(res, "path-traversal"), undefined);
});

test("nosql-injection: fires on find(req.body) direct passthrough", () => {
  const res = analyze({ filePath: "d.js", content: "const docs = Model.find(req.body);\n", config: cfg });
  assert.ok(find(res, "nosql-injection"), "nosql-injection should fire on raw body passthrough");
});

test("nosql-injection: fires on $where operator", () => {
  const res = analyze({ filePath: "d.js", content: "col.find({ $where: 'this.u == x' });\n", config: cfg });
  assert.ok(find(res, "nosql-injection"), "nosql-injection should fire on $where");
});

test("nosql-injection: does NOT fire on typed field access", () => {
  const res = analyze({ filePath: "d.js", content: "Model.find({ username: req.body.username });\n", config: cfg });
  assert.equal(find(res, "nosql-injection"), undefined);
});

test("prototype-pollution: fires on Object.assign(existing, req.body)", () => {
  const res = analyze({ filePath: "h.js", content: "Object.assign(user, req.body);\n", config: cfg });
  assert.ok(find(res, "prototype-pollution"), "prototype-pollution should fire");
});

test("prototype-pollution: does NOT fire on Object.assign({}, req.body)", () => {
  const res = analyze({ filePath: "h.js", content: "const safe = Object.assign({}, req.body);\n", config: cfg });
  assert.equal(find(res, "prototype-pollution"), undefined);
});

// --- agent autonomy config + capability manifest ----------------------------

test("DEFAULT_CONFIG ships an advisory agent policy", () => {
  const a = DEFAULT_CONFIG.gate.agent;
  assert.equal(a.mode, "advisory");
  assert.equal(a.autoFixFloor, "orange");
  assert.equal(a.maxFixesPerTurn, 3);
  assert.equal(a.escalateAfterTurns, 2);
  assert.equal(a.trustSource, "deterministic");
});

test("loadConfig merges a partial gate.agent over the defaults", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "grg-cfg-"));
  fs.writeFileSync(path.join(dir, ".diffgate.json"), JSON.stringify({ gate: { agent: { mode: "off", maxFixesPerTurn: 1 } } }));
  const { config } = loadConfig(dir);
  assert.equal(config.gate.agent.mode, "off", "override applied");
  assert.equal(config.gate.agent.maxFixesPerTurn, 1, "override applied");
  assert.equal(config.gate.agent.autoFixFloor, "orange", "untouched default kept");
  assert.equal(config.gate.agent.trustSource, "deterministic", "untouched default kept");
  assert.equal(config.gate.failOn, "orange", "sibling gate field kept");
});

test("buildCapabilities reports layers and gates LLM-only tools", () => {
  const caps = buildCapabilities(DEFAULT_CONFIG, "9.9.9");
  assert.equal(caps.version, "9.9.9");
  assert.equal(caps.core, true);
  assert.equal(caps.llm.available, false, "ai disabled by default");
  assert.ok(!caps.availableTools.includes("diffgate_explain"), "explain hidden when no LLM");
  assert.ok(caps.unavailableTools.includes("diffgate_deep_review"));
  assert.ok(caps.availableTools.includes("diffgate_analyze"));
  assert.equal(caps.agent.mode, "advisory");
  assert.ok(caps.protocol.some((p) => /Loop budget/.test(p)), "protocol carries the loop budget");
  assert.ok(caps.protocol.some((p) => /host mode/.test(p)), "no-LLM protocol warns about host-mode self-review");
  assert.ok(
    caps.protocol.some((p) => /both the original and the corrected/i.test(p)),
    "protocol tells the agent to surface self-corrections transparently"
  );
});

test("capabilityHint is a compact 3-field meta", () => {
  const hint = capabilityHint(DEFAULT_CONFIG);
  assert.deepEqual(Object.keys(hint).sort(), ["agentMode", "graph", "llm"]);
  assert.equal(hint.llm, false);
  assert.equal(hint.agentMode, "advisory");
});
