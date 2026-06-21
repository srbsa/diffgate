import test from "node:test";
import assert from "node:assert/strict";

import { analyze, DEFAULT_CONFIG } from "../dist/core/index.js";
import { maskComments } from "../dist/core/mask.js";
import { isTestPath, applyTestScope } from "../dist/core/testscope.js";
import { mergeLearningStores } from "../dist/core/learnings.js";

const cfg = DEFAULT_CONFIG;
const find = (res, ruleId) => res.findings.find((f) => f.ruleId === ruleId);

// --- comment masking --------------------------------------------------------

test("mask: blanks a python line comment, keeps the code before it", () => {
  const [out] = maskComments(["os.system(x)  # danger eval()"], "python");
  assert.match(out, /^os\.system\(x\)\s+$/);
  assert.equal(out.length, "os.system(x)  # danger eval()".length, "length (columns) preserved");
});

test("mask: does not treat // inside a string as a comment", () => {
  const [out] = maskComments(['const u = "http://example.com";'], "javascript");
  assert.match(out, /http:\/\/example\.com/, "string content left intact");
});

test("mask: carries a block comment across lines", () => {
  const out = maskComments(["/* start", "eval(x)", "end */ real()"], "javascript");
  assert.match(out[1], /^\s+$/, "interior block-comment line fully masked");
  assert.match(out[2], /real\(\)/, "code after block close survives");
});

test("mask: unknown language is a no-op", () => {
  const input = ["anything # here"];
  assert.deepEqual(maskComments(input, "cobol"), input);
});

test("analyze: commented-out exec is NOT flagged; real exec IS (python)", () => {
  const res = analyze({
    filePath: "x.py",
    content: "# os.system(bad)\nos.system(real)\n",
    config: cfg,
  });
  const execs = res.findings.filter((f) => f.ruleId === "dangerous-exec");
  assert.equal(execs.length, 1, "only the real call fires");
  assert.equal(execs[0].line, 2);
});

test("analyze: a secret inside a comment is STILL flagged (scanRaw)", () => {
  const res = analyze({
    filePath: "x.py",
    content: "# key = AKIAIOSFODNN7EXAMPLE\n",
    config: cfg,
  });
  assert.ok(find(res, "hardcoded-secret"), "commented secret is a real leak");
});

test("analyze: SQL inside a string is still detected (strings not masked)", () => {
  const res = analyze({
    filePath: "x.py",
    content: 'q = "DROP TABLE users"\n',
    config: cfg,
  });
  assert.ok(find(res, "db-schema-destructive"));
});

// --- test-context de-escalation --------------------------------------------

test("isTestPath: recognizes common conventions across languages", () => {
  for (const p of [
    "src/app.test.ts", "src/app.spec.js", "pkg/foo_test.go", "tests/test_foo.py",
    "src/__tests__/a.js", "spec/models/user_spec.rb", "com/acme/FooTest.java", "conftest.py",
    "fixtures/data.js",
  ]) assert.equal(isTestPath(p), true, `${p} should be a test path`);
  for (const p of ["src/app.ts", "src/latest.js", "lib/contest.py"]) {
    assert.equal(isTestPath(p), false, `${p} should NOT be a test path`);
  }
});

test("test-scope: orange exec de-escalates to yellow in a test file", () => {
  const res = analyze({ filePath: "src/app.test.js", content: "eval(userInput);\n", config: cfg });
  const f = find(res, "dangerous-exec");
  assert.equal(f.tier, "yellow");
  assert.equal(f.blocking, false);
  assert.equal(f.tierAdjusted, "deescalated");
});

test("test-scope: secrets and destructive schema stay blocking in tests", () => {
  const res = analyze({
    filePath: "src/app.test.js",
    content: 'const k = "AKIAIOSFODNN7EXAMPLE";\ndb.query("DROP TABLE t");\n',
    config: cfg,
  });
  assert.equal(find(res, "hardcoded-secret").tier, "orange");
  assert.equal(find(res, "hardcoded-secret").blocking, true);
  assert.equal(find(res, "db-schema-destructive").tier, "orange");
});

test("test-scope: testScope:false gates test code like prod", () => {
  const res = analyze({ filePath: "src/app.test.js", content: "eval(userInput);\n", config: { ...cfg, testScope: false } });
  assert.equal(find(res, "dangerous-exec").tier, "orange");
});

test("test-scope: prod file is unaffected", () => {
  const res = analyze({ filePath: "src/app.js", content: "eval(userInput);\n", config: cfg });
  assert.equal(find(res, "dangerous-exec").tier, "orange");
});

test("test-scope: a pinned rule keeps its tier even in a test file", () => {
  const res = analyze({
    filePath: "src/app.test.js",
    content: "eval(userInput);\n",
    config: { ...cfg, rules: { "dangerous-exec": { tier: "orange" } } },
  });
  assert.equal(find(res, "dangerous-exec").tier, "orange");
});

test("applyTestScope: never suppresses — count is preserved", () => {
  const findings = [
    { ruleId: "dangerous-exec", tier: "orange", blocking: true, message: "m" },
    { ruleId: "hardcoded-secret", tier: "orange", blocking: true, message: "m" },
  ];
  const out = applyTestScope(findings, "a.test.js", {});
  assert.equal(out.length, 2);
});

// --- learnings merge driver -------------------------------------------------

test("mergeLearningStores: unions entries by id, sorted", () => {
  const ours = { version: 1, entries: [{ id: "r1:a", at: "2026-01-01" }, { id: "r2:b", at: "2026-02-01" }] };
  const theirs = { version: 1, entries: [{ id: "r1:a", at: "2026-01-01" }, { id: "r3:c", at: "2026-03-01" }] };
  const m = mergeLearningStores(ours, theirs);
  assert.deepEqual(m.entries.map((e) => e.id), ["r1:a", "r2:b", "r3:c"]);
});

test("mergeLearningStores: newer timestamp wins on id collision", () => {
  const ours = { version: 1, entries: [{ id: "r1:a", verdict: "dismiss", at: "2026-01-01" }] };
  const theirs = { version: 1, entries: [{ id: "r1:a", verdict: "confirm", at: "2026-05-01" }] };
  const m = mergeLearningStores(ours, theirs);
  assert.equal(m.entries.length, 1);
  assert.equal(m.entries[0].verdict, "confirm", "theirs is strictly newer");
});

test("mergeLearningStores: ours wins an exact-timestamp tie", () => {
  const ours = { version: 1, entries: [{ id: "r1:a", verdict: "confirm", at: "2026-01-01" }] };
  const theirs = { version: 1, entries: [{ id: "r1:a", verdict: "dismiss", at: "2026-01-01" }] };
  const m = mergeLearningStores(ours, theirs);
  assert.equal(m.entries[0].verdict, "confirm");
});
