import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";

import { recordLearning, loadLearnings, applyLearnings, isDismissed, codeHash } from "../dist/core/learnings.js";

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "grg-learn-"));
}

function finding(over = {}) {
  return {
    ruleId: "todo-marker", tier: "yellow", blocking: false, title: "TODO", message: "m",
    line: 1, column: 0, endLine: 1, endColumn: 0, code: "// TODO: fix later", fix: null, ...over,
  };
}

function result(findings) {
  return { filePath: "/x.ts", language: "javascript", findings, tier: "yellow", counts: {}, blocking: false };
}

test("recordLearning + loadLearnings roundtrip, writes under .diffgate/", () => {
  const root = tmp();
  recordLearning(root, { ruleId: "todo-marker", code: "// TODO: fix later", verdict: "dismiss", now: "2026-06-16T00:00:00Z" });
  assert.ok(fs.existsSync(path.join(root, ".diffgate", "learnings.json")));
  const store = loadLearnings(root);
  assert.equal(store.entries.length, 1);
  assert.equal(store.entries[0].verdict, "dismiss");
  assert.equal(store.entries[0].codeHash, codeHash("// TODO: fix later"));
});

test("latest verdict wins for the same (ruleId, code)", () => {
  const root = tmp();
  recordLearning(root, { ruleId: "todo-marker", code: "// TODO: x", verdict: "dismiss", now: "2026-06-16T00:00:00Z" });
  recordLearning(root, { ruleId: "todo-marker", code: "// TODO: x", verdict: "confirm", now: "2026-06-16T01:00:00Z" });
  const store = loadLearnings(root);
  assert.equal(store.entries.length, 1);
  assert.equal(store.entries[0].verdict, "confirm");
});

test("applyLearnings drops dismissed findings and recomputes tier", () => {
  const root = tmp();
  recordLearning(root, { ruleId: "todo-marker", code: "// TODO: fix later", verdict: "dismiss" });
  const store = loadLearnings(root);
  const orange = finding({ ruleId: "public-api-change", tier: "orange", code: "export function f(){}" });
  const out = applyLearnings(result([finding(), orange]), store);
  assert.equal(out.findings.length, 1);
  assert.equal(out.findings[0].ruleId, "public-api-change");
  assert.equal(out.tier, "orange");
});

test("isDismissed only matches same rule + same code; confirm does not suppress", () => {
  const root = tmp();
  recordLearning(root, { ruleId: "todo-marker", code: "// TODO: a", verdict: "confirm" });
  recordLearning(root, { ruleId: "todo-marker", code: "// TODO: b", verdict: "dismiss" });
  const store = loadLearnings(root);
  assert.equal(isDismissed({ ruleId: "todo-marker", code: "// TODO: a" }, store), false, "confirm is not a suppression");
  assert.equal(isDismissed({ ruleId: "todo-marker", code: "// TODO: b" }, store), true);
  assert.equal(isDismissed({ ruleId: "other", code: "// TODO: b" }, store), false, "rule must match");
});
