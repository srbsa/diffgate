import test from "node:test";
import assert from "node:assert";
import { buildMetrics, agentVerdict } from "../dist/metrics.js";

function finding(ruleId, tier, over = {}) {
  return { ruleId, tier, blocking: tier === "orange", title: ruleId, message: "m", line: 1, column: 0, endLine: 1, endColumn: 1, code: "", fix: null, ...over };
}
function file(filePath, findings) {
  return { filePath, language: "javascript", findings, tier: "green", counts: {}, blocking: false };
}

test("buildMetrics", async (t) => {
  const files = [
    file("/repo/a.js", [finding("sql-injection", "orange"), finding("network-call", "yellow")]),
    file("/repo/b.js", [finding("sql-injection", "orange")]),
  ];
  const learnings = { version: 1, entries: [
    { id: "1", ruleId: "todo-marker", codeHash: "h", verdict: "dismiss", at: "t" },
    { id: "2", ruleId: "todo-marker", codeHash: "h2", verdict: "dismiss", at: "t" },
    { id: "3", ruleId: "sql-injection", codeHash: "h3", verdict: "confirm", at: "t" },
  ] };

  await t.test("counts tiers and blocked", () => {
    const m = buildMetrics(files, learnings, "/repo");
    assert.deepEqual(m.counts, { green: 0, yellow: 1, orange: 2 });
    assert.equal(m.total, 3);
    assert.equal(m.blocked, true);
    assert.equal(m.filesWithFindings, 2);
  });

  await t.test("ranks top rules and hotspot files", () => {
    const m = buildMetrics(files, learnings, "/repo");
    assert.equal(m.topRules[0].rule, "sql-injection");
    assert.equal(m.topRules[0].count, 2);
    assert.equal(m.topFiles[0].file, "a.js"); // 1 orange + 1 yellow = highest total
  });

  await t.test("summarizes the learnings loop", () => {
    const m = buildMetrics(files, learnings, "/repo");
    assert.equal(m.learnings.dismissed, 2);
    assert.equal(m.learnings.confirmed, 1);
    assert.equal(m.learnings.noisiestRules[0].rule, "todo-marker");
    assert.equal(m.learnings.noisiestRules[0].count, 2);
  });
});

test("agentVerdict", async (t) => {
  await t.test("blocked on orange", () => {
    const v = agentVerdict([file("/r/a.js", [finding("sql-injection", "orange")])]);
    assert.equal(v.verdict, "blocked");
    assert.equal(v.findings.length, 1);
  });
  await t.test("pass when only yellow/green", () => {
    const v = agentVerdict([file("/r/a.js", [finding("network-call", "yellow")])]);
    assert.equal(v.verdict, "pass");
  });
});
