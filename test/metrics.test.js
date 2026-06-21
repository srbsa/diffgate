import test from "node:test";
import assert from "node:assert";
import { buildMetrics, agentVerdict } from "../dist/metrics.js";
import { findingFingerprint } from "../dist/core/session.js";

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

test("agentVerdict autonomy ladder", async (t) => {
  await t.test("advisory (default): a non-blocking orange is 'review', not 'blocked'", () => {
    const v = agentVerdict([file("/r/a.js", [finding("network-call", "orange", { blocking: false })])]);
    assert.equal(v.verdict, "review");
    assert.equal(v.mode, "advisory");
    assert.equal(v.findings[0].rung, "autofix");
  });

  await t.test("advisory: a hard (blocking) finding blocks", () => {
    const v = agentVerdict([file("/r/a.js", [finding("hardcoded-secret", "orange", { blocking: true })])]);
    assert.equal(v.verdict, "blocked");
    assert.equal(v.findings[0].rung, "block");
  });

  await t.test("advisory: a graph-confirmed taint blocks even when not flagged blocking", () => {
    const v = agentVerdict([file("/r/a.js", [finding("xss-sink", "orange", { blocking: false, trust: "confirmed" })])]);
    assert.equal(v.verdict, "blocked");
    assert.equal(v.findings[0].rung, "block");
  });

  await t.test("advisory: an escalated (high blast radius) finding is 'review' + 'escalate' rung", () => {
    const v = agentVerdict([file("/r/a.js", [finding("public-api-change", "orange", { blocking: false, tierAdjusted: "escalated" })])]);
    assert.equal(v.verdict, "review");
    assert.equal(v.findings[0].rung, "escalate");
  });

  await t.test("off mode never blocks", () => {
    const v = agentVerdict([file("/r/a.js", [finding("hardcoded-secret", "orange", { blocking: true })])], { mode: "off" });
    assert.equal(v.verdict, "pass");
  });

  await t.test("gated mode keeps legacy orange-blocks behavior", () => {
    const v = agentVerdict([file("/r/a.js", [finding("network-call", "orange", { blocking: false })])], { mode: "gated" });
    assert.equal(v.verdict, "blocked");
  });

  await t.test("echoes mode + budget for the agent", () => {
    const v = agentVerdict([file("/r/a.js", [finding("todo-marker", "green")])], { mode: "advisory", maxFixesPerTurn: 5, escalateAfterTurns: 4 });
    assert.equal(v.verdict, "pass");
    assert.deepEqual(v.budget, { maxFixesPerTurn: 5, escalateAfterTurns: 4 });
    assert.equal(v.findings[0].rung, "advisory");
    assert.equal(v.findings[0].trust, "confirmed", "defaults to confirmed when unset");
    assert.equal(v.escalations, 0, "no escalations without a tracked session");
  });
});

test("agentVerdict budget overrun (opt-in session)", async (t) => {
  await t.test("an over-budget advisory finding is promoted to 'escalate' → 'review'", () => {
    const yellow = finding("network-call", "yellow", { code: "fetch(x)" });
    const over = new Set([findingFingerprint("/r/a.js", yellow)]);
    const v = agentVerdict([file("/r/a.js", [yellow])], { mode: "advisory" }, { overBudget: over });
    assert.equal(v.findings[0].rung, "escalate");
    assert.equal(v.findings[0].overBudget, true);
    assert.equal(v.escalations, 1);
    assert.equal(v.verdict, "review", "escalation surfaces a non-blocking finding for human review");
  });

  await t.test("a blocking finding stays 'block' even when over budget", () => {
    const secret = finding("hardcoded-secret", "orange", { blocking: true, code: "sk_live_x" });
    const over = new Set([findingFingerprint("/r/a.js", secret)]);
    const v = agentVerdict([file("/r/a.js", [secret])], { mode: "advisory" }, { overBudget: over });
    assert.equal(v.findings[0].rung, "block");
    assert.equal(v.verdict, "blocked");
  });

  await t.test("no overBudget set → no escalation (deterministic default)", () => {
    const v = agentVerdict([file("/r/a.js", [finding("network-call", "yellow", { code: "fetch(x)" })])], { mode: "advisory" });
    assert.equal(v.findings[0].rung, "advisory");
    assert.equal(v.escalations, 0);
  });
});
