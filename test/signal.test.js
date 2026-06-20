import test from "node:test";
import assert from "node:assert/strict";

import { predictedSignal, realizedSignal } from "../dist/core/index.js";

test("predictedSignal: orange+yellow = signal, green = low-signal", () => {
  const s = predictedSignal({ green: 1, yellow: 2, orange: 1 });
  assert.equal(s.t1, 1);
  assert.equal(s.t2, 2);
  assert.equal(s.t3, 1);
  assert.equal(s.total, 4);
  assert.equal(s.ratio, 0.75);
});

test("predictedSignal: no findings → ratio 1 (nothing is noise)", () => {
  const s = predictedSignal({ green: 0, yellow: 0, orange: 0 });
  assert.equal(s.total, 0);
  assert.equal(s.ratio, 1);
});

function store(entries) {
  return { version: 1, entries };
}

test("realizedSignal: counts confirms vs dismisses into a ratio", () => {
  const s = realizedSignal(
    store([
      { ruleId: "hardcoded-secret", verdict: "confirm" },
      { ruleId: "hardcoded-secret", verdict: "confirm" },
      { ruleId: "todo-marker", verdict: "dismiss" },
    ])
  );
  assert.equal(s.confirmed, 2);
  assert.equal(s.dismissed, 1);
  assert.equal(s.total, 3);
  assert.equal(Math.round(s.signalRatio * 100), 67);
});

test("realizedSignal: flags chronically noisy rules (≥3 dismissals, ≥70% noise)", () => {
  const s = realizedSignal(
    store([
      { ruleId: "todo-marker", verdict: "dismiss" },
      { ruleId: "todo-marker", verdict: "dismiss" },
      { ruleId: "todo-marker", verdict: "dismiss" },
      { ruleId: "todo-marker", verdict: "confirm" },
      { ruleId: "sql-injection", verdict: "confirm" },
    ])
  );
  const noisy = s.chronicNoise.map((r) => r.ruleId);
  assert.ok(noisy.includes("todo-marker"), "todo-marker is 3/4 = 75% noise");
  assert.ok(!noisy.includes("sql-injection"), "sql-injection has no dismissals");
  const todo = s.byRule.find((r) => r.ruleId === "todo-marker");
  assert.equal(todo.dismissed, 3);
  assert.equal(todo.total, 4);
});

test("realizedSignal: below the dismissal floor is not chronic noise", () => {
  const s = realizedSignal(
    store([
      { ruleId: "network-call", verdict: "dismiss" },
      { ruleId: "network-call", verdict: "dismiss" },
    ])
  );
  assert.equal(s.chronicNoise.length, 0, "only 2 dismissals — below the min-3 floor");
});

test("realizedSignal: empty store → ratio 1, no noise", () => {
  const s = realizedSignal(store([]));
  assert.equal(s.total, 0);
  assert.equal(s.signalRatio, 1);
  assert.deepEqual(s.chronicNoise, []);
});
