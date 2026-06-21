import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  recordTurn,
  findingFingerprint,
  loadSession,
  clearSession,
} from "../dist/core/session.js";

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "diffgate-session-"));
}
function f(ruleId, code) {
  return { ruleId, code };
}
function entries(...findings) {
  return findings.map((fd) => ({ file: "/repo/a.js", finding: fd }));
}

test("findingFingerprint is stable across lines, distinct per rule/file/code", () => {
  const a1 = findingFingerprint("/repo/a.js", { ruleId: "sql-injection", code: "q(x)" });
  const a2 = findingFingerprint("/repo/a.js", { ruleId: "sql-injection", code: "q(x)" });
  assert.equal(a1, a2, "same rule+file+code → same fingerprint");
  assert.notEqual(a1, findingFingerprint("/repo/b.js", { ruleId: "sql-injection", code: "q(x)" }), "file matters");
  assert.notEqual(a1, findingFingerprint("/repo/a.js", { ruleId: "xss-sink", code: "q(x)" }), "rule matters");
  assert.notEqual(a1, findingFingerprint("/repo/a.js", { ruleId: "sql-injection", code: "q(y)" }), "code matters");
});

test("recordTurn escalates a finding only after it outlasts escalateAfterTurns", () => {
  const dir = tmp();
  try {
    const fp = findingFingerprint("/repo/a.js", f("sql-injection", "q(x)"));
    const r1 = recordTurn(dir, "s1", entries(f("sql-injection", "q(x)")), { escalateAfterTurns: 2 });
    assert.equal(r1.turns.get(fp), 1);
    assert.equal(r1.overBudget.has(fp), false, "1 turn < budget");

    const r2 = recordTurn(dir, "s1", entries(f("sql-injection", "q(x)")), { escalateAfterTurns: 2 });
    assert.equal(r2.turns.get(fp), 2);
    assert.equal(r2.overBudget.has(fp), true, "2 turns ≥ budget → over");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("recordTurn counts each distinct finding once per turn", () => {
  const dir = tmp();
  try {
    const fp = findingFingerprint("/repo/a.js", f("xss-sink", "el.innerHTML=x"));
    // Same finding twice in one turn must only bump the counter once.
    const r = recordTurn(dir, "s1", entries(f("xss-sink", "el.innerHTML=x"), f("xss-sink", "el.innerHTML=x")), { escalateAfterTurns: 2 });
    assert.equal(r.turns.get(fp), 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a different sessionId resets the ledger (no cross-session bleed)", () => {
  const dir = tmp();
  try {
    const fp = findingFingerprint("/repo/a.js", f("sql-injection", "q(x)"));
    recordTurn(dir, "s1", entries(f("sql-injection", "q(x)")), { escalateAfterTurns: 2 });
    const other = recordTurn(dir, "s2", entries(f("sql-injection", "q(x)")), { escalateAfterTurns: 2 });
    assert.equal(other.turns.get(fp), 1, "s2 starts fresh, ignoring s1's count");
    assert.equal(other.overBudget.has(fp), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an expired idle window resets the ledger", () => {
  const dir = tmp();
  try {
    const fp = findingFingerprint("/repo/a.js", f("sql-injection", "q(x)"));
    recordTurn(dir, "s1", entries(f("sql-injection", "q(x)")), { escalateAfterTurns: 2 });
    // ttl=0 → the prior turn is always "too old", so the next turn starts a fresh count.
    const r = recordTurn(dir, "s1", entries(f("sql-injection", "q(x)")), { escalateAfterTurns: 2, ttlMs: 0 });
    assert.equal(r.turns.get(fp), 1, "stale ledger reset → back to 1");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("loadSession reflects saved state; clearSession forgets it", () => {
  const dir = tmp();
  try {
    recordTurn(dir, "s1", entries(f("sql-injection", "q(x)")), { escalateAfterTurns: 5 });
    const s = loadSession(dir, "s1");
    assert.equal(Object.keys(s.turns).length, 1);
    clearSession(dir);
    const fresh = loadSession(dir, "s1");
    assert.deepEqual(fresh.turns, {});
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
