import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";

import { analyze, attachImpact, reviewChanges, DEFAULT_CONFIG } from "../dist/core/index.js";

const cfg = DEFAULT_CONFIG;
const find = (res, ruleId) => res.findings.find((f) => f.ruleId === ruleId);

function fakeGraph(impl, counter) {
  return {
    id: "fake",
    impact: (q) => {
      if (counter) counter.n++;
      return impl(q);
    },
  };
}

function impactObj(over = {}) {
  return {
    symbol: "getThing",
    callerCount: 0,
    callers: [],
    reachable: null,
    testGaps: [],
    reviewers: [],
    source: "codegraph",
    truncated: false,
    ...over,
  };
}

function publicApiResult() {
  return analyze({ filePath: "api.js", content: `export function getThing(id) { return id; }\n`, config: cfg });
}

test("attachImpact: keeps orange and marks escalated when callers exist", () => {
  const res = publicApiResult();
  assert.equal(find(res, "public-api-change").symbol, "getThing");
  const graph = fakeGraph(() => impactObj({ callerCount: 5, callers: [{ file: "a.js" }, { file: "b.js" }], reviewers: ["alice"], reachable: true }));
  const [out] = attachImpact([res], { cwd: "/repo", config: cfg, graph });
  const f = find(out, "public-api-change");
  assert.equal(f.tier, "orange");
  assert.equal(f.tierAdjusted, "escalated");
  assert.equal(f.impact.callerCount, 5);
  assert.match(f.message, /Blast radius/);
  assert.match(f.message, /@alice/);
  assert.equal(out.tier, "orange");
});

test("attachImpact: de-escalates an exported symbol with zero callers", () => {
  const res = publicApiResult();
  const graph = fakeGraph(() => impactObj({ callerCount: 0, source: "codegraph" }));
  const [out] = attachImpact([res], { cwd: "/repo", config: cfg, graph });
  const f = find(out, "public-api-change");
  assert.equal(f.tier, "yellow", "0 callers → down-tiered");
  assert.equal(f.tierAdjusted, "deescalated");
  assert.equal(out.tier, "yellow", "file tier recomputed");
  assert.equal(out.counts.orange, 0);
  assert.equal(out.counts.yellow, 1);
});

test("attachImpact: does NOT de-escalate a non-authoritative (grep) source", () => {
  const res = publicApiResult();
  const graph = fakeGraph(() => impactObj({ callerCount: 0, source: "grep" }));
  const [out] = attachImpact([res], { cwd: "/repo", config: cfg, graph });
  const f = find(out, "public-api-change");
  assert.equal(f.tier, "orange", "0 from grep is a possible miss — don't trust it to down-tier");
  assert.equal(f.tierAdjusted, undefined);
});

test("attachImpact: respects a user-pinned tier (no auto-adjust)", () => {
  const res = publicApiResult();
  const pinned = { ...cfg, rules: { "public-api-change": { tier: "orange" } } };
  const graph = fakeGraph(() => impactObj({ callerCount: 0, source: "codegraph" }));
  const [out] = attachImpact([res], { cwd: "/repo", config: pinned, graph });
  const f = find(out, "public-api-change");
  assert.equal(f.tier, "orange", "pinned tier must not be de-escalated");
  assert.equal(f.tierAdjusted, undefined);
  assert.ok(f.impact, "impact is still attached for context");
});

test("attachImpact: null graph is a pure no-op", () => {
  const res = publicApiResult();
  const files = [res];
  const out = attachImpact(files, { cwd: "/repo", config: cfg, graph: null });
  assert.equal(out, files, "same array reference returned");
  assert.equal(find(out[0], "public-api-change").impact, undefined);
});

test("attachImpact: only queries the graph for impact-eligible findings", () => {
  // A plain debug-logging finding has no symbol → graph must not be consulted.
  const res = analyze({ filePath: "log.js", content: `console.log("hi");\n`, config: cfg });
  const counter = { n: 0 };
  const graph = fakeGraph(() => impactObj(), counter);
  attachImpact([res], { cwd: "/repo", config: cfg, graph });
  assert.equal(counter.n, 0, "no symbol → zero graph calls");
});

test("attachImpact: caches per (file,symbol,line) — one call per finding", () => {
  const res = publicApiResult();
  const counter = { n: 0 };
  const graph = fakeGraph(() => impactObj({ callerCount: 2, callers: [{ file: "a.js" }] }), counter);
  attachImpact([res], { cwd: "/repo", config: cfg, graph });
  assert.equal(counter.n, 1);
});

test("attachImpact: enriches a non-tierable rule (deprecated-api) without changing tier", () => {
  // StripeClient.charge is a default deprecated entry (yellow) and now carries a symbol.
  const res = analyze({ filePath: "pay.js", content: `const r = StripeClient.charge(amount, token);\n`, config: cfg });
  const dep = find(res, "deprecated-api");
  assert.ok(dep, "expected deprecated-api finding");
  assert.equal(dep.symbol, "StripeClient.charge");
  const graph = fakeGraph(() => impactObj({ symbol: "StripeClient.charge", callerCount: 8, callers: [{ file: "x.js" }] }));
  const [out] = attachImpact([res], { cwd: "/repo", config: cfg, graph });
  const f = find(out, "deprecated-api");
  assert.equal(f.tier, "yellow", "deprecated-api tier is unchanged");
  assert.equal(f.tierAdjusted, undefined);
  assert.match(f.message, /Blast radius: 8/);
});

test("attachImpact: escalateThreshold gate (below threshold leaves tier as-is, still enriches)", () => {
  const res = publicApiResult();
  const config = { ...cfg, graph: { ...cfg.graph, escalateThreshold: 10 } };
  const graph = fakeGraph(() => impactObj({ callerCount: 3, callers: [{ file: "a.js" }], source: "codegraph" }));
  const [out] = attachImpact([res], { cwd: "/repo", config, graph });
  const f = find(out, "public-api-change");
  // 3 callers, below threshold 10 but > 0 → not de-escalated, not marked escalated.
  assert.equal(f.tier, "orange");
  assert.equal(f.tierAdjusted, undefined);
  assert.ok(f.impact);
});

// --- end-to-end through reviewChanges with an injected graph -----------------

function runGit(cwd, ...args) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
}

test("reviewChanges: injected graph de-escalates a no-caller signature change end-to-end", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dg-impact-"));
  try {
    runGit(tmp, "init", "-q");
    runGit(tmp, "config", "user.email", "t@t.dev");
    runGit(tmp, "config", "user.name", "Test");
    const file = path.join(tmp, "math.js");
    fs.writeFileSync(file, `export function add(a, b) {\n  return a + b;\n}\n`);
    runGit(tmp, "add", "-A");
    runGit(tmp, "commit", "-q", "-m", "base");
    // Change the exported signature.
    fs.writeFileSync(file, `export function add(a, b, c) {\n  return a + b + c;\n}\n`);

    // Baseline: no graph → signature-drift stays orange.
    const baseline = reviewChanges(tmp, { graph: null });
    assert.equal(baseline.tier, "orange");
    assert.ok(baseline.files.flatMap((f) => f.findings).some((f) => f.ruleId === "signature-drift"));

    // With a graph reporting zero callers → the whole review de-escalates to yellow.
    const graph = { id: "fake", impact: () => impactObj({ symbol: "add", callerCount: 0, source: "codegraph" }) };
    const withGraph = reviewChanges(tmp, { graph });
    const drift = withGraph.files.flatMap((f) => f.findings).find((f) => f.ruleId === "signature-drift");
    assert.equal(drift.tierAdjusted, "deescalated");
    assert.equal(drift.tier, "yellow");
    assert.equal(withGraph.tier, "yellow", "overall review tier reflects the de-escalation");
    assert.equal(withGraph.blocking, false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
