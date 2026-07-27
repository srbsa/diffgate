// Graph-backed confirmation for `single-caller-abstraction`.
//
// The detector rule emits optimistically from a single file; this pass is what makes the finding
// mean anything. The invariant under test throughout: an UNKNOWN is never treated as a zero. No
// graph, no language coverage, a truncated walk, or a provider that throws all mean "cannot prove
// speculative" — and an unproven finding is dropped rather than shown.
import test from "node:test";
import assert from "node:assert/strict";
import { attachStructuralImpact, STRUCTURAL_IMPACT_RULES } from "../dist/core/index.js";

const RULE = "single-caller-abstraction";

function finding(over = {}) {
  return {
    ruleId: RULE,
    symbol: "PaymentGateway",
    line: 3,
    tier: "yellow",
    blocking: false,
    message: "⚡ Speculative abstraction: PaymentGateway",
    code: "class PaymentGateway:",
    ...over,
  };
}

function file(findings) {
  return {
    filePath: "src/pay.py",
    findings,
    tier: "yellow",
    counts: { green: 0, yellow: findings.length, orange: 0 },
    blocking: false,
  };
}

function impact(over = {}) {
  return { callerCount: 0, source: "builtin", ambiguous: false, testGaps: [], refs: [], ...over };
}

/** Graph stub. `impl` receives the query and returns an ImpactInfo or null. */
function fakeGraph(impl, counter) {
  return {
    id: "fake",
    impact: (q) => {
      if (counter) counter.n++;
      return impl(q);
    },
  };
}

const run = (files, graph) => attachStructuralImpact(files, { cwd: "/repo", config: {}, graph });
const ids = (out) => out.flatMap((f) => f.findings.map((x) => x.ruleId));

test("callerCount 0 → kept and annotated with the proof", () => {
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 0 })));
  assert.equal(out[0].findings.length, 1);
  assert.match(out[0].findings[0].message, /no call sites/);
  assert.match(out[0].findings[0].message, /Flatten it/);
});

test("callerCount 1 → kept (a single caller is still speculative)", () => {
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 1 })));
  assert.equal(out[0].findings.length, 1);
  assert.match(out[0].findings[0].message, /1 call site/);
});

test("callerCount 2+ → dropped, the abstraction is justified", () => {
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 5 })));
  assert.deepEqual(ids(out), []);
});

test("no graph → dropped (unknown is not zero)", () => {
  const out = run([file([finding()])], null);
  assert.deepEqual(ids(out), []);
});

test("graph returns null (no coverage / truncated walk) → dropped", () => {
  const out = run([file([finding()])], fakeGraph(() => null));
  assert.deepEqual(ids(out), []);
});

test("graph throws → dropped, never propagates", () => {
  const out = run([file([finding()])], fakeGraph(() => { throw new Error("provider exploded"); }));
  assert.deepEqual(ids(out), []);
});

test("ambiguous match → kept but flagged as unreliable, never silently authoritative", () => {
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 0, ambiguous: true })));
  assert.equal(out[0].findings.length, 1);
  assert.match(out[0].findings[0].message, /matched multiple definitions/);
});

test("finding without a symbol → dropped (nothing to look up)", () => {
  const out = run([file([finding({ symbol: null })])], fakeGraph(() => impact({ callerCount: 0 })));
  assert.deepEqual(ids(out), []);
});

test("confirmed findings stay yellow and non-blocking", () => {
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 0 })));
  assert.equal(out[0].findings[0].tier, "yellow");
  assert.equal(out[0].findings[0].blocking, false);
});

test("unrelated findings are never touched, with or without a graph", () => {
  const other = { ruleId: "sql-injection", symbol: "q", line: 9, tier: "orange", blocking: true, message: "m", code: "c" };
  for (const graph of [null, fakeGraph(() => impact({ callerCount: 9 }))]) {
    const out = run([file([finding(), other])], graph);
    assert.deepEqual(ids(out), ["sql-injection"]);
    assert.equal(out[0].findings[0].blocking, true, "unrelated finding kept intact");
  }
});

test("recompute: dropping the only finding clears the file's blocking/tier rollup", () => {
  const f = file([finding({ tier: "yellow" })]);
  const out = run([f], fakeGraph(() => impact({ callerCount: 4 })));
  assert.equal(out[0].findings.length, 0);
  assert.equal(out[0].blocking, false);
  assert.deepEqual(out[0].counts, { green: 0, yellow: 0, orange: 0 });
});

test("no candidate findings → input returned untouched, graph never consulted", () => {
  const counter = { n: 0 };
  const only = [file([{ ruleId: "todo-marker", line: 1, tier: "green", blocking: false, message: "m", code: "c" }])];
  const out = run(only, fakeGraph(() => impact(), counter));
  assert.equal(out, only, "same array identity — no work done");
  assert.equal(counter.n, 0, "graph must not be queried when nothing is eligible");
});

test("repeated symbol+line in one file is cached, not re-queried", () => {
  const counter = { n: 0 };
  run([file([finding(), finding()])], fakeGraph(() => impact({ callerCount: 0 }), counter));
  assert.equal(counter.n, 1, "second identical lookup should hit the cache");
});

test("STRUCTURAL_IMPACT_RULES is the contract the detector must match", () => {
  assert.ok(STRUCTURAL_IMPACT_RULES.has(RULE));
});

// ---------------------------------------------------------------------------
// Truncated walk: a count from an incomplete graph is a floor, not a total.
// ---------------------------------------------------------------------------

test("truncated walk with 0 callers → dropped (unknown is never a zero)", () => {
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 0, truncated: true })));
  assert.deepEqual(ids(out), []);
});

test("truncated walk with 1 caller → dropped (the callers we did not reach are the ones that matter)", () => {
  // The regression: the provider's own guard only covered callerCount === 0, but the rule's
  // confirmation threshold is <= 1, so a budget-truncated walk that happened to find exactly one
  // caller was reported as an exact count and confirmed the finding.
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 1, truncated: true })));
  assert.deepEqual(ids(out), []);
});

test("a complete walk with 1 caller is still confirmed — truncation is the discriminator, not the count", () => {
  const out = run([file([finding()])], fakeGraph(() => impact({ callerCount: 1, truncated: false })));
  assert.equal(out[0].findings.length, 1);
  assert.match(out[0].findings[0].message, /1 call site/);
});
