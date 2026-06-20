import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeImpact,
  makeCodeGraphProvider,
  codeGraphAvailable,
  getGraph,
  resolveGraphConfig,
} from "../dist/core/index.js";

// --- normalizeImpact: defensive parsing of varied graph payloads -------------

test("normalizeImpact parses a CodeGraph-style analyze_impact payload", () => {
  const raw = {
    callers: [
      { uri: "file:///repo/a.js", line: 12, symbol: "callA" },
      { uri: "/repo/b.js", line: 3 },
    ],
    suggested_reviewers: [
      { author: "anvanster", lines_owned: 3200 },
      { author: "junior", lines_owned: 40 },
    ],
    test_gaps: ["refresh_token", "revoke_session"],
    reachable: true,
  };
  const im = normalizeImpact(raw, { symbol: "doThing", source: "codegraph" });
  assert.equal(im.symbol, "doThing");
  assert.equal(im.callerCount, 2);
  assert.equal(im.callers[0].file, "/repo/a.js"); // file:// stripped
  assert.equal(im.callers[0].line, 12);
  assert.deepEqual(im.reviewers, ["anvanster", "junior"]); // sorted by lines_owned desc
  assert.equal(im.testGaps.length, 2);
  assert.equal(im.testGaps[0].symbol, "refresh_token"); // string → ref
  assert.equal(im.reachable, true);
  assert.equal(im.source, "codegraph");
});

test("normalizeImpact reads alternate key names + explicit count + string test gaps", () => {
  const raw = {
    direct_callers: [{ file: "x.js", line: 1 }],
    caller_count: 47,
    untested: "alpha, beta",
    reviewers: ["solo"],
  };
  const im = normalizeImpact(raw, { symbol: "s", source: "codegraph" });
  assert.equal(im.callerCount, 47, "explicit caller_count wins over array length");
  assert.equal(im.testGaps.length, 2, "comma string split into refs");
  assert.deepEqual(im.reviewers, ["solo"]);
});

test("normalizeImpact reads nested impact/blast_radius blocks", () => {
  const im = normalizeImpact({ impact: { callers: [{ file: "n.js" }], reachable: false } }, { symbol: "s", source: "codegraph" });
  assert.equal(im.callerCount, 1);
  assert.equal(im.reachable, false);
});

test("normalizeImpact caps callers and sets truncated", () => {
  const callers = Array.from({ length: 30 }, (_, i) => ({ file: `f${i}.js`, line: i }));
  const im = normalizeImpact({ callers }, { symbol: "s", source: "codegraph", maxCallers: 5 });
  assert.equal(im.callers.length, 5);
  assert.equal(im.callerCount, 30, "count reflects the true total, not the cap");
  assert.equal(im.truncated, true);
});

test("normalizeImpact returns null on non-object input", () => {
  assert.equal(normalizeImpact(null, { symbol: "s", source: "codegraph" }), null);
  assert.equal(normalizeImpact("nope", { symbol: "s", source: "codegraph" }), null);
});

test("normalizeImpact reachability is null when the graph did not say", () => {
  const im = normalizeImpact({ callers: [] }, { symbol: "s", source: "codegraph" });
  assert.equal(im.reachable, null);
  assert.equal(im.callerCount, 0);
});

// --- CodeGraph provider with an injected runner (no live binary) -------------

test("makeCodeGraphProvider calls analyze_impact with uri+line+symbol and parses output", () => {
  let seen = null;
  const runner = (call) => {
    seen = call;
    return JSON.stringify({ callers: [{ file: "c.js", line: 2 }], suggested_reviewers: [{ author: "ann" }] });
  };
  const provider = makeCodeGraphProvider("/repo", {}, runner);
  const im = provider.impact({ symbol: "getThing", file: "src/api.js", line: 10, cwd: "/repo" });
  assert.equal(seen.tool, "analyze_impact");
  assert.match(String(seen.args.uri), /\/repo\/src\/api\.js$/);
  assert.equal(seen.args.line, 10);
  assert.equal(seen.args.symbol, "getThing");
  assert.equal(im.callerCount, 1);
  assert.deepEqual(im.reviewers, ["ann"]);
  assert.equal(im.source, "codegraph");
});

test("CodeGraph provider tolerates leading log lines before the JSON", () => {
  const runner = () => "INFO indexing...\nWARN slow\n{ \"callers\": [{\"file\":\"z.js\"}] }\n";
  const provider = makeCodeGraphProvider("/repo", {}, runner);
  const im = provider.impact({ symbol: "s", file: "a.js", line: 1, cwd: "/repo" });
  assert.equal(im.callerCount, 1);
});

test("CodeGraph provider returns null when the runner fails", () => {
  const provider = makeCodeGraphProvider("/repo", {}, () => null);
  assert.equal(provider.impact({ symbol: "s", file: "a.js", line: 1, cwd: "/repo" }), null);
});

// --- getGraph detection / disabling ------------------------------------------

test("getGraph returns null when disabled or mode=off", () => {
  assert.equal(getGraph("/repo", { graph: { enabled: false } }), null);
  assert.equal(getGraph("/repo", { graph: { mode: "off" } }), null);
});

test("getGraph returns an injected provider verbatim", () => {
  const fake = { id: "fake", impact: () => null };
  assert.equal(getGraph("/repo", {}, { provider: fake }), fake);
});

test("getGraph honors an explicit null provider (host opts out)", () => {
  assert.equal(getGraph("/repo", {}, { provider: null }), null);
});

test("codeGraphAvailable is false when graphing is turned off", () => {
  assert.equal(codeGraphAvailable({ mode: "off" }), false);
  assert.equal(codeGraphAvailable({ enabled: false }), false);
});

test("resolveGraphConfig fills defaults and applies overrides", () => {
  const g = resolveGraphConfig({ graph: { escalateThreshold: 5 } });
  assert.equal(g.provider, "codegraph");
  assert.equal(g.escalateThreshold, 5);
  assert.equal(g.maxCallers, 20);
});
