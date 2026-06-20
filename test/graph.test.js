import test from "node:test";
import assert from "node:assert/strict";

import {
  normalizeImpact,
  normalizePrContext,
  normalizeEditContext,
  normalizeSecurity,
  normalizeTests,
  makeCodeGraphProvider,
  codeGraphAvailable,
  commandAvailable,
  getGraph,
  graphStatus,
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
  // New capability flags default on (security "auto", de-escalation off).
  assert.equal(g.prContext, true);
  assert.equal(g.relatedTests, true);
  assert.equal(g.editContext, true);
  assert.equal(g.security, "auto");
  assert.equal(g.securityDeescalate, false);
});

// --- normalizeImpact: new complexity + stale-doc fields ----------------------

test("normalizeImpact reads complexity and stale-doc flags", () => {
  const im = normalizeImpact(
    { callers: [{ file: "a.js" }], cyclomatic_complexity: 14, stale_doc: true },
    { symbol: "s", source: "codegraph" }
  );
  assert.equal(im.complexity, 14);
  assert.equal(im.staleDoc, true);
});

test("normalizeImpact omits complexity/staleDoc when absent", () => {
  const im = normalizeImpact({ callers: [] }, { symbol: "s", source: "codegraph" });
  assert.equal(im.complexity, undefined);
  assert.equal(im.staleDoc, undefined);
});

// --- normalizePrContext: whole-diff payload ----------------------------------

test("normalizePrContext maps changed functions by symbol + collects stale docs", () => {
  const raw = {
    changed_functions: [
      { name: "getUser", callers: [{ file: "a.js" }, { file: "b.js" }], suggested_reviewers: ["alice"], complexity: 12 },
      { symbol: "saveUser", caller_count: 0, untested: ["saveUser"] },
    ],
    stale_docs: [{ symbol: "getUser", note: "doc references old param" }],
    commit_hint: "refactor: tighten user API",
  };
  const pr = normalizePrContext(raw, { source: "codegraph" });
  assert.equal(pr.bySymbol.getUser.callerCount, 2);
  assert.deepEqual(pr.bySymbol.getUser.reviewers, ["alice"]);
  assert.equal(pr.bySymbol.getUser.complexity, 12);
  assert.equal(pr.bySymbol.saveUser.callerCount, 0);
  assert.equal(pr.staleDocs.length, 1);
  assert.equal(pr.staleDocs[0].symbol, "getUser");
  assert.equal(pr.commitHint, "refactor: tighten user API");
});

test("normalizePrContext tolerates alternate keys + string stale docs", () => {
  const pr = normalizePrContext(
    { symbols: [{ name: "x", direct_callers: [{ file: "y.js" }] }], staleDocs: ["docs/api.md out of date"] },
    { source: "codegraph" }
  );
  assert.equal(pr.bySymbol.x.callerCount, 1);
  assert.equal(pr.staleDocs[0].note, "docs/api.md out of date");
});

test("normalizePrContext returns null on non-object input", () => {
  assert.equal(normalizePrContext(null, { source: "codegraph" }), null);
});

// --- normalizeTests / normalizeEditContext -----------------------------------

test("normalizeTests reads a bare array or a tests-keyed object", () => {
  assert.equal(normalizeTests({ tests: [{ file: "t.spec.js" }] }).length, 1);
  assert.equal(normalizeTests([{ file: "a.test.js" }, { file: "b.test.js" }]).length, 2);
  assert.deepEqual(normalizeTests({ tests: [] }), []);
});

test("normalizeEditContext gathers callers, tests, and history", () => {
  const ec = normalizeEditContext(
    {
      callers: [{ file: "a.js", line: 3 }],
      tests: [{ file: "a.test.js" }],
      history: [{ author: "alice", message: "fix add" }, "bob — refactor"],
    },
    { source: "codegraph" }
  );
  assert.equal(ec.callers.length, 1);
  assert.equal(ec.tests.length, 1);
  assert.equal(ec.history.length, 2);
  assert.match(ec.history[0], /alice/);
  assert.equal(ec.source, "codegraph");
});

// --- normalizeSecurity: taint verdict inference ------------------------------

test("normalizeSecurity reads an explicit tainted flag + data-flow path", () => {
  const v = normalizeSecurity(
    { tainted: true, data_flow: [{ symbol: "req.query.id" }, { symbol: "db.query" }], detector: "detect_injection" },
    { source: "codegraph" }
  );
  assert.equal(v.tainted, true);
  assert.equal(v.dataFlow.length, 2);
  assert.equal(v.detector, "detect_injection");
});

test("normalizeSecurity infers tainted=true from a non-empty path when no flag given", () => {
  const v = normalizeSecurity({ taint_path: [{ symbol: "src" }, { symbol: "sink" }] }, { source: "codegraph" });
  assert.equal(v.tainted, true);
});

test("normalizeSecurity infers tainted=false from an explicit clean result", () => {
  const v = normalizeSecurity({ clean: true }, { source: "codegraph" });
  assert.equal(v.tainted, false);
  assert.deepEqual(v.dataFlow, []);
});

test("normalizeSecurity leaves tainted null when the graph is silent", () => {
  const v = normalizeSecurity({ note: "analysis incomplete" }, { source: "codegraph" });
  assert.equal(v.tainted, null);
});

// --- provider: new tool methods via injected runner --------------------------

test("provider.prContext calls pr_context and maps symbols", () => {
  let seen = null;
  const runner = (call) => {
    seen = call;
    return JSON.stringify({ changed_functions: [{ name: "f", callers: [{ file: "a.js" }] }] });
  };
  const pr = makeCodeGraphProvider("/repo", {}, runner).prContext({ cwd: "/repo", baseBranch: "main" });
  assert.equal(seen.tool, "pr_context");
  assert.equal(seen.args.baseBranch, "main");
  assert.equal(pr.bySymbol.f.callerCount, 1);
});

test("provider.relatedTests returns [] for an authoritatively untested symbol", () => {
  const runner = () => JSON.stringify({ tests: [] });
  const tests = makeCodeGraphProvider("/repo", {}, runner).relatedTests({ symbol: "s", file: "a.js", line: 1, cwd: "/repo" });
  assert.deepEqual(tests, []);
});

test("provider.editContext + security route to the right tools", () => {
  const tools = [];
  const runner = (call) => {
    tools.push(call.tool);
    if (call.tool === "get_edit_context") return JSON.stringify({ callers: [{ file: "a.js" }], tests: [], history: [] });
    if (call.tool === "security_detect_injection") return JSON.stringify({ tainted: true, data_flow: [{ symbol: "sink" }] });
    return null;
  };
  const p = makeCodeGraphProvider("/repo", {}, runner);
  assert.equal(p.editContext({ symbol: "s", file: "a.js", line: 1, cwd: "/repo" }).callers.length, 1);
  const v = p.security({ symbol: "s", file: "a.js", line: 1, cwd: "/repo", ruleId: "sql-injection", sink: "db.query(x)" });
  assert.equal(v.tainted, true);
  assert.ok(tools.includes("get_edit_context"));
  assert.ok(tools.includes("security_detect_injection"));
});

test("provider retries with the codegraph_ namespace when the bare tool yields nothing", () => {
  const seen = [];
  const runner = (call) => {
    seen.push(call.tool);
    if (call.tool === "codegraph_analyze_impact") return JSON.stringify({ callers: [{ file: "a.js" }] });
    return null; // bare name returns nothing
  };
  const im = makeCodeGraphProvider("/repo", {}, runner).impact({ symbol: "s", file: "a.js", line: 1, cwd: "/repo" });
  assert.deepEqual(seen, ["analyze_impact", "codegraph_analyze_impact"]);
  assert.equal(im.callerCount, 1);
});

test("provider.reindex returns true when the index tool confirms", () => {
  const ok = makeCodeGraphProvider("/repo", {}, () => JSON.stringify({ indexed: 42 })).reindex({ full: true });
  assert.equal(ok, true);
  const no = makeCodeGraphProvider("/repo", {}, () => null).reindex();
  assert.equal(no, false);
});

// --- commandAvailable / graphStatus ------------------------------------------

test("commandAvailable resolves an existing absolute path, rejects a bogus one", () => {
  assert.equal(commandAvailable(process.execPath), true); // node itself
  assert.equal(commandAvailable("/definitely/not/a/real/binary-xyz"), false);
  assert.equal(commandAvailable(""), false);
});

test("graphStatus reports disabled and command-resolution states without spawning", () => {
  const off = graphStatus({ graph: { enabled: false } });
  assert.equal(off.enabled, false);
  assert.equal(off.indexed, false);
  assert.match(off.reason, /disabled/i);

  // enabled + a bogus command path → enabled true, command not found. (indexed depends on the
  // host's ~/.codegraph, so we don't assert it here.)
  const on = graphStatus({ graph: { enabled: "auto", command: "/definitely/not/real-xyz" } });
  assert.equal(on.enabled, true);
  assert.equal(on.commandFound, false);
  assert.equal(typeof on.reason, "string");
});
