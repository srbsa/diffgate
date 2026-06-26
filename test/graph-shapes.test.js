// Regression guard: the graph normalizers parse the REAL community-CodeGraph (v0.18.6) tool
// output, not the hand-authored flat shapes the unit fixtures originally assumed. Captured live
// against a Flask fixture in test/fixtures/codegraph-real.json. Before this guard, the real
// envelope (name nested under `symbol.name`, entry kind under `entry_type`, analyze_impact callers
// under `impacted`) silently produced "[object Object]" symbols and callerCount 0 — which broke
// reachability (false escalation) and blast radius (false de-escalation that hides breaking changes).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  normalizeEntryPoints, normalizeAncestors, normalizeImpact, normalizePrContext,
  makeCodeGraphProvider,
} from "../dist/core/index.js";

const REAL = JSON.parse(readFileSync(new URL("./fixtures/codegraph-real.json", import.meta.url), "utf-8"));

const noObjectObject = (refs) =>
  assert.ok(refs.every((r) => !/\[object Object\]/.test(r.symbol || "") && !/\[object Object\]/.test(r.file || "")),
    "no ref should stringify a nested object to '[object Object]'");

// --- find_entry_points (real: name under symbol.name, kind under entry_type) ---

test("normalizeEntryPoints: reads nested symbol.name + entry_type + route/method/file", () => {
  const eps = normalizeEntryPoints(REAL.find_entry_points_http_handler);
  assert.equal(eps.length, 1);
  const ep = eps[0];
  assert.equal(ep.name, "user_route", "name comes from symbol.name, not '[object Object]'");
  assert.equal(ep.kind, "http_handler", "kind comes from entry_type, not symbol.kind ('Function')");
  assert.equal(ep.route, "/user/<user_id>");
  assert.equal(ep.method, "GET");
  assert.match(ep.file, /app\.py$/, "file comes from symbol.location.file");
});

// --- get_callers / traverse_graph (real: caller under caller.symbol.name) ---

test("normalizeAncestors: reads nested caller symbol.name from get_callers", () => {
  const a = normalizeAncestors(REAL.get_callers_reachable);
  noObjectObject(a);
  assert.deepEqual(a.map((r) => r.symbol), ["user_route"]);
  assert.match(a[0].file, /app\.py$/, "file from call_site");
});

test("normalizeAncestors: reads nested symbol.name from traverse_graph (top-level array)", () => {
  const a = normalizeAncestors(REAL.traverse_graph_incoming);
  noObjectObject(a);
  assert.deepEqual(a.map((r) => r.symbol), ["user_route"]);
});

// --- analyze_impact (real: callers under `impacted`, count under direct_impacted) ---

test("normalizeImpact: reads impacted[] + direct_impacted (not 0)", () => {
  const im = normalizeImpact(REAL.analyze_impact, { symbol: "getGraph", source: "codegraph" });
  assert.ok(im);
  assert.equal(im.callerCount, 7, "callerCount from direct_impacted — NOT 0 (would falsely de-escalate)");
  noObjectObject(im.callers);
  const names = im.callers.map((c) => c.symbol);
  assert.ok(names.includes("analyzeDocument") && names.includes("handleAnalyze"), "named impacted sites parsed");
});

test("normalizeImpact: a real change is NOT seen as zero-caller (de-escalation safety)", () => {
  const im = normalizeImpact(REAL.analyze_impact, { symbol: "getGraph", source: "codegraph" });
  assert.ok(im.callerCount > 0, "a 7-caller change must never read as 0 — impact.ts de-escalates orange→yellow at 0");
});

// --- pr_context (real: per-symbol under function_details with a numeric caller count) ---

test("normalizePrContext: per-symbol from function_details with numeric caller counts", () => {
  const pr = normalizePrContext(REAL.pr_context, { source: "codegraph" });
  assert.ok(pr);
  const rw = pr.bySymbol["refreshWorkspace"];
  assert.ok(rw, "refreshWorkspace parsed from function_details");
  assert.equal(rw.callerCount, 3, "numeric `callers` field used as the count");
  assert.equal(pr.commitHint, "feat(src): <describe the change>");
});

// --- end-to-end provider.reachability() against the REAL runner shapes ----------

function runnerFromReal(map) {
  return ({ tool }) => {
    const key = tool.replace(/^codegraph_/, "");
    const v = map[key];
    return v === undefined ? null : JSON.stringify(v);
  };
}

test("provider.reachability: REAL shapes — sink reachable from its HTTP handler", () => {
  const provider = makeCodeGraphProvider("/tmp/flaskfix", {}, runnerFromReal({
    find_entry_points: REAL.find_entry_points_http_handler,
    get_callers: REAL.get_callers_reachable, // symbol_name: get_user, caller: user_route
  }));
  const v = provider.reachability({ symbol: "", file: "/tmp/flaskfix/app.py", line: 10, cwd: "/tmp/flaskfix" });
  assert.ok(v, "verdict produced");
  assert.equal(v.reachable, true, "get_user is reachable from user_route (http_handler)");
  assert.equal(v.entryPoints[0].name, "user_route");
  assert.equal(v.entryPoints[0].method, "GET");
});

test("provider.reachability: REAL shapes — helper reached only from a non-handler is NOT reachable", () => {
  const provider = makeCodeGraphProvider("/tmp/flaskfix", {}, runnerFromReal({
    find_entry_points: REAL.find_entry_points_http_handler, // only user_route is a handler
    get_callers: REAL.get_callers_unreachable,              // symbol_name: lookup_helper, caller: admin_cli
  }));
  const v = provider.reachability({ symbol: "", file: "/tmp/flaskfix/app.py", line: 16, cwd: "/tmp/flaskfix" });
  assert.ok(v, "verdict produced (not null — we know the handlers and the callers)");
  assert.equal(v.reachable, false, "admin_cli is not an http/event handler → unreachable, not a false escalation");
  assert.deepEqual(v.entryPoints, []);
});

test("provider.reachability: REAL shapes — enclosing resolved from get_callers symbol_name (no get_symbol_info)", () => {
  let symbolInfoCalls = 0;
  const runner = ({ tool }) => {
    const key = tool.replace(/^codegraph_/, "");
    if (key === "get_symbol_info" || key === "get_detailed_symbol") symbolInfoCalls++;
    const map = {
      find_entry_points: REAL.find_entry_points_http_handler,
      get_callers: REAL.get_callers_reachable,
    };
    const v = map[key];
    return v === undefined ? null : JSON.stringify(v);
  };
  const provider = makeCodeGraphProvider("/tmp/flaskfix", {}, runner);
  const v = provider.reachability({ symbol: "", file: "/tmp/flaskfix/app.py", line: 10, cwd: "/tmp/flaskfix" });
  assert.equal(v.reachable, true);
  assert.equal(symbolInfoCalls, 0, "enclosing came from get_callers' symbol_name — no extra round-trip");
});
