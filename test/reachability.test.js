import test from "node:test";
import assert from "node:assert/strict";

import {
  analyze, attachReachability, attachSecurity, labelTrust,
  REACHABILITY_RULES, makeCodeGraphProvider, DEFAULT_CONFIG,
} from "../dist/core/index.js";

const cfg = DEFAULT_CONFIG;
const find = (res, ruleId) => res.findings.find((f) => f.ruleId === ruleId);

// A Python f-string SQLi: today this fires ONLY the yellow, non-blocking raw-query advisory
// (the blocking sql-injection rule is JS-shaped — a pinned cross-language gap). It is the exact
// case reachability is meant to escalate without widening the base regex.
function rawQueryResult() {
  return analyze({
    filePath: "dao.py",
    content: 'def get_user(uid):\n    cursor.execute(f"SELECT * FROM u WHERE id = {uid}")\n',
    config: cfg,
  });
}

// A Python shell-out: dangerous-exec fires at orange (non-blocking) — used for de-escalation cases.
function execResult() {
  return analyze({
    filePath: "run.py",
    content: "import os\ndef handler(req):\n    os.system(req.args.get('cmd'))\n",
    config: cfg,
  });
}

// A JS template-literal SQLi → the blocking sql-injection rule (a SECURITY_RULE).
function sqlInjectionResult() {
  return analyze({
    filePath: "db.js",
    content: "function q(req){ return db.query(`SELECT * FROM u WHERE id = ${req.query.id}`); }\n",
    config: cfg,
  });
}

function reachGraph(verdict) {
  let calls = 0;
  return {
    graph: { id: "fake", impact: () => null, reachability: () => { calls++; return verdict; } },
    calls: () => calls,
  };
}

const REACHABLE = {
  reachable: true,
  source: "codegraph",
  entryPoints: [{ name: "get_user", kind: "http_handler", route: "/user", method: "GET", file: "routes.py" }],
  path: [{ symbol: "get_user", file: "dao.py", line: 2 }, { symbol: "get_user" }],
  depth: 0,
};
const UNREACHABLE = { reachable: false, source: "codegraph", entryPoints: [] };

// --- attachReachability with an injected fake graph -------------------------

test("REACHABILITY_RULES routes the broad advisory rules + the security rules", () => {
  assert.ok(REACHABILITY_RULES.has("raw-query"));
  assert.ok(REACHABILITY_RULES.has("dangerous-exec"));
  assert.ok(REACHABILITY_RULES.has("sql-injection"), "inherits the SECURITY_RULES set");
  assert.ok(REACHABILITY_RULES.has("sql-injection-candidate"));
  assert.ok(!REACHABILITY_RULES.has("todo-marker"));
});

test("attachReachability: reachable escalates a yellow advisory to a blocking orange", () => {
  const res = rawQueryResult();
  const rq = find(res, "raw-query");
  assert.ok(rq, "precondition: raw-query fired");
  assert.equal(rq.tier, "yellow");
  assert.equal(rq.blocking, false);

  const g = reachGraph(REACHABLE);
  const [out] = attachReachability([res], { cwd: "/repo", config: cfg, graph: g.graph });
  const f = find(out, "raw-query");
  assert.equal(f.tier, "orange");
  assert.equal(f.blocking, true);
  assert.equal(f.tierAdjusted, "escalated");
  assert.equal(f.reachability.reachable, true);
  assert.deepEqual(f.reachability.path, REACHABLE.path);
  assert.match(f.message, /Reachable/);
  assert.match(f.message, /GET \/user/);
  // result-level tier/blocking recomputed
  assert.equal(out.tier, "orange");
  assert.equal(out.blocking, true);
});

test("attachReachability + labelTrust: reachable finding is trust 'reachable'", () => {
  const g = reachGraph(REACHABLE);
  let [out] = attachReachability([rawQueryResult()], { cwd: "/repo", config: cfg, graph: g.graph });
  [out] = labelTrust([out]);
  assert.equal(find(out, "raw-query").trust, "reachable");
});

test("attachReachability: unreachable does NOT de-escalate by default, but labels 'unreachable'", () => {
  const g = reachGraph(UNREACHABLE);
  let [out] = attachReachability([execResult()], { cwd: "/repo", config: cfg, graph: g.graph });
  const f = find(out, "dangerous-exec");
  assert.equal(f.tier, "orange", "fail-safe: not weakened unless opted in");
  assert.equal(f.blocking, false, "dangerous-exec default blocking unchanged");
  assert.equal(f.tierAdjusted, undefined);
  assert.equal(f.reachability.reachable, false);
  [out] = labelTrust([out]);
  assert.equal(find(out, "dangerous-exec").trust, "unreachable");
});

test("attachReachability: unreachable de-escalates when reachabilityDeescalate is enabled", () => {
  const config = { ...cfg, graph: { ...cfg.graph, reachabilityDeescalate: true } };
  const g = reachGraph(UNREACHABLE);
  const [out] = attachReachability([execResult()], { cwd: "/repo", config, graph: g.graph });
  const f = find(out, "dangerous-exec");
  assert.equal(f.tier, "yellow", "opted-in: proven-unreachable sink down-tiers");
  assert.equal(f.blocking, false);
  assert.equal(f.tierAdjusted, "deescalated");
  assert.equal(out.tier, "yellow");
});

test("attachReachability: de-escalation respects a pinned rule tier", () => {
  const config = { ...cfg, graph: { ...cfg.graph, reachabilityDeescalate: true }, rules: { "dangerous-exec": { tier: "orange" } } };
  const g = reachGraph(UNREACHABLE);
  const [out] = attachReachability([execResult()], { cwd: "/repo", config, graph: g.graph });
  assert.equal(find(out, "dangerous-exec").tier, "orange", "pin wins over de-escalation");
});

test("attachReachability: a pinned rule is NOT escalated by a reachable verdict (pin wins)", () => {
  const config = { ...cfg, rules: { "dangerous-exec": { tier: "orange" } } };
  const g = reachGraph({ ...REACHABLE, entryPoints: [{ name: "handler", kind: "http_handler", route: "/x", method: "POST" }] });
  const [out] = attachReachability([execResult()], { cwd: "/repo", config, graph: g.graph });
  const f = find(out, "dangerous-exec");
  assert.equal(f.blocking, false, "not forced to blocking — rule is pinned");
  assert.equal(f.tierAdjusted, undefined);
  assert.ok(f.reachability, "verdict still recorded for the reviewer");
  assert.match(f.message, /Reachable/, "trace still attached");
});

test("attachReachability: null verdict (graph unsure) leaves the finding untouched", () => {
  const res = rawQueryResult();
  const g = reachGraph(null);
  const [out] = attachReachability([res], { cwd: "/repo", config: cfg, graph: g.graph });
  assert.equal(out, res, "same reference — untouched");
  assert.equal(find(out, "raw-query").reachability, undefined);
});

test("attachReachability: provider without reachability() is a pure no-op", () => {
  const res = rawQueryResult();
  const out = attachReachability([res], { cwd: "/repo", config: cfg, graph: { id: "fake", impact: () => null } });
  assert.equal(out[0], res);
});

test("attachReachability: null graph is a pure no-op", () => {
  const res = rawQueryResult();
  const out = attachReachability([res], { cwd: "/repo", config: cfg, graph: null });
  assert.equal(out[0], res);
});

test("attachReachability: graph.reachability=false disables the pass", () => {
  const config = { ...cfg, graph: { ...cfg.graph, reachability: false } };
  const g = reachGraph(REACHABLE);
  const [out] = attachReachability([rawQueryResult()], { cwd: "/repo", config, graph: g.graph });
  assert.equal(find(out, "raw-query").reachability, undefined);
  assert.equal(g.calls(), 0, "no reachability queries when disabled");
});

test("attachReachability: only queries REACHABILITY_RULES findings", () => {
  const res = analyze({ filePath: "x.js", content: "// TODO: cleanup\n", config: cfg });
  const g = reachGraph(REACHABLE);
  attachReachability([res], { cwd: "/repo", config: cfg, graph: g.graph });
  assert.equal(g.calls(), 0);
});

test("attachReachability: one reachability call per finding (cached)", () => {
  const g = reachGraph(REACHABLE);
  attachReachability([rawQueryResult()], { cwd: "/repo", config: cfg, graph: g.graph });
  assert.equal(g.calls(), 1);
});

test("attachReachability: a Pro security verdict wins — reachability is not consulted", () => {
  const res = sqlInjectionResult(); // db.query(...) fires both sql-injection AND raw-query
  // Simulate a Pro taint pass having already ruled on every injection-class sink in the file.
  for (const f of res.findings) f.security = { tainted: false, dataFlow: [], source: "codegraph" };
  const g = reachGraph(REACHABLE);
  const [out] = attachReachability([res], { cwd: "/repo", config: cfg, graph: g.graph });
  assert.equal(g.calls(), 0, "Pro verdict is authoritative");
  assert.equal(find(out, "sql-injection").reachability, undefined);
});

test("labelTrust: a Pro 'cleared' verdict still wins over a reachable graph", () => {
  const res = sqlInjectionResult();
  const g = secGraph({ tainted: false, dataFlow: [], source: "codegraph" });
  let [out] = attachSecurity([res], { cwd: "/repo", config: cfg, graph: g });
  // Even if a (stale) reachable verdict were present, security tainted=false maps to 'cleared'.
  find(out, "sql-injection").reachability = { reachable: true, source: "codegraph", entryPoints: [] };
  [out] = labelTrust([out]);
  assert.equal(find(out, "sql-injection").trust, "cleared");
});

function secGraph(verdict) {
  return { id: "fake", impact: () => null, security: () => verdict };
}

// --- provider reachability() with a canned CodeGraph runner -----------------

function runnerFrom(map) {
  return ({ tool }) => {
    const key = tool.replace(/^codegraph_/, "");
    const v = map[key];
    return v === undefined ? null : typeof v === "string" ? v : JSON.stringify(v);
  };
}

test("provider.reachability: links a sink to its HTTP handler (reachable)", () => {
  const provider = makeCodeGraphProvider("/app", {}, runnerFrom({
    find_entry_points: { entry_points: [{ name: "user_route", type: "http_handler", method: "get", route: "/user", file: "routes.py" }] },
    get_callers: { callers: [{ symbol: "user_route", file: "routes.py" }] },
  }));
  const v = provider.reachability({ symbol: "get_user", file: "/app/dao.py", line: 10, cwd: "/app" });
  assert.ok(v);
  assert.equal(v.reachable, true);
  assert.equal(v.source, "codegraph");
  assert.equal(v.entryPoints[0].name, "user_route");
  assert.equal(v.entryPoints[0].route, "/user");
  assert.equal(v.entryPoints[0].method, "GET", "method upper-cased");
  assert.ok(Array.isArray(v.path) && v.path.length >= 2);
});

test("provider.reachability: a sink the handler can't reach is 'false' (not unknown)", () => {
  const provider = makeCodeGraphProvider("/app", {}, runnerFrom({
    find_entry_points: { entry_points: [{ name: "user_route", type: "http_handler", method: "GET", route: "/user" }] },
    get_callers: { callers: [{ symbol: "cron_job" }] },
  }));
  const v = provider.reachability({ symbol: "helper", file: "/app/x.py", line: 3, cwd: "/app" });
  assert.ok(v);
  assert.equal(v.reachable, false);
  assert.deepEqual(v.entryPoints, []);
});

test("provider.reachability: respects untrustedEntryKinds (CLI-only entry → unknown, not unreachable)", () => {
  const provider = makeCodeGraphProvider("/app", {}, runnerFrom({
    find_entry_points: { entry_points: [{ name: "cli_main", type: "cli_command" }] },
    get_callers: { callers: [{ symbol: "cli_main" }] },
  }));
  const v = provider.reachability({ symbol: "helper", file: "/app/x.py", line: 3, cwd: "/app", untrustedKinds: ["http_handler", "event_handler"] });
  assert.equal(v, null, "no untrusted entry points the index knows of → unknown (fail-safe), never a false 'unreachable'");
});

test("provider.reachability: resolves the enclosing symbol for a pattern-only finding (no symbol)", () => {
  const provider = makeCodeGraphProvider("/app", {}, runnerFrom({
    find_entry_points: { entry_points: [{ name: "user_route", type: "http_handler", route: "/u", method: "GET" }] },
    get_symbol_info: { symbol: "get_user" },
    get_callers: { callers: [{ symbol: "user_route" }] },
  }));
  const v = provider.reachability({ symbol: "", file: "/app/dao.py", line: 10, cwd: "/app" });
  assert.ok(v);
  assert.equal(v.reachable, true);
});

test("provider.reachability: sink written directly in the handler body (depth 0)", () => {
  const provider = makeCodeGraphProvider("/app", {}, runnerFrom({
    find_entry_points: { entry_points: [{ name: "user_route", type: "http_handler", route: "/u", method: "GET" }] },
    get_callers: { callers: [] }, // the handler has no callers of its own; the sink is inside it
  }));
  const v = provider.reachability({ symbol: "user_route", file: "/app/app.py", line: 5, cwd: "/app" });
  assert.ok(v);
  assert.equal(v.reachable, true);
  assert.equal(v.depth, 0);
});

test("provider.reachability: fail-safe — no entry points / no callers / garbage → null", () => {
  assert.equal(makeCodeGraphProvider("/app", {}, runnerFrom({})).reachability({ symbol: "x", file: "/a.py", line: 1, cwd: "/app" }), null);
  const noCallers = makeCodeGraphProvider("/app", {}, runnerFrom({
    find_entry_points: { entry_points: [{ name: "r", type: "http_handler" }] },
  }));
  assert.equal(noCallers.reachability({ symbol: "x", file: "/a.py", line: 1, cwd: "/app" }), null, "entry points but unanswerable caller walk → unknown");
});

test("provider.reachability: find_entry_points is fetched once per provider (memoized)", () => {
  let epCalls = 0;
  const runner = ({ tool }) => {
    const key = tool.replace(/^codegraph_/, "");
    if (key === "find_entry_points") epCalls++;
    const map = {
      find_entry_points: { entry_points: [{ name: "user_route", type: "http_handler", route: "/u", method: "GET" }] },
      get_callers: { callers: [{ symbol: "user_route" }] },
    };
    const v = map[key];
    return v === undefined ? null : JSON.stringify(v);
  };
  const provider = makeCodeGraphProvider("/app", {}, runner);
  provider.reachability({ symbol: "get_user", file: "/app/a.py", line: 1, cwd: "/app" });
  provider.reachability({ symbol: "get_post", file: "/app/b.py", line: 2, cwd: "/app" });
  assert.equal(epCalls, 1, "entry-point discovery memoized across findings");
});
