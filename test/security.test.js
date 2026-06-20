import test from "node:test";
import assert from "node:assert/strict";

import { analyze, attachSecurity, SECURITY_RULES, DEFAULT_CONFIG } from "../dist/core/index.js";

const cfg = DEFAULT_CONFIG;
const find = (res, ruleId) => res.findings.find((f) => f.ruleId === ruleId);

// A diff with a clear SQL-injection sink on a changed line.
function sqlInjectionResult() {
  return analyze({
    filePath: "db.js",
    content: "function q(req){ return db.query(`SELECT * FROM u WHERE id = ${req.query.id}`); }\n",
    config: cfg,
  });
}

function secGraph(verdict) {
  let calls = 0;
  return {
    graph: {
      id: "fake",
      impact: () => null,
      security: () => { calls++; return verdict; },
    },
    calls: () => calls,
  };
}

test("SECURITY_RULES covers the injection-class rules", () => {
  assert.ok(SECURITY_RULES.has("sql-injection"));
  assert.ok(SECURITY_RULES.has("xss-sink"));
  assert.ok(!SECURITY_RULES.has("todo-marker"));
});

test("attachSecurity: a confirmed taint path enriches the message, keeps the gate", () => {
  const res = sqlInjectionResult();
  assert.ok(find(res, "sql-injection"), "precondition: sql-injection fired");
  const g = secGraph({ tainted: true, dataFlow: [{ symbol: "req.query.id" }, { symbol: "db.query" }], source: "codegraph" });
  const [out] = attachSecurity([res], { cwd: "/repo", config: cfg, graph: g.graph });
  const f = find(out, "sql-injection");
  assert.equal(f.tier, "orange", "stays orange");
  assert.equal(f.blocking, true);
  assert.equal(f.security.tainted, true);
  assert.match(f.message, /Taint path/);
  assert.match(f.message, /req\.query\.id → db\.query/);
});

test("attachSecurity: tainted=false does NOT de-escalate by default (enrich-only)", () => {
  const res = sqlInjectionResult();
  const g = secGraph({ tainted: false, dataFlow: [], source: "codegraph" });
  const [out] = attachSecurity([res], { cwd: "/repo", config: cfg, graph: g.graph });
  const f = find(out, "sql-injection");
  assert.equal(f.tier, "orange", "security findings are not weakened unless opted in");
  assert.equal(f.blocking, true);
  assert.equal(f.tierAdjusted, undefined);
  assert.equal(f.security.tainted, false, "verdict still recorded for context");
});

test("attachSecurity: tainted=false de-escalates when securityDeescalate is enabled", () => {
  const res = sqlInjectionResult();
  const config = { ...cfg, graph: { ...cfg.graph, securityDeescalate: true } };
  const g = secGraph({ tainted: false, dataFlow: [], source: "codegraph" });
  const [out] = attachSecurity([res], { cwd: "/repo", config, graph: g.graph });
  const f = find(out, "sql-injection");
  assert.equal(f.tier, "yellow", "opted-in: proven-clean sink down-tiers");
  assert.equal(f.blocking, false, "no longer blocks the gate");
  assert.equal(f.tierAdjusted, "deescalated");
  assert.equal(out.tier, "yellow");
});

test("attachSecurity: de-escalation respects a pinned rule tier", () => {
  const res = sqlInjectionResult();
  const config = { ...cfg, graph: { ...cfg.graph, securityDeescalate: true }, rules: { "sql-injection": { tier: "orange" } } };
  const g = secGraph({ tainted: false, dataFlow: [], source: "codegraph" });
  const [out] = attachSecurity([res], { cwd: "/repo", config, graph: g.graph });
  assert.equal(find(out, "sql-injection").tier, "orange", "pinned tier wins over de-escalation");
});

test("attachSecurity: a non-authoritative source never de-escalates", () => {
  const res = sqlInjectionResult();
  const config = { ...cfg, graph: { ...cfg.graph, securityDeescalate: true } };
  const g = secGraph({ tainted: false, dataFlow: [], source: "grep" });
  const [out] = attachSecurity([res], { cwd: "/repo", config, graph: g.graph });
  assert.equal(find(out, "sql-injection").tier, "orange");
});

test("attachSecurity: graph.security=false disables the pass", () => {
  const res = sqlInjectionResult();
  const config = { ...cfg, graph: { ...cfg.graph, security: false } };
  const g = secGraph({ tainted: true, dataFlow: [{ symbol: "x" }], source: "codegraph" });
  const [out] = attachSecurity([res], { cwd: "/repo", config, graph: g.graph });
  assert.equal(find(out, "sql-injection").security, undefined);
  assert.equal(g.calls(), 0, "no security queries when disabled");
});

test("attachSecurity: provider without a security() capability is a no-op", () => {
  const res = sqlInjectionResult();
  const out = attachSecurity([res], { cwd: "/repo", config: cfg, graph: { id: "fake", impact: () => null } });
  assert.equal(out[0], res, "same reference — untouched");
});

test("attachSecurity: null graph is a pure no-op", () => {
  const res = sqlInjectionResult();
  const out = attachSecurity([res], { cwd: "/repo", config: cfg, graph: null });
  assert.equal(out[0], res);
});

test("attachSecurity: only queries injection-class findings", () => {
  // A plain todo-marker is not security-relevant.
  const res = analyze({ filePath: "x.js", content: "// TODO: cleanup\n", config: cfg });
  const g = secGraph({ tainted: true, dataFlow: [], source: "codegraph" });
  attachSecurity([res], { cwd: "/repo", config: cfg, graph: g.graph });
  assert.equal(g.calls(), 0);
});

test("attachSecurity: null verdict (graph unsure) leaves the finding untouched", () => {
  const res = sqlInjectionResult();
  const g = secGraph(null);
  const [out] = attachSecurity([res], { cwd: "/repo", config: cfg, graph: g.graph });
  assert.equal(find(out, "sql-injection").security, undefined);
});
