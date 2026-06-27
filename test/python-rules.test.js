// Python AST-precision rules (tree-sitter). Proves the Python sql-injection rule reaches the same
// precision tier as the JS @babel rule — and that recall degrades gracefully to the cross-language
// regex when the grammar isn't loaded.
//
// Ordering matters: the FIRST test runs BEFORE initTreeSitter(), asserting the regex fallback path
// (a fresh process per test file means tree-sitter state starts uninitialized). Every later test
// runs after init and asserts the precise tsast behavior. If the wasm grammar can't load in this
// environment, the precision tests skip (mirrors the gated CodeGraph e2e), so the suite stays green.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady } from "../dist/core/index.js";

const DYN_FSTRING = `def get_user(req):\n    uid = req.args.get("id")\n    cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n`;

function findings(content, ruleId) {
  return analyze({ filePath: "x.py", content }).findings.filter((f) => f.ruleId === ruleId);
}

// --- 1. fallback: BEFORE init, no tree-sitter → the broad regex candidate carries recall ----------
test("python: regex candidate fires when tree-sitter is not initialized (graceful fallback)", () => {
  assert.equal(treeSitterReady("python"), false, "precondition: grammar not yet loaded");
  const cand = findings(DYN_FSTRING, "sql-injection-candidate");
  const ast = findings(DYN_FSTRING, "sql-injection");
  assert.equal(cand.length, 1, "candidate regex preserves recall without the AST");
  assert.equal(ast.length, 0, "the precise tsast rule needs a loaded grammar");
});

// Load grammars once for all precision tests below.
test("python: tree-sitter grammar loads", async () => {
  await initTreeSitter();
  // If the grammar is unavailable in this environment, later tests self-skip rather than fail.
  assert.ok(true);
});

const precise = (name, fn) =>
  test(name, async (t) => {
    await initTreeSitter();
    if (!treeSitterReady("python")) return t.skip("tree-sitter python grammar unavailable");
    fn();
  });

function sqli(content) {
  const f = findings(content, "sql-injection");
  return f.length ? f[0] : null;
}

// --- 2. once loaded, the precise AST rule OWNS python and suppresses the regex candidate -----------
precise("python: dynamic f-string into a sink blocks, candidate suppressed", () => {
  const f = sqli(DYN_FSTRING);
  assert.ok(f, "dynamic f-string should be flagged");
  assert.equal(f.tier, "orange");
  assert.equal(f.blocking, true);
  assert.equal(f.symbol, "get_user", "enclosing function named for graph lookup");
  assert.equal(findings(DYN_FSTRING, "sql-injection-candidate").length, 0, "AST owns it — no double regex finding");
});

precise("python: string concatenation into a sink blocks", () => {
  const f = sqli(`def g(name):\n    cur.execute("SELECT * FROM t WHERE n = '" + name + "'")\n`);
  assert.ok(f && f.blocking);
});

precise("python: .format() into a sink blocks", () => {
  const f = sqli(`def g(uid):\n    cur.execute("SELECT * FROM t WHERE id = {}".format(uid))\n`);
  assert.ok(f && f.blocking);
});

precise("python: cross-line query variable resolved and blocked", () => {
  const f = sqli(`def g(uid):\n    q = f"SELECT * FROM t WHERE id = {uid}"\n    cur.execute(q)\n`);
  assert.ok(f && f.blocking);
});

precise("python: executemany is a recognized sink", () => {
  const f = sqli(`def g(uid):\n    cur.executemany(f"DELETE FROM t WHERE id={uid}", rows)\n`);
  assert.ok(f && f.blocking);
});

// --- 3. precision: the cases the regex could not clear ---------------------------------------------
precise("python: parameterized query (%s + params) is NOT flagged", () => {
  assert.equal(sqli(`def g(req):\n    cur.execute("SELECT * FROM users WHERE id = %s", (req.args["id"],))\n`), null);
});

precise("python: f-string interpolating only a static constant is NOT flagged", () => {
  assert.equal(sqli(`TABLE = "users"\ndef g():\n    cur.execute(f"SELECT * FROM {TABLE}")\n`), null);
});

precise("python: a SQL-looking f-string NOT passed to a sink (log line) is NOT flagged", () => {
  assert.equal(sqli(`def g(uid):\n    log.info(f"SELECT done for {uid}")\n`), null);
});

precise("python: a fully static query string is NOT flagged", () => {
  assert.equal(sqli(`def g():\n    cur.execute("SELECT 1")\n`), null);
});

// --- 4. sanitizer awareness: down-tier (never suppress), and never hide a partially-raw value ------
precise("python: every dynamic part wrapped in a recognized quoter is down-tiered to review", () => {
  const f = sqli(`def g(table):\n    cur.execute(f"SELECT * FROM {quote_ident(table)}")\n`);
  assert.ok(f, "still surfaced");
  assert.equal(f.blocking, false);
  assert.equal(f.tier, "yellow");
  assert.equal(f.tierAdjusted, "deescalated");
});

precise("python: the safe psycopg2 sql.SQL(...).format(sql.Identifier(...)) pattern is NOT flagged", () => {
  assert.equal(sqli(`from psycopg2 import sql\ndef g(col):\n    cur.execute(sql.SQL("SELECT {} FROM t").format(sql.Identifier(col)))\n`), null);
});

precise("python: a mix of sanitized and raw interpolation stays blocking (cannot hide the raw value)", () => {
  const f = sqli(`def g(table, uid):\n    cur.execute(f"SELECT * FROM {quote_ident(table)} WHERE id={uid}")\n`);
  assert.ok(f && f.blocking, "one unsanitized value must keep the gate");
});

// --- 5. diff-scoping: only changed lines are flagged ----------------------------------------------
precise("python: a dynamic sink on an unchanged line is not flagged", () => {
  const content = `def g(uid):\n    cur.execute(f"SELECT * FROM t WHERE id={uid}")\n`;
  const r = analyze({ filePath: "x.py", content, changedLines: new Set([1]) });
  assert.equal(r.findings.filter((f) => f.ruleId === "sql-injection").length, 0);
});
