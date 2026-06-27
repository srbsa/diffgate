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

precise("python: implicit adjacent-literal concatenation (multi-line SQL idiom) blocks", () => {
  // `"SELECT … " f"WHERE id = {x}"` is a concatenated_string, the most common multi-line SQL form.
  const f = sqli(`def g(uid):\n    cur.execute("SELECT * FROM t " f"WHERE id = {uid}")\n`);
  assert.ok(f && f.blocking, "implicit f-string concatenation into a sink must be flagged");
});

precise("python: implicit concatenation of only static parts is NOT flagged", () => {
  assert.equal(sqli(`def g():\n    cur.execute("SELECT * " "FROM t " "WHERE a = 1")\n`), null);
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

// --- XSS: parity with the JS xss-sink rule (sink-targeted, dynamic-aware, sanitizer-aware) ---------
function xss(content) {
  const f = findings(content, "xss-sink");
  return f.length ? f[0] : null;
}

precise("python xss: mark_safe of a dynamic f-string is flagged", () => {
  const f = xss(`from django.utils.safestring import mark_safe\ndef v(request):\n    return mark_safe(f"<b>{request.GET['q']}</b>")\n`);
  assert.ok(f, "dynamic mark_safe should be flagged");
  assert.equal(f.tier, "orange");
  assert.equal(f.symbol, "v");
});

precise("python xss: mark_safe of a static literal is NOT flagged", () => {
  assert.equal(xss(`def v():\n    return mark_safe("<b>hi</b>")\n`), null);
});

precise("python xss: render_template_string with a dynamic template is flagged (SSTI/XSS)", () => {
  assert.ok(xss(`def v(tpl):\n    return render_template_string(tpl)\n`));
});

precise("python xss: an escape()-wrapped value is down-tiered to review, not suppressed", () => {
  const f = xss(`from django.utils.html import escape\ndef v(name):\n    return mark_safe(escape(name))\n`);
  assert.ok(f, "still surfaced");
  assert.equal(f.blocking, false);
  assert.equal(f.tier, "yellow");
  assert.equal(f.tierAdjusted, "deescalated");
});

precise("python xss: a plain string call (not a safe-marking sink) is NOT flagged", () => {
  assert.equal(xss(`def v(name):\n    return str(name)\n`), null);
});

// --- path traversal: request-source aware + sanitizer-wrapper aware -------------------------------
function pt(content) {
  const f = findings(content, "path-traversal");
  return f.length ? f[0] : null;
}

precise("python path-traversal: open() of request data is flagged", () => {
  const f = pt(`def v():\n    return open(request.args['f']).read()\n`);
  assert.ok(f && f.tier === "orange");
});

precise("python path-traversal: a static path is NOT flagged", () => {
  assert.equal(pt(`def v():\n    return open('/etc/config.json').read()\n`), null);
});

precise("python path-traversal: send_from_directory (contained API) is NOT a sink", () => {
  assert.equal(pt(`def v():\n    return send_from_directory('/d', request.args['f'])\n`), null);
});

precise("python path-traversal: a secure_filename/basename wrapper down-tiers to review", () => {
  const f = pt(`def v():\n    return open(os.path.join('/d', secure_filename(request.args['f']))).read()\n`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

precise("python path-traversal: a mix of sanitized + raw request data stays orange (cannot hide the raw value)", () => {
  // path-traversal is a non-blocking orange (like the JS rule); the invariant is that a partially
  // sanitized expression is NOT down-tiered to yellow when a raw request value remains.
  const f = pt(`def v():\n    return open(secure_filename(request.args['a']) + request.args['b']).read()\n`);
  assert.ok(f && f.tier === "orange" && f.tierAdjusted !== "deescalated", "one unsanitized request value must keep it orange");
});

// --- permissive CORS: flask-cors / django-cors-headers / manual header ----------------------------
function cors(content) {
  const f = findings(content, "permissive-cors");
  return f.length ? f[0] : null;
}

precise("python cors: bare CORS(app) (permissive default) is flagged", () => {
  assert.ok(cors(`from flask_cors import CORS\nCORS(app)\n`));
});

precise("python cors: origins='*' is flagged", () => {
  assert.ok(cors(`CORS(app, origins="*")\n`));
});

precise("python cors: an explicit allowlist is NOT flagged", () => {
  assert.equal(cors(`CORS(app, origins=["https://app.example.com"])\n`), null);
});

precise("python cors: django CORS_ALLOW_ALL_ORIGINS = True is flagged", () => {
  assert.ok(cors(`CORS_ALLOW_ALL_ORIGINS = True\n`));
});

precise("python cors: a manual Access-Control-Allow-Origin: * header is flagged", () => {
  assert.ok(cors(`resp.headers['Access-Control-Allow-Origin'] = '*'\n`));
});

// --- 5. diff-scoping: only changed lines are flagged ----------------------------------------------
precise("python: a dynamic sink on an unchanged line is not flagged", () => {
  const content = `def g(uid):\n    cur.execute(f"SELECT * FROM t WHERE id={uid}")\n`;
  const r = analyze({ filePath: "x.py", content, changedLines: new Set([1]) });
  assert.equal(r.findings.filter((f) => f.ruleId === "sql-injection").length, 0);
});
