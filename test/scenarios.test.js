import test from "node:test";
import assert from "node:assert/strict";

import { analyze, attachReachability, labelTrust, DEFAULT_CONFIG } from "../dist/core/index.js";

// Code-scenario depth tests: every shipped rule exercised with a true-positive and a
// false-positive guard, plus the cross-language behavior of the language-agnostic (`["*"]`)
// rules. Where a language's idiomatic injection vector is NOT caught, the gap is pinned with an
// explicit assertion + comment so the limitation is visible and regression-proof rather than
// hidden — the engine ships a JS/TS AST parser and otherwise relies on regex rules, so non-JS
// coverage is uneven by construction.

const cfg = DEFAULT_CONFIG;
const ids = (filePath, content, overrides = {}) =>
  analyze({ filePath, content, config: { ...cfg, ...overrides } }).findings.map((f) => f.ruleId);
const fired = (filePath, content, id, overrides) => ids(filePath, content, overrides).includes(id);
const finding = (filePath, content, id, overrides) =>
  analyze({ filePath, content, config: { ...cfg, ...overrides } }).findings.find((f) => f.ruleId === id);

// =====================================================================================
// Previously-untested rules — true positive + false-positive guard for each.
// =====================================================================================

test("auth-crypto: fires on JS crypto/auth APIs, quiet on arithmetic", () => {
  const f = finding("auth.js", "jwt.sign(payload, secret);\n", "auth-crypto");
  assert.ok(f, "jwt.sign should be flagged");
  assert.equal(f.tier, "orange");
  assert.equal(fired("calc.js", "const total = price + tax;\n", "auth-crypto"), false);
});

test("auth-crypto: also recognizes cross-language crypto libs (bcrypt in Python)", () => {
  assert.equal(fired("auth.py", "import bcrypt\nbcrypt.hashpw(p, salt)\n", "auth-crypto"), true);
});

test("db-schema-change: fires on ALTER/ADD COLUMN, quiet on prose mentioning 'table'", () => {
  const f = finding("m.sql", "ALTER TABLE users ADD COLUMN age int;\n", "db-schema-change");
  assert.ok(f, "ALTER TABLE should be flagged");
  assert.equal(f.tier, "orange");
  // The word 'table' in a comment must not trip the rule (requires ALTER<sp>TABLE adjacency).
  assert.equal(fired("note.js", "// we may alter the table layout in CSS later\n", "db-schema-change"), false);
});

test("db-schema-destructive vs db-schema-change: DROP is the destructive (blocking) rule", () => {
  const drop = finding("m.sql", "DROP TABLE sessions;\n", "db-schema-destructive");
  assert.ok(drop, "DROP TABLE is destructive");
  assert.equal(drop.blocking, true);
  // A plain additive ALTER is the non-blocking schema-change rule, not destructive.
  assert.equal(fired("m.sql", "ALTER TABLE users ADD COLUMN age int;\n", "db-schema-destructive"), false);
});

test("leftover-debugger: fires in JS, scoped OUT of non-JS (languages: JS)", () => {
  assert.equal(fired("a.js", "function f(){ debugger; }\n", "leftover-debugger"), true);
  // Same token in Python is a variable name, not a debugger statement → must not fire.
  assert.equal(fired("a.py", "debugger = make_debugger()\n", "leftover-debugger"), false);
});

test("debug-logging: green-tier, cross-language (JS console, Go fmt, Java System.out)", () => {
  const f = finding("a.js", "console.log(x);\n", "debug-logging");
  assert.ok(f);
  assert.equal(f.tier, "green");
  assert.equal(fired("a.go", "fmt.Println(x)\n", "debug-logging"), true);
  assert.equal(fired("A.java", "System.out.println(x);\n", "debug-logging"), true);
});

test("configured-high-impact: fires on a user-supplied orangePatterns regex", () => {
  const f = finding("flags.js", "toggle(FEATURE_FLAG_CHECKOUT);\n", "configured-high-impact",
    { orangePatterns: ["FEATURE_FLAG_\\w+"] });
  assert.ok(f, "a configured orange pattern should match");
  assert.equal(f.tier, "orange");
  // No config → no such rule.
  assert.equal(fired("flags.js", "toggle(FEATURE_FLAG_CHECKOUT);\n", "configured-high-impact"), false);
});

// =====================================================================================
// Cross-language injection — what the language-agnostic regex rules DO catch.
// =====================================================================================

test("python: string-concatenation SQL injection IS caught (blocking sql-injection)", () => {
  const f = finding("dao.py", 'cursor.execute("SELECT * FROM u WHERE id = " + uid)\n', "sql-injection");
  assert.ok(f, "Python `+` concatenation into execute() is caught");
  assert.equal(f.blocking, true);
});

test("python: dangerous exec sinks are caught (os.system, subprocess, pickle)", () => {
  assert.equal(fired("a.py", "import os\nos.system(cmd)\n", "dangerous-exec"), true);
  assert.equal(fired("a.py", "subprocess.Popen(cmd, shell=True)\n", "dangerous-exec"), true);
  assert.equal(fired("a.py", "data = pickle.loads(blob)\n", "dangerous-exec"), true);
});

test("hardcoded secrets are detected regardless of language (Python, Go)", () => {
  assert.equal(fired("conf.py", 'api_key = "sk_live_abcdef0123456789abcd"\n', "hardcoded-secret"), true);
  assert.equal(fired("conf.go", 'apiKey := "sk_live_abcdef0123456789abcd"\n', "hardcoded-secret"), true);
});

// =====================================================================================
// Cross-language injection — now CAUGHT by the advisory `sql-injection-candidate` rule (Strategy B).
// The blocking `sql-injection` rule is still JS-shaped (intentionally — widening it with looser regex
// would block on guesses), so the idiomatic non-JS vectors are caught as a YELLOW, NON-BLOCKING
// candidate instead. The candidate only becomes a blocking orange when CodeGraph confirms the sink
// is reachable from an untrusted entry point (see the Strategy-B escalation tests below). On its own
// it never blocks — the low-noise contract. The previously-pinned GAPs are now covered, not silent.
// =====================================================================================

test("candidate: python f-string SQLi → advisory candidate (not the blocking sql-injection)", () => {
  const got = ids("dao.py", 'cursor.execute(f"SELECT * FROM u WHERE id = {uid}")\n');
  assert.equal(got.includes("sql-injection"), false, "still not the JS-shaped blocking rule");
  assert.equal(got.includes("sql-injection-candidate"), true, "caught as a yellow candidate");
  const c = finding("dao.py", 'cursor.execute(f"SELECT * FROM u WHERE id = {uid}")\n', "sql-injection-candidate");
  assert.equal(c.tier, "yellow");
  assert.equal(c.blocking, false, "never blocks on its own");
});

test("candidate: python %-format and .format() SQLi → advisory candidate, never blocking", () => {
  for (const src of [
    'cursor.execute("SELECT * FROM u WHERE id = %s" % uid)\n',
    'cursor.execute("SELECT * FROM u WHERE id = {}".format(uid))\n',
  ]) {
    assert.equal(fired("a.py", src, "sql-injection"), false, "not the blocking rule");
    const c = finding("a.py", src, "sql-injection-candidate");
    assert.ok(c, "candidate fires");
    assert.equal(c.blocking, false);
  }
});

test("candidate: PHP `.`-concat and Ruby `#{}` SQLi → advisory candidate (previously missed entirely)", () => {
  const php = finding("db.php", '$db->query("SELECT * FROM u WHERE id = " . $id);\n', "sql-injection-candidate");
  assert.ok(php, "PHP concatenation now caught");
  assert.equal(php.blocking, false);
  const rb = finding("user.rb", 'User.where("name = \'#{params[:name]}\'")\n', "sql-injection-candidate");
  assert.ok(rb, "Ruby interpolation now caught");
  assert.equal(rb.blocking, false);
  // The blocking sql-injection rule still does not fire on either (no false blocks from widening).
  assert.equal(fired("db.php", '$db->query("SELECT * FROM u WHERE id = " . $id);\n', "sql-injection"), false);
  assert.equal(fired("user.rb", 'User.where("name = \'#{params[:name]}\'")\n', "sql-injection"), false);
});

test("candidate: low-noise — does NOT fire on a parameterized (placeholder) query", () => {
  assert.equal(fired("ok.py", 'cursor.execute("SELECT * FROM u WHERE id = ?", [uid])\n', "sql-injection-candidate"), false);
  assert.equal(fired("ok.py", 'cursor.execute("SELECT * FROM u WHERE id = %s", (uid,))\n', "sql-injection-candidate"), false);
});

test("candidate: never runs on JS/TS (the precise AST sql-injection rule owns those)", () => {
  const got = ids("q.js", "db.query(`SELECT * FROM u WHERE id = ${req.params.id}`)\n");
  assert.equal(got.includes("sql-injection-candidate"), false, "skipIfAst keeps it off JS");
  assert.equal(got.includes("sql-injection"), true, "the AST rule still blocks here");
});

test("dangerous-exec: now catches Go exec.Command and Ruby system (advisory orange, non-blocking)", () => {
  const go = finding("main.go", 'exec.Command("sh", "-c", userInput)\n', "dangerous-exec");
  assert.ok(go, "Go exec.Command now flagged");
  assert.equal(go.tier, "orange");
  assert.equal(go.blocking, false, "advisory until reachable");
  assert.equal(fired("r.rb", 'system("rm -rf #{path}")\n', "dangerous-exec"), true);
  assert.equal(fired("r.rb", "out = %x{ls #{dir}}\n", "dangerous-exec"), true);
});

// --- Strategy B: the candidate earns a blocking orange ONLY when reachable --------------------

test("reachability B: sql-injection-candidate blocks ONLY when reachable from a handler", () => {
  const php = '$db->query("SELECT * FROM u WHERE id = " . $id);\n';
  // No graph → yellow advisory, trust "unconfirmed" (an honest guess, not false confidence).
  const base = labelTrust([analyze({ filePath: "db.php", content: php, config: cfg })])[0];
  const bc = byId(base, "sql-injection-candidate");
  assert.equal(bc.tier, "yellow");
  assert.equal(bc.blocking, false);
  assert.equal(bc.trust, "unconfirmed");
  // Reachable from POST /users → blocking orange, trust "reachable".
  const hot = byId(withReach("db.php", php, reachableFrom("/users", "POST")), "sql-injection-candidate");
  assert.equal(hot.tier, "orange");
  assert.equal(hot.blocking, true);
  assert.equal(hot.trust, "reachable");
  // Unreachable (e.g. a helper only a CLI command calls) → stays yellow advisory.
  const cold = byId(withReach("db.php", php, unreachable), "sql-injection-candidate");
  assert.equal(cold.tier, "yellow");
  assert.equal(cold.blocking, false);
  assert.equal(cold.trust, "unreachable");
});

// =====================================================================================
// JS/TS baseline — confirm the deep AST path still fires for the canonical web-security sinks.
// =====================================================================================

test("javascript baseline: template-literal SQLi, innerHTML XSS, and path traversal all fire", () => {
  assert.equal(fired("q.js", "db.query(`SELECT * FROM u WHERE id = ${req.params.id}`)\n", "sql-injection"), true);
  assert.equal(fired("v.js", "el.innerHTML = userInput;\n", "xss-sink"), true);
  assert.equal(fired("f.js", "fs.readFile(req.query.path)\n", "path-traversal"), true);
});

// =====================================================================================
// Reachability-gated escalation (Strategy A). The broad cross-language advisory rules that
// already fire (raw-query, dangerous-exec) earn the right to BLOCK only when the community code
// graph proves a path from an untrusted entry point to the sink. Without a graph they are exactly
// as advisory as before — this is the mechanism that buys recall without unconditional regex.
// =====================================================================================

const byId = (res, id) => res.findings.find((f) => f.ruleId === id);
function withReach(filePath, content, verdict, overrides = {}) {
  const config = { ...cfg, ...overrides };
  const res = analyze({ filePath, content, config });
  const graph = { id: "fake", impact: () => null, reachability: () => verdict };
  const [out] = attachReachability([res], { cwd: "/repo", config, graph });
  return labelTrust([out])[0];
}
const reachableFrom = (route, method = "GET") => ({
  reachable: true,
  source: "codegraph",
  entryPoints: [{ name: "handler", kind: "http_handler", route, method }],
});
const unreachable = { reachable: false, source: "codegraph", entryPoints: [] };

test("reachability A: python f-string raw-query blocks ONLY when reachable from a handler", () => {
  const content = 'def get_user(uid):\n    cursor.execute(f"SELECT * FROM u WHERE id = {uid}")\n';
  // No graph → advisory only (the low-noise guarantee: never blocks unconditionally).
  const base = finding("dao.py", content, "raw-query");
  assert.equal(base.tier, "yellow");
  assert.equal(base.blocking, false);
  // Reachable from GET /user → escalates to a blocking orange, trust "reachable".
  const hot = byId(withReach("dao.py", content, reachableFrom("/user")), "raw-query");
  assert.equal(hot.tier, "orange");
  assert.equal(hot.blocking, true);
  assert.equal(hot.tierAdjusted, "escalated");
  assert.equal(hot.trust, "reachable");
  assert.match(hot.message, /GET \/user/);
  // Unreachable → stays advisory (fail-safe: no de-escalation by default), labelled "unreachable".
  const cold = byId(withReach("dao.py", content, unreachable), "raw-query");
  assert.equal(cold.tier, "yellow");
  assert.equal(cold.blocking, false);
  assert.equal(cold.trust, "unreachable");
});

test("reachability A: python os.system dangerous-exec becomes blocking when reachable", () => {
  const content = "import os\ndef handler(req):\n    os.system(req.args.get('cmd'))\n";
  // dangerous-exec is orange but NON-blocking on its own.
  const base = finding("run.py", content, "dangerous-exec");
  assert.equal(base.tier, "orange");
  assert.equal(base.blocking, false);
  const hot = byId(withReach("run.py", content, reachableFrom("/run", "POST")), "dangerous-exec");
  assert.equal(hot.blocking, true, "a reachable shell-out blocks the gate");
  assert.equal(hot.tierAdjusted, "escalated");
});
