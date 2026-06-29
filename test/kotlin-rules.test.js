// Kotlin AST-precision rules (tree-sitter). Proves the Kotlin sql/command/deser/path rules reach the same
// precision tier as the other languages — including Kotlin's string templates (`"$x"` simple and `"${x}"`
// braced) — and that recall degrades gracefully to the cross-language regex when the grammar isn't loaded.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady } from "../dist/core/index.js";

function findings(content, ruleId) {
  return analyze({ filePath: "T.kt", content }).findings.filter((f) => f.ruleId === ruleId);
}

// --- 1. fallback: BEFORE init, the broad regex candidate carries recall ----------------------------
test("kotlin: regex candidate fires when tree-sitter is not initialized (graceful fallback)", () => {
  assert.equal(treeSitterReady("kotlin"), false, "precondition: grammar not yet loaded");
  const src = `fun m(id: String) { stmt.executeQuery("SELECT * FROM u WHERE id=" + id) }`;
  assert.ok(findings(src, "sql-injection-candidate").length >= 1, "candidate regex preserves recall without the AST");
});

test("kotlin: tree-sitter grammar loads", async () => {
  await initTreeSitter();
  assert.ok(true);
});

const precise = (name, fn) =>
  test(name, async (t) => {
    await initTreeSitter();
    if (!treeSitterReady("kotlin")) return t.skip("tree-sitter kotlin grammar unavailable");
    fn();
  });

// --- 2. SQL injection: templates, concat, def-use; placeholders & const templates safe -------------
function sqli(content) {
  const f = findings(content, "sql-injection");
  return f.length ? f[0] : null;
}

precise("kotlin sql: a simple string template ($id) into a query blocks", () => {
  const f = sqli(`fun m(id: String) { stmt.executeQuery("SELECT * FROM u WHERE id=$id") }`);
  assert.ok(f && f.blocking && f.tier === "orange");
});

precise("kotlin sql: a braced template (${expr}) into a query blocks", () => {
  assert.ok(sqli(`fun m(user: User) { stmt.executeQuery("SELECT * WHERE id=\${user.id}") }`)?.blocking);
});

precise("kotlin sql: string concatenation into a query blocks", () => {
  assert.ok(sqli(`fun m(id: String) { stmt.executeUpdate("DELETE FROM t WHERE id=" + id) }`)?.blocking);
});

precise("kotlin sql: interpolating only a const is NOT flagged", () => {
  assert.equal(sqli(`const val TABLE = "users"\nfun m() { stmt.executeQuery("SELECT * FROM $TABLE") }`), null);
});

precise("kotlin sql: a parameterized prepareStatement (?) is NOT flagged", () => {
  assert.equal(sqli(`fun m(conn: Connection) { conn.prepareStatement("SELECT * FROM u WHERE id=?") }`), null);
});

precise("kotlin sql: a cross-line query variable (val) is resolved and blocks", () => {
  const f = sqli(`fun m(id: String) { val q = "SELECT * FROM t WHERE id=$id"; stmt.execute(q) }`);
  assert.ok(f && f.blocking, "execute(q) with def-use to a template must block");
});

precise("kotlin sql: a val resolving to a static literal is NOT flagged", () => {
  assert.equal(sqli(`fun m() { val name = "fixed"; stmt.executeQuery("SELECT * FROM $name") }`), null);
});

precise("kotlin sql: a fully static query is NOT flagged", () => {
  assert.equal(sqli(`fun m() { stmt.executeQuery("SELECT * FROM t") }`), null);
});

precise("kotlin sql: a non-sink call with a template is NOT flagged", () => {
  assert.equal(sqli(`fun m(k: String) { cache.get("key_$k") }`), null);
});

// --- 3. command injection --------------------------------------------------------------------------
function cmd(content) {
  const f = findings(content, "command-injection");
  return f.length ? f[0] : null;
}

precise("kotlin cmd: Runtime.exec with a template blocks", () => {
  assert.ok(cmd(`fun m(id: String) { Runtime.getRuntime().exec("ping $id") }`)?.blocking);
});

precise("kotlin cmd: Runtime.exec with concatenation blocks", () => {
  assert.ok(cmd(`fun m(id: String) { Runtime.getRuntime().exec("ping " + id) }`)?.blocking);
});

precise("kotlin cmd: a request-tainted exec argument blocks", () => {
  assert.ok(cmd(`fun m(req: HttpServletRequest) { Runtime.getRuntime().exec(req.getParameter("cmd")) }`)?.blocking);
});

precise("kotlin cmd: a static command is NOT flagged", () => {
  assert.equal(cmd(`fun m() { Runtime.getRuntime().exec("ls -la") }`), null);
});

precise("kotlin cmd: a bare opaque command parameter is NOT flagged", () => {
  assert.equal(cmd(`fun m(cmd: String) { Runtime.getRuntime().exec(cmd) }`), null);
});

// --- 4. unsafe deserialization ---------------------------------------------------------------------
function deser(content) {
  const f = findings(content, "unsafe-deserialization");
  return f.length ? f[0] : null;
}

precise("kotlin deser: ObjectInputStream.readObject blocks", () => {
  assert.ok(deser(`fun m(ois: ObjectInputStream) { val o = ois.readObject() }`)?.blocking);
});

// --- 5. path traversal -----------------------------------------------------------------------------
function pt(content) {
  const f = findings(content, "path-traversal");
  return f.length ? f[0] : null;
}

precise("kotlin path: File(request data) is flagged (advisory)", () => {
  const f = pt(`fun m(req: HttpServletRequest) { File(req.getParameter("f")).readText() }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});

precise("kotlin path: a FilenameUtils.getName wrapper down-tiers to review", () => {
  const f = pt(`fun m(req: HttpServletRequest) { File(FilenameUtils.getName(req.getParameter("f"))).readText() }`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

precise("kotlin path: a static path is NOT flagged", () => {
  assert.equal(pt(`fun m() { File("/etc/app.conf").readText() }`), null);
});

// --- 6. diff-scoping -------------------------------------------------------------------------------
precise("kotlin: a dynamic sink on an unchanged line is not flagged", () => {
  const content = `fun m(id: String) {\n  stmt.executeQuery("SELECT * FROM u WHERE id=$id")\n}`;
  const r = analyze({ filePath: "T.kt", content, changedLines: new Set([1]) });
  assert.equal(r.findings.filter((f) => f.ruleId === "sql-injection").length, 0);
});
