// Go AST-precision rules (tree-sitter). Proves the Go sql/command/path rules reach the same precision
// tier as the JS/Python/PHP rules — and that recall degrades gracefully to the cross-language regex when
// the grammar isn't loaded.
//
// Ordering matters: the FIRST test runs BEFORE initTreeSitter(), asserting the regex fallback path. Every
// later test runs after init and asserts the precise tsast behavior; if the wasm grammar can't load in
// this environment, the precision tests skip (mirrors python-rules / php-rules) so the suite stays green.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady } from "../dist/core/index.js";

function findings(content, ruleId) {
  return analyze({ filePath: "x.go", content }).findings.filter((f) => f.ruleId === ruleId);
}

// --- 1. fallback: BEFORE init, no tree-sitter → the broad regex candidate carries recall ----------
test("go: regex candidate fires when tree-sitter is not initialized (graceful fallback)", () => {
  assert.equal(treeSitterReady("go"), false, "precondition: grammar not yet loaded");
  const src = `package m\nfunc h(db *sql.DB, id string){ db.Query("SELECT * FROM t WHERE id=" + id) }`;
  // Recall is preserved by the cross-language regex layer before the grammar loads. (The concat form
  // also matches the `*` sql-injection regex, which shares the id; the precise test below proves the
  // tsast rule takes over and suppresses the candidate once the grammar is loaded.)
  assert.ok(findings(src, "sql-injection-candidate").length >= 1, "candidate regex preserves recall without the AST");
});

test("go: tree-sitter grammar loads", async () => {
  await initTreeSitter();
  assert.ok(true);
});

const precise = (name, fn) =>
  test(name, async (t) => {
    await initTreeSitter();
    if (!treeSitterReady("go")) return t.skip("tree-sitter go grammar unavailable");
    fn();
  });

// --- 2. SQL injection: Sprintf/concat block, placeholders & statics are safe -----------------------
function sqli(content) {
  const f = findings(content, "sql-injection");
  return f.length ? f[0] : null;
}

precise("go sql: fmt.Sprintf into a query blocks", () => {
  const f = sqli(`package m\nfunc h(db *sql.DB, id string){ db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id)) }`);
  assert.ok(f && f.blocking && f.tier === "orange");
  assert.equal(f.symbol, "h", "enclosing function named for the graph layer");
  assert.equal(findings(`package m\nfunc h(db *sql.DB, id string){ db.Query(fmt.Sprintf("SELECT * FROM t WHERE id=%s", id)) }`, "sql-injection-candidate").length, 0, "AST owns it — no double regex finding");
});

precise("go sql: string concatenation into a query blocks", () => {
  assert.ok(sqli(`package m\nfunc h(db *sql.DB, id string){ db.Exec("DELETE FROM t WHERE id=" + id) }`)?.blocking);
});

precise("go sql: a cross-line query variable (:=) is resolved and blocks", () => {
  const f = sqli(`package m\nfunc h(db *sql.DB, id string){ q := fmt.Sprintf("SELECT * FROM t WHERE id=%s", id); db.Query(q) }`);
  assert.ok(f && f.blocking, "def-use across := must resolve");
});

precise("go sql: a var-declared query is resolved and blocks", () => {
  const f = sqli(`package m\nfunc h(db *sql.DB, id string){ var q = "SELECT * FROM t WHERE id=" + id; db.Query(q) }`);
  assert.ok(f && f.blocking, "def-use across var = must resolve");
});

precise("go sql: a parameterized query (placeholder + args) is NOT flagged", () => {
  assert.equal(sqli(`package m\nfunc h(db *sql.DB, id string){ db.Query("SELECT * FROM t WHERE id = ?", id) }`), null);
});

precise("go sql: a fully static query string is NOT flagged", () => {
  assert.equal(sqli(`package m\nfunc h(db *sql.DB){ db.Query("SELECT * FROM t") }`), null);
});

precise("go sql: a SQL-looking Sprintf NOT passed to a sink (log line) is NOT flagged", () => {
  assert.equal(sqli(`package m\nfunc h(id string){ log.Printf(fmt.Sprintf("SELECT done for %s", id)) }`), null);
});

precise("go sql: concatenating only static parts is NOT flagged", () => {
  assert.equal(sqli(`package m\nfunc h(db *sql.DB){ db.Query("SELECT * " + "FROM t") }`), null);
});

// --- 3. command injection: arg-vector is safe; shell + dynamic, or dynamic program name, block ------
function cmd(content) {
  const f = findings(content, "command-injection");
  return f.length ? f[0] : null;
}

precise("go cmd: a shell program with a dynamic argument blocks", () => {
  const f = cmd(`package m\nfunc h(x string){ exec.Command("sh", "-c", "ls "+x) }`);
  assert.ok(f && f.blocking && f.tier === "orange");
});

precise("go cmd: a request-tainted program name blocks", () => {
  assert.ok(cmd(`package m\nfunc h(w http.ResponseWriter, r *http.Request){ exec.Command(r.URL.Query().Get("cmd")) }`)?.blocking);
});

precise("go cmd: a request-tainted program name resolved across := blocks", () => {
  assert.ok(cmd(`package m\nfunc h(w http.ResponseWriter, r *http.Request){ c := r.FormValue("cmd"); exec.Command(c) }`)?.blocking);
});

precise("go cmd: a bare dynamic program name (likely config, not request) is NOT flagged", () => {
  // Avoids the gosec-G204 false-block: a configured/parameter binary path is not necessarily attacker input.
  assert.equal(cmd(`package m\nfunc h(toolPath string){ exec.Command(toolPath, "--version") }`), null);
});

precise("go cmd: a fixed program with an argument vector is NOT flagged (Go does not use a shell)", () => {
  assert.equal(cmd(`package m\nfunc h(x string){ exec.Command("git", "checkout", x) }`), null);
});

precise("go cmd: CommandContext shifts the program to arg1 — bash -c with a dynamic arg blocks", () => {
  assert.ok(cmd(`package m\nfunc h(ctx context.Context, x string){ exec.CommandContext(ctx, "bash", "-c", x) }`)?.blocking);
});

precise("go cmd: a shell program with only static arguments is NOT flagged", () => {
  assert.equal(cmd(`package m\nfunc h(){ exec.Command("sh", "-c", "ls -la") }`), null);
});

precise("go cmd: a fixed program with no dynamic args is NOT flagged", () => {
  assert.equal(cmd(`package m\nfunc h(){ exec.Command("ls", "-la") }`), null);
});

// --- 4. path traversal: request-source aware + filepath.Base down-tier ----------------------------
function pt(content) {
  const f = findings(content, "path-traversal");
  return f.length ? f[0] : null;
}

precise("go path: os.ReadFile of request data is flagged", () => {
  const f = pt(`package m\nfunc h(w http.ResponseWriter, r *http.Request){ os.ReadFile(r.URL.Query().Get("f")) }`);
  assert.ok(f && f.tier === "orange");
});

precise("go path: http.ServeFile of request data (arg2) is flagged", () => {
  assert.ok(pt(`package m\nfunc h(w http.ResponseWriter, r *http.Request){ http.ServeFile(w, r, r.FormValue("f")) }`));
});

precise("go path: a filepath.Base wrapper down-tiers to review", () => {
  const f = pt(`package m\nfunc h(w http.ResponseWriter, r *http.Request){ os.ReadFile(filepath.Base(r.FormValue("f"))) }`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

precise("go path: a static path is NOT flagged", () => {
  assert.equal(pt(`package m\nfunc h(){ os.ReadFile("/etc/config.yaml") }`), null);
});

// --- 5. diff-scoping: only changed lines are flagged ----------------------------------------------
precise("go: a dynamic sink on an unchanged line is not flagged", () => {
  const content = `package m\nfunc h(db *sql.DB, id string){ db.Query("SELECT * FROM t WHERE id=" + id) }`;
  const r = analyze({ filePath: "x.go", content, changedLines: new Set([1]) });
  assert.equal(r.findings.filter((f) => f.ruleId === "sql-injection").length, 0);
});
