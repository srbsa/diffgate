// PHP AST-precision rules (tree-sitter). Same shape as test/python-rules.test.js: the first test runs
// BEFORE initTreeSitter() to prove the regex fallback preserves recall; the rest run after init and
// self-skip if the grammar can't load. PHP's distinguishing precision: single-quoted strings don't
// interpolate, and a placeholder prepared statement is safe while an interpolated one is not.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady } from "../dist/core/index.js";

const H = "<?php\n";
const php = (body) => H + body + "\n";
const DYN = php(`function g($conn,$id){ $conn->query("SELECT * FROM t WHERE id = $id"); }`);

function findings(content, ruleId) {
  return analyze({ filePath: "x.php", content }).findings.filter((f) => f.ruleId === ruleId);
}
function sqli(body) {
  const f = findings(php(body), "sql-injection");
  return f.length ? f[0] : null;
}

// --- 1. fallback BEFORE init: the regex candidate carries recall ----------------------------------
test("php: regex candidate fires when tree-sitter is not initialized (graceful fallback)", () => {
  assert.equal(treeSitterReady("php"), false, "precondition: grammar not yet loaded");
  assert.ok(findings(DYN, "sql-injection-candidate").length >= 1, "candidate preserves recall without the AST");
  assert.equal(findings(DYN, "sql-injection").length, 0, "the precise tsast rule needs a loaded grammar");
});

test("php: tree-sitter grammar loads", async () => {
  await initTreeSitter();
  assert.ok(true);
});

const precise = (name, fn) =>
  test(name, async (t) => {
    await initTreeSitter();
    if (!treeSitterReady("php")) return t.skip("tree-sitter php grammar unavailable");
    fn();
  });

// --- 2. once loaded, the AST rule owns PHP and suppresses the candidate ----------------------------
precise("php: double-quoted interpolation into a sink blocks, candidate suppressed", () => {
  const f = sqli(`function g($conn,$id){ mysqli_query($conn, "SELECT * FROM t WHERE id = $id"); }`);
  assert.ok(f && f.blocking && f.tier === "orange");
  assert.equal(f.symbol, "g");
  assert.equal(findings(DYN, "sql-injection-candidate").length, 0, "AST owns it — no double regex finding");
});

precise("php: brace interpolation {$id} blocks", () => {
  const f = sqli(`function g($wpdb,$id){ $wpdb->get_results("SELECT * FROM t WHERE id = {$id}"); }`);
  assert.ok(f && f.blocking);
});

precise("php: concatenation into a sink blocks", () => {
  const f = sqli(`function g($conn,$name){ $conn->query("SELECT * FROM t WHERE n = " . $name); }`);
  assert.ok(f && f.blocking);
});

precise("php: cross-line query variable resolved and blocked", () => {
  const f = sqli(`function g($conn,$id){ $q = "SELECT * FROM t WHERE id = $id"; mysqli_query($conn,$q); }`);
  assert.ok(f && f.blocking);
});

// --- 3. precision the regex can't reach -----------------------------------------------------------
precise("php: single-quoted string does NOT interpolate — not flagged", () => {
  assert.equal(sqli(`function g($conn){ $conn->query('SELECT * FROM t WHERE x = $id'); }`), null);
});

precise("php: prepared statement with a ? placeholder is NOT flagged", () => {
  assert.equal(sqli(`function g($pdo){ $pdo->prepare("SELECT * FROM t WHERE id = ?"); }`), null);
});

precise("php: interpolation into ->prepare IS flagged (placeholder anti-pattern)", () => {
  const f = sqli(`function g($pdo,$id){ $pdo->prepare("SELECT * FROM t WHERE id = $id"); }`);
  assert.ok(f && f.blocking);
});

precise("php: an interpolated value resolving to a static constant is NOT flagged", () => {
  assert.equal(sqli(`function g($conn){ $t = "users"; mysqli_query($conn, "SELECT * FROM $t"); }`), null);
});

precise("php: a SQL-looking interpolation NOT passed to a sink is NOT flagged", () => {
  assert.equal(sqli(`function g($log,$id){ $log->info("SELECT done for $id"); }`), null);
});

precise("php: a fully static query is NOT flagged", () => {
  assert.equal(sqli(`function g($conn){ mysqli_query($conn, "SELECT 1"); }`), null);
});

// --- 4. sanitizer awareness: down-tier, never hide a raw value ------------------------------------
precise("php: an (int) cast on every dynamic part down-tiers to review", () => {
  const f = sqli(`function g($conn,$id){ $conn->query("SELECT * FROM t WHERE id = " . (int)$id); }`);
  assert.ok(f && !f.blocking && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

precise("php: mysqli_real_escape_string on every dynamic part down-tiers to review", () => {
  const f = sqli(`function g($conn,$id){ $conn->query("SELECT * FROM t WHERE id = '" . mysqli_real_escape_string($conn,$id) . "'"); }`);
  assert.ok(f && !f.blocking && f.tierAdjusted === "deescalated");
});

precise("php: a mix of escaped and raw values stays blocking", () => {
  const f = sqli(`function g($conn,$id,$n){ $conn->query("SELECT * FROM t WHERE id = " . (int)$id . " AND n = " . $n); }`);
  assert.ok(f && f.blocking, "one raw value must keep the gate");
});
