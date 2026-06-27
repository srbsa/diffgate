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
function one(ruleId) {
  return (body) => {
    const f = findings(php(body), ruleId);
    return f.length ? f[0] : null;
  };
}
const sqli = one("sql-injection");
const cmd = one("command-injection");
const code = one("code-injection");
const lfi = one("file-inclusion");
const deser = one("unsafe-deserialization");
const xss = one("xss-sink");
const pt = one("path-traversal");

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

// --- 5. command injection (CWE-78) -----------------------------------------------------------------
precise("php: exec() with a concatenated variable blocks", () => {
  const f = cmd(`function g($file){ exec("ls " . $file); }`);
  assert.ok(f && f.blocking && f.tier === "orange");
  assert.equal(f.symbol, "g");
});
precise("php: shell_exec/passthru/system/proc_open/popen interpolation all block", () => {
  for (const sink of ["shell_exec", "passthru", "system", "popen", "proc_open"]) {
    const call = sink === "popen" ? `${sink}("$f", "r")` : sink === "proc_open" ? `${sink}("$f", [], $p)` : `${sink}("cat $f")`;
    const f = cmd(`function g($f){ ${call}; }`);
    assert.ok(f && f.blocking, `${sink} must block`);
  }
});
precise("php: backtick shell command with interpolation blocks", () => {
  const f = cmd("function g($f){ $x = `ls $f`; return $x; }");
  assert.ok(f && f.blocking);
});
precise("php: escapeshellarg on every dynamic part down-tiers to review", () => {
  const f = cmd(`function g($f){ exec("ls " . escapeshellarg($f)); }`);
  assert.ok(f && !f.blocking && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});
precise("php: a static command is NOT flagged", () => {
  assert.equal(cmd(`function g(){ exec("ls -la"); }`), null);
});
precise("php: proc_open with an argument ARRAY (no shell) is NOT flagged", () => {
  assert.equal(cmd(`function g($f){ proc_open(["ls", $f], [], $p); }`), null);
});
precise("php: a $db->exec(...) method call is SQL, not command-injection", () => {
  assert.equal(cmd(`function g($db,$id){ $db->exec("DELETE FROM t WHERE id = $id"); }`), null);
});
precise("php: command-injection does not double-report with dangerous-exec on PHP", () => {
  assert.equal(findings(php(`function g($f){ system("rm $f"); }`), "dangerous-exec").length, 0);
});

// --- 6. dynamic code execution (CWE-95) ------------------------------------------------------------
precise("php: eval() of a dynamic value blocks", () => {
  const f = code(`function g($c){ eval($c); }`);
  assert.ok(f && f.blocking);
});
precise("php: eval() of a static string is NOT flagged", () => {
  assert.equal(code(`function g(){ eval("return 1;"); }`), null);
});
precise("php: create_function with a dynamic body blocks", () => {
  const f = code(`function g($b){ $fn = create_function('$a', $b); return $fn; }`);
  assert.ok(f && f.blocking);
});
precise("php: assert(string) blocks but assert(boolean) does NOT (no false positive)", () => {
  assert.ok(code(`function g($x){ assert("strlen($x)"); }`), "string-arg assert is code-eval");
  assert.equal(code(`function g($x){ assert($x === 1); }`), null, "boolean assert is not code-eval");
  assert.equal(code(`function g($x){ assert(is_array($x)); }`), null);
});

// --- 7. file inclusion / LFI-RFI (CWE-98) ----------------------------------------------------------
precise("php: include of request data blocks", () => {
  const f = lfi(`include($_GET['page']);`);
  assert.ok(f && f.blocking);
});
precise("php: require/require_once/include_once of a variable block", () => {
  for (const kw of ["require", "require_once", "include_once"]) {
    const f = lfi(`function g($p){ ${kw}($p); }`);
    assert.ok(f && f.blocking, `${kw} of a variable must block`);
  }
});
precise("php: include of a concatenated path blocks", () => {
  const f = lfi(`function g($p){ include($p . ".php"); }`);
  assert.ok(f && f.blocking);
});
precise("php: a static include path is NOT flagged", () => {
  assert.equal(lfi(`include("config.php");`), null);
});
precise("php: include(basename($p)) down-tiers to review", () => {
  const f = lfi(`function g($p){ include(basename($p)); }`);
  assert.ok(f && !f.blocking && f.tierAdjusted === "deescalated");
});

// --- 8. unsafe deserialization (CWE-502) -----------------------------------------------------------
precise("php: unserialize of request data blocks", () => {
  const f = deser(`unserialize($_POST['data']);`);
  assert.ok(f && f.blocking);
});
precise("php: unserialize of any dynamic variable blocks", () => {
  const f = deser(`function g($d){ return unserialize($d); }`);
  assert.ok(f && f.blocking);
});
precise("php: unserialize of a static string is NOT flagged", () => {
  assert.equal(deser(`unserialize('a:0:{}');`), null);
});
precise("php: unserialize with allowed_classes=>false down-tiers to review", () => {
  const f = deser(`function g($d){ return unserialize($d, ['allowed_classes' => false]); }`);
  assert.ok(f && !f.blocking && f.tierAdjusted === "deescalated");
});

// --- 9. reflected XSS (CWE-79) — advisory, request-data targeted -----------------------------------
precise("php: echo of request data is flagged (non-blocking advisory)", () => {
  const f = xss(`echo $_GET['name'];`);
  assert.ok(f && !f.blocking && f.tier === "orange");
});
precise("php: echo of a concatenated request value, print, and printf are flagged", () => {
  assert.ok(xss(`echo "Hi " . $_POST['n'];`));
  assert.ok(xss(`print $_GET['x'];`));
  assert.ok(xss(`printf($_GET['fmt']);`));
});
precise("php: a request value resolved across lines is flagged", () => {
  const f = xss(`function g(){ $x = $_GET['n']; echo $x; }`);
  assert.ok(f);
});
precise("php: echo of a static string or a non-request variable is NOT flagged", () => {
  assert.equal(xss(`echo "hello world";`), null);
  assert.equal(xss(`function g($name){ echo $name; }`), null, "non-request echo is too noisy to flag");
});
precise("php: echo htmlspecialchars($_GET[...]) down-tiers to review", () => {
  const f = xss(`echo htmlspecialchars($_GET['n']);`);
  assert.ok(f && !f.blocking && f.tierAdjusted === "deescalated");
});

// --- 10. path traversal (CWE-22) — advisory, request-data targeted --------------------------------
precise("php: fopen/readfile/file_get_contents of request data are flagged", () => {
  assert.ok(pt(`function g(){ fopen($_GET['p'], "r"); }`));
  assert.ok(pt(`readfile($_GET['f']);`));
  assert.ok(pt(`function g(){ file_get_contents($_GET['u']); }`), "also SSRF");
});
precise("php: path-traversal is a non-blocking advisory", () => {
  const f = pt(`readfile($_GET['f']);`);
  assert.ok(f && !f.blocking && f.tier === "orange");
});
precise("php: basename() on the request value down-tiers to review", () => {
  const f = pt(`function g(){ readfile(basename($_GET['f'])); }`);
  assert.ok(f && !f.blocking && f.tierAdjusted === "deescalated");
});
precise("php: a static path, or a non-request variable path, is NOT flagged", () => {
  assert.equal(pt(`function g(){ fopen("/etc/app.conf", "r"); }`), null);
  assert.equal(pt(`function g($p){ file_get_contents($p); }`), null);
});

// --- 11. bug-bash regressions --------------------------------------------------------------------
precise("php: include(__DIR__ . '/static.php') is NOT a false block (magic constant is static)", () => {
  assert.equal(lfi(`include(__DIR__ . "/config.php");`), null);
  assert.equal(lfi(`require(APP_ROOT . "/bootstrap.php");`), null, "user-defined constant is static");
  assert.equal(lfi(`include(dirname(__FILE__) . "/x.php");`), null, "dirname(__FILE__) idiom is static");
  const f = lfi(`function g($p){ include(__DIR__ . "/" . $p); }`);
  assert.ok(f && f.blocking, "but a dynamic part alongside __DIR__ still blocks");
});
precise("php: file_put_contents(STATIC_PATH, $request) does NOT flag path-traversal (data arg, not path)", () => {
  assert.equal(pt(`function g(){ file_put_contents("/var/log/app.log", $_POST['msg']); }`), null);
  assert.ok(pt(`function g(){ file_put_contents($_GET['f'], "data"); }`), "but a request PATH arg0 is flagged");
  assert.ok(pt(`function g($src){ copy($src, $_GET['dst']); }`), "copy's 2nd arg is also a path");
});
precise("php: short-echo `<?= $_GET[...] ?>` is flagged as XSS", () => {
  const f = findings(`<?php ?><?= $_GET['x'] ?>`, "xss-sink");
  assert.ok(f.length && !f[0].blocking, "short-echo of request data is an advisory XSS finding");
  const safe = findings(`<?php ?><?= htmlspecialchars($_GET['x']) ?>`, "xss-sink");
  assert.ok(safe.length && safe[0].tierAdjusted === "deescalated", "escaped short-echo down-tiers");
});
precise("php: sprintf-built SQL into a sink is flagged (parity with Python .format)", () => {
  const f = sqli(`function g($c,$id){ $c->query(sprintf("SELECT * FROM t WHERE id=%s", $id)); }`);
  assert.ok(f && f.blocking);
  assert.ok(sqli(`function g($c,$id){ $c->query(sprintf("SELECT * FROM t WHERE id=%d", (int)$id)); }`)?.tierAdjusted === "deescalated", "(int) on the arg down-tiers");
});
precise("php: Laravel raw-fragment sinks (whereRaw/orderByRaw/...) flag dynamic, not parameterized", () => {
  assert.ok(sqli(`function g($q,$id){ $q->whereRaw("age > $id"); }`)?.blocking, "interpolated fragment blocks");
  assert.ok(sqli(`function g($q,$id){ $q->orderByRaw("col $id"); }`)?.blocking);
  assert.equal(sqli(`function g($q,$id){ $q->whereRaw("age > ?", [$id]); }`), null, "placeholder + bindings is safe");
  assert.equal(sqli(`function g($q){ $q->whereRaw('age > 18'); }`), null, "static fragment is safe");
  assert.equal(sqli(`function g($q,$c){ $q->where('active', $c); }`), null, "a normal where() is not a raw sink");
});
precise("php: a nowdoc (<<<'EOT') does NOT interpolate — not flagged", () => {
  assert.equal(sqli(`function g($c){ $q = <<<'EOT'\nSELECT * FROM t WHERE id = $id\nEOT;\n$c->query($q); }`), null);
});
precise("php: commented-out dangerous code is NOT flagged (AST sees a comment, not a call)", () => {
  assert.equal(cmd(`function g($f){ // exec("rm $f");\n return 1; }`), null);
  assert.equal(deser(`function g(){ # unserialize($_POST['d']);\n return 1; }`), null);
  assert.equal(sqli(`function g($c,$id){ /* $c->query("SELECT $id"); */ return 1; }`), null);
});
precise("php: namespaced \\unserialize / \\exec are still recognized", () => {
  assert.ok(deser(`\\unserialize($_POST['d']);`)?.blocking);
  assert.ok(cmd(`function g($f){ \\exec("ls $f"); }`)?.blocking);
});
