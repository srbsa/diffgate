// Ruby AST-precision rules (tree-sitter). Proves the Ruby sql/command/code/deser/xss rules reach the same
// precision tier as the other languages — and that recall degrades gracefully to the cross-language regex
// when the grammar isn't loaded.
//
// Ordering matters: the FIRST test runs BEFORE initTreeSitter(), asserting the regex fallback path. Later
// tests run after init; if the wasm grammar can't load here, the precision tests self-skip (mirrors the
// other language suites) so the suite stays green.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady } from "../dist/core/index.js";

function findings(content, ruleId) {
  return analyze({ filePath: "x.rb", content }).findings.filter((f) => f.ruleId === ruleId);
}

// --- 1. fallback: BEFORE init, the broad regex candidate carries recall ----------------------------
test("ruby: regex candidate fires when tree-sitter is not initialized (graceful fallback)", () => {
  assert.equal(treeSitterReady("ruby"), false, "precondition: grammar not yet loaded");
  const src = `User.where("name = '#{params[:n]}'")`;
  assert.ok(findings(src, "sql-injection-candidate").length >= 1, "candidate regex preserves recall without the AST");
});

test("ruby: tree-sitter grammar loads", async () => {
  await initTreeSitter();
  assert.ok(true);
});

const precise = (name, fn) =>
  test(name, async (t) => {
    await initTreeSitter();
    if (!treeSitterReady("ruby")) return t.skip("tree-sitter ruby grammar unavailable");
    fn();
  });

// --- 2. SQL injection: interpolation blocks; placeholders, hashes, constants are safe --------------
function sqli(content) {
  const f = findings(content, "sql-injection");
  return f.length ? f[0] : null;
}

precise("ruby sql: where with string interpolation blocks", () => {
  const f = sqli(`class C\n  def i\n    User.where("name = '#{params[:n]}'")\n  end\nend`);
  assert.ok(f && f.blocking && f.tier === "orange");
  assert.equal(f.symbol, "i", "enclosing method named for the graph layer");
  assert.equal(findings(`class C\n  def i\n    User.where("name = '#{params[:n]}'")\n  end\nend`, "sql-injection-candidate").length, 0, "AST owns it — no double regex finding");
});

precise("ruby sql: a placeholder query is NOT flagged", () => {
  assert.equal(sqli(`User.where("name = ?", params[:n])`), null);
});

precise("ruby sql: an interpolated BOUND value (placeholder + value) is NOT flagged", () => {
  // The fragment arg0 is static; the value arg is bound (escaped) even though it interpolates.
  assert.equal(sqli(`User.where("id = ?", "#{params[:x]}")`), null);
});

precise("ruby sql: the hash form is NOT flagged", () => {
  assert.equal(sqli(`User.where(name: params[:n])`), null);
});

precise("ruby sql: interpolating only a constant is NOT flagged", () => {
  assert.equal(sqli(`User.where("role = '#{ADMIN_ROLE}'")`), null);
});

precise("ruby sql: find_by_sql via a cross-line variable blocks (def-use)", () => {
  const f = sqli(`class C\n  def i\n    q = "SELECT * FROM t WHERE id = #{params[:id]}"\n    User.find_by_sql(q)\n  end\nend`);
  assert.ok(f && f.blocking);
});

precise("ruby sql: order with interpolation blocks", () => {
  assert.ok(sqli(`Post.order("#{params[:col]} ASC")`)?.blocking);
});

precise("ruby sql: an array-placeholder fragment is NOT flagged, but an interpolated array fragment blocks", () => {
  assert.equal(sqli(`User.where(["name = ?", params[:n]])`), null);
  assert.ok(sqli(`User.where(["name = '#{params[:n]}'"])`)?.blocking);
});

precise("ruby sql: a quoted dynamic part down-tiers to review", () => {
  const f = sqli(`User.where("name = '#{connection.quote(params[:n])}'")`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

// --- 3. command injection: single-string shells; multi-arg / array form is safe -------------------
function cmd(content) {
  const f = findings(content, "command-injection");
  return f.length ? f[0] : null;
}

precise("ruby cmd: system with a single interpolated string blocks", () => {
  assert.ok(cmd(`system("rm -rf #{params[:dir]}")`)?.blocking);
});

precise("ruby cmd: the multi-argument form is NOT flagged (no shell)", () => {
  assert.equal(cmd(`system("git", "checkout", params[:branch])`), null);
});

precise("ruby cmd: backticks (subshell) with interpolation block", () => {
  assert.ok(cmd("`ls #{params[:dir]}`")?.blocking);
});

precise("ruby cmd: %x{} with interpolation blocks", () => {
  assert.ok(cmd("%x{ls #{params[:dir]}}")?.blocking);
});

precise("ruby cmd: IO.popen with a single interpolated string blocks", () => {
  assert.ok(cmd(`IO.popen("cat #{params[:f]}")`)?.blocking);
});

precise("ruby cmd: a static command string is NOT flagged", () => {
  assert.equal(cmd(`system("ls -la")`), null);
});

precise("ruby cmd: a Shellwords.escape-wrapped value down-tiers to review", () => {
  const f = cmd(`system("ls #{Shellwords.escape(params[:dir])}")`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

// --- 4. code injection: eval-family of a dynamic value --------------------------------------------
function code(content) {
  const f = findings(content, "code-injection");
  return f.length ? f[0] : null;
}

precise("ruby code: eval of a dynamic value blocks", () => {
  assert.ok(code(`eval(params[:code])`)?.blocking);
});

precise("ruby code: instance_eval of a dynamic string blocks", () => {
  assert.ok(code(`obj.instance_eval(params[:code])`)?.blocking);
});

precise("ruby code: eval of a literal is NOT flagged", () => {
  assert.equal(code(`eval("puts 1")`), null);
});

precise("ruby code: an instance_eval BLOCK form (no string arg) is NOT flagged", () => {
  assert.equal(code(`obj.instance_eval { do_thing }`), null);
});

// --- 5. unsafe deserialization: Marshal / YAML / Oj ------------------------------------------------
function deser(content) {
  const f = findings(content, "unsafe-deserialization");
  return f.length ? f[0] : null;
}

precise("ruby deser: Marshal.load of a dynamic value blocks", () => {
  assert.ok(deser(`Marshal.load(params[:data])`)?.blocking);
});

precise("ruby deser: YAML.load of a dynamic value blocks", () => {
  assert.ok(deser(`YAML.load(params[:y])`)?.blocking);
});

precise("ruby deser: YAML.safe_load is NOT a sink", () => {
  assert.equal(deser(`YAML.safe_load(params[:y])`), null);
});

// --- 6. XSS: raw / html_safe of a dynamic value (advisory) ----------------------------------------
function xss(content) {
  const f = findings(content, "xss-sink");
  return f.length ? f[0] : null;
}

precise("ruby xss: raw of a dynamic value is flagged (advisory)", () => {
  const f = xss(`raw(params[:html])`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});

precise("ruby xss: .html_safe on an interpolated string is flagged", () => {
  assert.ok(xss(`"<b>#{params[:x]}</b>".html_safe`));
});

precise("ruby xss: raw of a static literal is NOT flagged", () => {
  assert.equal(xss(`raw("<b>ok</b>")`), null);
});

precise("ruby xss: a sanitize-wrapped value down-tiers to review", () => {
  const f = xss(`sanitize(params[:html]).html_safe`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

// --- 7. diff-scoping: only changed lines are flagged ----------------------------------------------
precise("ruby: a dynamic sink on an unchanged line is not flagged", () => {
  const content = `class C\n  def i\n    User.where("name = '#{params[:n]}'")\n  end\nend`;
  const r = analyze({ filePath: "x.rb", content, changedLines: new Set([1]) });
  assert.equal(r.findings.filter((f) => f.ruleId === "sql-injection").length, 0);
});

// --- SSRF: request-tainted URL into an HTTP library ----------------------------------------------
function ssrf(content) { const f = findings(content, "ssrf"); return f.length ? f[0] : null; }
precise("ruby ssrf: Net::HTTP.get of params is flagged (advisory)", () => {
  const f = ssrf(`Net::HTTP.get(URI(params[:url]))`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});
precise("ruby ssrf: HTTParty.get of params is flagged", () => {
  assert.ok(ssrf(`HTTParty.get(params[:url])`));
});
precise("ruby ssrf: a static URL is NOT flagged", () => {
  assert.equal(ssrf(`Net::HTTP.get(URI("https://api/x"))`), null);
});
precise("ruby ssrf: a generic .get on an unrelated receiver is NOT flagged", () => {
  assert.equal(ssrf(`myobj.get(params[:k])`), null);
});
