// C# AST-precision rules (tree-sitter). Proves the C# sql/command/deser/path/xss rules reach the same
// precision tier as the other languages — and that recall degrades gracefully to the cross-language regex
// when the grammar isn't loaded. C# has string interpolation, so a `$"…{x}…"` sink is the dynamic vector.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady } from "../dist/core/index.js";

function findings(content, ruleId) {
  return analyze({ filePath: "T.cs", content }).findings.filter((f) => f.ruleId === ruleId);
}
const W = (body) => `public class T {\n  void M(string id) {\n    ${body}\n  }\n}`;

// --- 1. fallback: BEFORE init, the broad regex candidate carries recall ----------------------------
test("csharp: regex candidate fires when tree-sitter is not initialized (graceful fallback)", () => {
  assert.equal(treeSitterReady("csharp"), false, "precondition: grammar not yet loaded");
  const src = W(`cmd.CommandText = "SELECT * FROM u WHERE id=" + id;`);
  assert.ok(findings(src, "sql-injection-candidate").length >= 1, "candidate regex preserves recall without the AST");
});

test("csharp: tree-sitter grammar loads", async () => {
  await initTreeSitter();
  assert.ok(true);
});

const precise = (name, fn) =>
  test(name, async (t) => {
    await initTreeSitter();
    if (!treeSitterReady("csharp")) return t.skip("tree-sitter c# grammar unavailable");
    fn();
  });

// --- 2. SQL injection ------------------------------------------------------------------------------
function sqli(content) {
  const f = findings(content, "sql-injection");
  return f.length ? f[0] : null;
}

precise("csharp sql: new SqlCommand with string interpolation blocks", () => {
  const f = sqli(W(`var c = new SqlCommand($"SELECT * FROM u WHERE id={id}");`));
  assert.ok(f && f.blocking && f.tier === "orange");
  assert.equal(f.symbol, "M", "enclosing method named for the graph layer");
  assert.equal(findings(W(`var c = new SqlCommand($"SELECT * FROM u WHERE id={id}");`), "sql-injection-candidate").length, 0, "AST owns it — no double regex finding");
});

precise("csharp sql: CommandText assignment with concatenation blocks", () => {
  assert.ok(sqli(W(`cmd.CommandText = "SELECT * FROM u WHERE id=" + id;`))?.blocking);
});

precise("csharp sql: a parameterized CommandText (@id) is NOT flagged", () => {
  assert.equal(sqli(W(`cmd.CommandText = "SELECT * FROM u WHERE id=@id";`)), null);
});

precise("csharp sql: a cross-line query variable (declarator) is resolved and blocks", () => {
  const f = sqli(W(`string q = "SELECT * FROM u WHERE id=" + id; var c = new SqlCommand(q, conn);`));
  assert.ok(f && f.blocking, "def-use across a variable_declarator must resolve");
});

precise("csharp sql: Dapper Query with concatenation blocks (keyword sink)", () => {
  assert.ok(sqli(W(`conn.Query("SELECT * FROM u WHERE id=" + id);`))?.blocking);
});

precise("csharp sql: EF FromSqlRaw with interpolation blocks", () => {
  assert.ok(sqli(W(`db.Users.FromSqlRaw($"SELECT * FROM Users WHERE id={id}");`))?.blocking);
});

precise("csharp sql: EF FromSqlInterpolated is NOT flagged (EF parameterizes it)", () => {
  assert.equal(sqli(W(`db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE id={id}");`)), null);
});

precise("csharp sql: interpolating only a const is NOT flagged", () => {
  assert.equal(sqli(`public class T { const string Tbl = "users"; void M(){ var c = new SqlCommand($"SELECT * FROM {Tbl}"); } }`), null);
});

precise("csharp sql: a fully static query is NOT flagged", () => {
  assert.equal(sqli(W(`var c = new SqlCommand("SELECT * FROM u");`)), null);
});

// --- 3. command injection --------------------------------------------------------------------------
function cmd(content) {
  const f = findings(content, "command-injection");
  return f.length ? f[0] : null;
}

precise("csharp cmd: Process.Start with concatenation blocks", () => {
  assert.ok(cmd(W(`Process.Start("cmd.exe", "/c dir " + id);`))?.blocking);
});

precise("csharp cmd: a static command is NOT flagged", () => {
  assert.equal(cmd(W(`Process.Start("notepad.exe");`)), null);
});

precise("csharp cmd: a bare opaque command parameter is NOT flagged", () => {
  assert.equal(cmd(`public class T { void M(string cmd){ Process.Start(cmd); } }`), null);
});

// --- 4. unsafe deserialization ---------------------------------------------------------------------
function deser(content) {
  const f = findings(content, "unsafe-deserialization");
  return f.length ? f[0] : null;
}

precise("csharp deser: BinaryFormatter.Deserialize (via def-use) blocks", () => {
  assert.ok(deser(`public class T { void M(System.IO.Stream s){ var bf = new BinaryFormatter(); var o = bf.Deserialize(s); } }`)?.blocking);
});

precise("csharp deser: inline new BinaryFormatter().Deserialize blocks", () => {
  assert.ok(deser(`public class T { void M(System.IO.Stream s){ var o = new BinaryFormatter().Deserialize(s); } }`)?.blocking);
});

precise("csharp deser: a safe serializer's Deserialize is NOT flagged", () => {
  assert.equal(deser(`public class T { void M(System.IO.Stream s){ var js = new JsonSerializer(); js.Deserialize(s); } }`), null);
});

// --- 5. path traversal -----------------------------------------------------------------------------
function pt(content) {
  const f = findings(content, "path-traversal");
  return f.length ? f[0] : null;
}

precise("csharp path: File.ReadAllText of request data is flagged (advisory)", () => {
  const f = pt(`public class T { void M(HttpRequest Request){ File.ReadAllText(Request.Query["f"]); } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});

precise("csharp path: a mix of sanitized + raw request data stays orange (cannot hide the raw value)", () => {
  const f = pt(`public class T { void M(HttpRequest Request){ File.ReadAllText(Path.GetFileName(Request.Query["a"]) + Request.Query["b"]); } }`);
  assert.ok(f && f.tier === "orange" && f.tierAdjusted !== "deescalated", "one unsanitized request value must keep it orange");
});

precise("csharp path: a Path.GetFileName wrapper down-tiers to review", () => {
  const f = pt(`public class T { void M(HttpRequest Request){ File.ReadAllText(Path.GetFileName(Request.Query["f"])); } }`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

precise("csharp path: a static path is NOT flagged", () => {
  assert.equal(pt(`public class T { void M(){ File.ReadAllText("/etc/app.conf"); } }`), null);
});

// --- 6. XSS ----------------------------------------------------------------------------------------
function xss(content) {
  const f = findings(content, "xss-sink");
  return f.length ? f[0] : null;
}

precise("csharp xss: Html.Raw of request data is flagged (advisory)", () => {
  const f = xss(`public class T { void M(HttpRequest Request){ Html.Raw(Request.Query["html"]); } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});

precise("csharp xss: a HtmlEncode-wrapped value down-tiers to review", () => {
  const f = xss(`public class T { void M(HttpRequest Request){ Html.Raw(HttpUtility.HtmlEncode(Request.Query["x"])); } }`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

precise("csharp xss: Html.Raw of a static literal is NOT flagged", () => {
  assert.equal(xss(W(`Html.Raw("<b>ok</b>");`)), null);
});

// --- 7. diff-scoping -------------------------------------------------------------------------------
precise("csharp: a dynamic sink on an unchanged line is not flagged", () => {
  const content = W(`cmd.CommandText = "SELECT * FROM u WHERE id=" + id;`);
  const r = analyze({ filePath: "T.cs", content, changedLines: new Set([1]) });
  assert.equal(r.findings.filter((f) => f.ruleId === "sql-injection").length, 0);
});

// --- SSRF: request-tainted URL into HttpClient/WebClient/WebRequest -------------------------------
function ssrf(content) { const f = findings(content, "ssrf"); return f.length ? f[0] : null; }
precise("csharp ssrf: HttpClient.GetStringAsync of request data is flagged (advisory)", () => {
  const f = ssrf(`public class T { void M(HttpClient c, HttpRequest Request) { c.GetStringAsync(Request.Query["u"]); } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});
precise("csharp ssrf: WebRequest.Create of request data is flagged", () => {
  assert.ok(ssrf(`public class T { void M(HttpRequest Request) { WebRequest.Create(Request.Form["u"]); } }`));
});
precise("csharp ssrf: a static URL is NOT flagged", () => {
  assert.equal(ssrf(`public class T { void M(HttpClient c) { c.GetStringAsync("https://api/x"); } }`), null);
});

// --- XXE: explicit opt-in to external-entity resolution (advisory) ---------------------------------
function xxe(content) { const f = findings(content, "xxe"); return f.length ? f[0] : null; }
precise("csharp xxe: legacy new XmlTextReader(...) is flagged (advisory)", () => {
  const f = xxe(W(`var r = new XmlTextReader(id);`));
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});
precise("csharp xxe: XmlTextReader hardened with DtdProcessing.Prohibit is NOT flagged", () => {
  assert.equal(xxe(W(`var r = new XmlTextReader(id); r.DtdProcessing = DtdProcessing.Prohibit;`)), null);
});
precise("csharp xxe: DtdProcessing = DtdProcessing.Parse is flagged", () => {
  assert.ok(xxe(W(`var s = new XmlReaderSettings(); s.DtdProcessing = DtdProcessing.Parse;`)));
});
precise("csharp xxe: DtdProcessing.Parse with XmlResolver = null is NOT flagged (safe)", () => {
  assert.equal(xxe(W(`var s = new XmlReaderSettings(); s.DtdProcessing = DtdProcessing.Parse; s.XmlResolver = null;`)), null);
});
precise("csharp xxe: explicit XmlResolver = new XmlUrlResolver() is flagged", () => {
  assert.ok(xxe(W(`var d = new XmlDocument(); d.XmlResolver = new XmlUrlResolver();`)));
});
precise("csharp xxe: modern XmlReader.Create with no DTD opt-in is NOT flagged", () => {
  assert.equal(xxe(W(`var r = XmlReader.Create(id);`)), null);
});
precise("csharp xxe: the hardened XmlSecureResolver is NOT flagged (no false positive)", () => {
  assert.equal(xxe(W(`var d = new XmlDocument(); d.XmlResolver = new XmlSecureResolver(new XmlUrlResolver(), perms);`)), null);
});

// --- permissive CORS: AllowAnyOrigin / wildcard / reflected (0.7.4) --------------------------------
function csCors(content) { const f = findings(content, "permissive-cors"); return f.length ? f[0] : null; }
precise("cs cors: AllowAnyOrigin() is flagged (advisory)", () => {
  const f = csCors(`class C { void Cfg(CorsPolicyBuilder b){ b.AllowAnyOrigin(); } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});
precise("cs cors: WithOrigins(\"*\") is flagged", () => {
  assert.ok(csCors(`class C { void Cfg(CorsPolicyBuilder b){ b.WithOrigins("*"); } }`));
});
precise("cs cors: Headers.Add/Append of ACAO * are flagged", () => {
  assert.ok(csCors(`class C { void F(){ Response.Headers.Add("Access-Control-Allow-Origin", "*"); } }`));
  assert.ok(csCors(`class C { void F(){ context.Response.Headers.Append("Access-Control-Allow-Origin", "*"); } }`));
});
precise("cs cors: Headers[\"…\"] = \"*\" and a reflected Request Origin are flagged", () => {
  assert.ok(csCors(`class C { void F(){ Response.Headers["Access-Control-Allow-Origin"] = "*"; } }`));
  assert.ok(csCors(`class C { void F(){ Response.Headers["Access-Control-Allow-Origin"] = Request.Headers["Origin"]; } }`));
});
precise("cs cors: an explicit origin allowlist is NOT flagged", () => {
  assert.equal(csCors(`class C { void Cfg(CorsPolicyBuilder b){ b.WithOrigins("https://app.example.com"); } }`), null);
});
precise("cs cors: unrelated Add('*') / non-CORS headers are NOT flagged", () => {
  assert.equal(csCors(`class C { void F(){ map.Add("glob", "*"); } }`), null);
  assert.equal(csCors(`class C { void F(){ Response.Headers["X-Custom"] = "*"; } }`), null);
});
