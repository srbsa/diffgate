// Java AST-precision rules (tree-sitter). Proves the Java sql/command/deser/path rules reach the same
// precision tier as the other languages — and that recall degrades gracefully to the cross-language regex
// when the grammar isn't loaded.
import test from "node:test";
import assert from "node:assert/strict";
import { analyze, initTreeSitter, treeSitterReady } from "../dist/core/index.js";

function findings(content, ruleId) {
  return analyze({ filePath: "T.java", content }).findings.filter((f) => f.ruleId === ruleId);
}
const wrap = (body) => `public class T {\n  void m(String id) throws Exception {\n    ${body}\n  }\n}`;

// --- 1. fallback: BEFORE init, the broad regex candidate carries recall ----------------------------
test("java: regex candidate fires when tree-sitter is not initialized (graceful fallback)", () => {
  assert.equal(treeSitterReady("java"), false, "precondition: grammar not yet loaded");
  const src = wrap(`stmt.executeQuery("SELECT * FROM t WHERE id=" + id);`);
  assert.ok(findings(src, "sql-injection-candidate").length >= 1, "candidate regex preserves recall without the AST");
});

test("java: tree-sitter grammar loads", async () => {
  await initTreeSitter();
  assert.ok(true);
});

const precise = (name, fn) =>
  test(name, async (t) => {
    await initTreeSitter();
    if (!treeSitterReady("java")) return t.skip("tree-sitter java grammar unavailable");
    fn();
  });

// --- 2. SQL injection ------------------------------------------------------------------------------
function sqli(content) {
  const f = findings(content, "sql-injection");
  return f.length ? f[0] : null;
}

precise("java sql: executeQuery with concatenation blocks", () => {
  const f = sqli(wrap(`stmt.executeQuery("SELECT * FROM t WHERE id=" + id);`));
  assert.ok(f && f.blocking && f.tier === "orange");
  assert.equal(f.symbol, "m", "enclosing method named for the graph layer");
  assert.equal(findings(wrap(`stmt.executeQuery("SELECT * FROM t WHERE id=" + id);`), "sql-injection-candidate").length, 0, "AST owns it — no double regex finding");
});

precise("java sql: String.format into a query blocks", () => {
  assert.ok(sqli(wrap(`stmt.executeUpdate(String.format("DELETE FROM t WHERE id=%s", id));`))?.blocking);
});

precise("java sql: prepareStatement with concatenation blocks (fragment sink)", () => {
  assert.ok(sqli(wrap(`conn.prepareStatement("SELECT * FROM t WHERE id=" + id);`))?.blocking);
});

precise("java sql: a parameterized prepareStatement (?) is NOT flagged", () => {
  assert.equal(sqli(wrap(`conn.prepareStatement("SELECT * FROM t WHERE id=?");`)), null);
});

precise("java sql: HQL createQuery with concatenation blocks (no SELECT keyword)", () => {
  assert.ok(sqli(wrap(`em.createQuery("from User where name='" + id + "'");`))?.blocking);
});

precise("java sql: a cross-line query variable (declarator) is resolved and blocks", () => {
  const f = sqli(wrap(`String q = "SELECT * FROM t WHERE id=" + id; stmt.execute(q);`));
  assert.ok(f && f.blocking, "execute(q) with def-use to a SQL concat must block");
});

precise("java sql: ExecutorService.execute (no SQL keyword) is NOT flagged", () => {
  assert.equal(sqli(`public class T { void m(java.util.concurrent.ExecutorService ex, Runnable r){ ex.execute(r); } }`), null);
});

precise("java sql: a fully static query string is NOT flagged", () => {
  assert.equal(sqli(wrap(`stmt.executeQuery("SELECT * FROM t");`)), null);
});

// --- 3. command injection --------------------------------------------------------------------------
function cmd(content) {
  const f = findings(content, "command-injection");
  return f.length ? f[0] : null;
}

precise("java cmd: Runtime.exec with concatenation blocks", () => {
  assert.ok(cmd(wrap(`Runtime.getRuntime().exec("ping " + id);`))?.blocking);
});

precise("java cmd: a request-tainted exec argument blocks", () => {
  assert.ok(cmd(`public class T { void m(javax.servlet.http.HttpServletRequest req) throws Exception { Runtime.getRuntime().exec(req.getParameter("cmd")); } }`)?.blocking);
});

precise("java cmd: ProcessBuilder with a dynamic argument blocks", () => {
  assert.ok(cmd(wrap(`new ProcessBuilder("sh", "-c", "ls " + id);`))?.blocking);
});

precise("java cmd: a static command is NOT flagged", () => {
  assert.equal(cmd(wrap(`Runtime.getRuntime().exec("ls -la");`)), null);
});

precise("java cmd: a bare opaque command parameter is NOT flagged (no config false-block)", () => {
  assert.equal(cmd(`public class T { void m(String cmd) throws Exception { Runtime.getRuntime().exec(cmd); } }`), null);
});

// --- 4. unsafe deserialization ---------------------------------------------------------------------
function deser(content) {
  const f = findings(content, "unsafe-deserialization");
  return f.length ? f[0] : null;
}

precise("java deser: ObjectInputStream.readObject blocks", () => {
  assert.ok(deser(`public class T { void m(java.io.ObjectInputStream ois) throws Exception { Object o = ois.readObject(); } }`)?.blocking);
});

precise("java deser: defaultReadObject (not the gadget sink) is NOT flagged", () => {
  assert.equal(deser(`public class T { void m(java.io.ObjectInputStream in) throws Exception { in.defaultReadObject(); } }`), null);
});

// --- 5. path traversal -----------------------------------------------------------------------------
function pt(content) {
  const f = findings(content, "path-traversal");
  return f.length ? f[0] : null;
}

precise("java path: new File of request data is flagged (advisory)", () => {
  const f = pt(`public class T { void m(javax.servlet.http.HttpServletRequest req){ new java.io.File(req.getParameter("f")); } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});

precise("java path: a FilenameUtils.getName wrapper down-tiers to review", () => {
  const f = pt(`public class T { void m(javax.servlet.http.HttpServletRequest req){ new java.io.File(org.apache.commons.io.FilenameUtils.getName(req.getParameter("f"))); } }`);
  assert.ok(f && f.blocking === false && f.tier === "yellow" && f.tierAdjusted === "deescalated");
});

precise("java path: a mix of sanitized + raw request data stays orange (cannot hide the raw value)", () => {
  const f = pt(`public class T { void m(javax.servlet.http.HttpServletRequest req){ new java.io.File(org.apache.commons.io.FilenameUtils.getName(req.getParameter("a")) + req.getParameter("b")); } }`);
  assert.ok(f && f.tier === "orange" && f.tierAdjusted !== "deescalated", "one unsanitized request value must keep it orange");
});

precise("java path: a static path is NOT flagged", () => {
  assert.equal(pt(`public class T { void m(){ new java.io.File("/etc/app.conf"); } }`), null);
});

// --- 6. diff-scoping -------------------------------------------------------------------------------
precise("java: a dynamic sink on an unchanged line is not flagged", () => {
  const content = wrap(`stmt.executeQuery("SELECT * FROM t WHERE id=" + id);`);
  const r = analyze({ filePath: "T.java", content, changedLines: new Set([1]) });
  assert.equal(r.findings.filter((f) => f.ruleId === "sql-injection").length, 0);
});

// --- SSRF: request-tainted URL into URL/RestTemplate ---------------------------------------------
function ssrf(content) { const f = findings(content, "ssrf"); return f.length ? f[0] : null; }
precise("java ssrf: new URL of request data is flagged (advisory)", () => {
  const f = ssrf(`public class T { void m(javax.servlet.http.HttpServletRequest req) throws Exception { new java.net.URL(req.getParameter("u")).openStream(); } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});
precise("java ssrf: RestTemplate.getForObject of request data is flagged", () => {
  assert.ok(ssrf(`public class T { void m(javax.servlet.http.HttpServletRequest req){ rest.getForObject(req.getParameter("u"), String.class); } }`));
});
precise("java ssrf: a static URL is NOT flagged", () => {
  assert.equal(ssrf(`public class T { void m() throws Exception { new java.net.URL("https://api/x").openStream(); } }`), null);
});

// --- XXE: XML parser created without disabling external entities (advisory) ------------------------
function xxe(content) { const f = findings(content, "xxe"); return f.length ? f[0] : null; }
precise("java xxe: DocumentBuilderFactory.newInstance() without hardening is flagged (advisory)", () => {
  const f = xxe(`public class T { void m() throws Exception { DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.newDocumentBuilder().parse(s); } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});
precise("java xxe: a hardened factory (disallow-doctype-decl) is NOT flagged", () => {
  assert.equal(xxe(`public class T { void m() throws Exception { DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); } }`), null);
});
precise("java xxe: XMLInputFactory hardened with SUPPORT_DTD=false is NOT flagged", () => {
  assert.equal(xxe(`public class T { void m() { XMLInputFactory f = XMLInputFactory.newInstance(); f.setProperty(XMLInputFactory.SUPPORT_DTD, false); } }`), null);
});
precise("java xxe: dom4j SAXReader construction is flagged", () => {
  assert.ok(xxe(`public class T { void m() { org.dom4j.io.SAXReader r = new SAXReader(); } }`));
});
precise("java xxe: FEATURE_SECURE_PROCESSING hardening is NOT flagged", () => {
  assert.equal(xxe(`public class T { void m() throws Exception { TransformerFactory tf = TransformerFactory.newInstance(); tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); } }`), null);
});

// --- permissive CORS: @CrossOrigin defaults + wildcard/reflected (0.7.4) --------------------------
function jCors(content) { const f = findings(content, "permissive-cors"); return f.length ? f[0] : null; }
precise("java cors: bare @CrossOrigin (defaults to all origins) is flagged (advisory)", () => {
  const f = jCors(`class C { @CrossOrigin\n@GetMapping("/a") String a(){ return "x"; } }`);
  assert.ok(f && f.tier === "orange" && f.blocking === false);
});
precise("java cors: @CrossOrigin(origins = \"*\") is flagged", () => {
  assert.ok(jCors(`class C { @CrossOrigin(origins = "*")\nString a(){ return "x"; } }`));
});
precise("java cors: @CrossOrigin(maxAge = …) leaves origins at the permissive default — flagged", () => {
  assert.ok(jCors(`class C { @CrossOrigin(maxAge = 3600)\nString a(){ return "x"; } }`));
});
precise("java cors: allowedOrigins(\"*\") / addAllowedOrigin(\"*\") are flagged", () => {
  assert.ok(jCors(`class C { void cfg(CorsRegistry r){ r.addMapping("/**").allowedOrigins("*"); } }`));
  assert.ok(jCors(`class C { void cfg(CorsConfiguration c){ c.addAllowedOrigin("*"); } }`));
});
precise("java cors: setHeader ACAO * and reflected Origin are flagged", () => {
  assert.ok(jCors(`class C { void f(HttpServletResponse response){ response.setHeader("Access-Control-Allow-Origin", "*"); } }`));
  assert.ok(jCors(`class C { void f(HttpServletRequest request, HttpServletResponse response){ response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin")); } }`));
});
precise("java cors: an explicit origin (key or implicit value form) is NOT flagged", () => {
  assert.equal(jCors(`class C { @CrossOrigin(origins = "https://app.example.com")\nString a(){ return "x"; } }`), null);
  assert.equal(jCors(`class C { @CrossOrigin("https://app.example.com")\nString a(){ return "x"; } }`), null);
  assert.equal(jCors(`class C { void cfg(CorsRegistry r){ r.addMapping("/**").allowedOrigins("https://app.example.com"); } }`), null);
});
precise("java cors: unrelated annotations and non-CORS headers are NOT flagged", () => {
  assert.equal(jCors(`class C { @GetMapping("/a")\nString a(){ return "x"; } }`), null);
  assert.equal(jCors(`class C { void f(HttpServletResponse response){ response.setHeader("X-Custom", "*"); } }`), null);
});
